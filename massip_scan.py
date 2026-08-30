#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MassIP Scan — массовый сканер IP-адресов и портов.

Возможности:
  * Фильтрация целей по стране и ASN (базы GeoLite2 + авто-fallback на онлайн)
  * Фильтр Блума — защита от повторной проверки одного и того же IP
  * Многопоточность (по умолчанию 250 потоков)
  * Режимы портов: один / список через запятую / диапазон / пресеты
    (камеры, IoT, маршрутизаторы, NAS, удалённый доступ, СУБД)
  * Интерактивное меню + CLI-аргументы
  * Сохранение результатов в текстовый файл (формат: ip:port)

Зависимости (опционально, для локального GeoIP):
  pip install geoip2
  Файлы GeoLite2-Country.mmdb и GeoLite2-ASN.mmdb положить рядом со скриптом
  (или в /usr/share/GeoIP) — бесплатная регистрация на maxmind.com.

ВНИМАНИЕ:
  Используйте только в сетях, на аудит которых у вас есть разрешение
  (CTF, HackTheBox / TryHackMe, собственная инфраструктура, pentest с ROC).
  Несанкционированное сканирование чужих сетей незаконно.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import socket
import sys
import threading
import time
import urllib.request
from typing import Iterable, Iterator, Optional

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
#  Цвета
# ---------------------------------------------------------------------------

def _enable_win_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
        return True
    except Exception:
        return False


def _use_color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    return _enable_win_ansi()


USE_COLOR = _use_color()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)

def bold(t):   return _c(t, "1")
def red(t):    return _c(t, "91")
def green(t):  return _c(t, "92")
def yellow(t): return _c(t, "93")
def cyan(t):   return _c(t, "96")

# ---------------------------------------------------------------------------
#  Фильтр Блума
# ---------------------------------------------------------------------------

class BloomFilter:
    """
    Потокобезопасный фильтр Блума (схема двойного хеширования
    Kirsch-Mitzenmacher). Ложные срабатывания возможны (~0.1% по умолчанию),
    ложных отрицательных не бывает: проверенный IP не попадёт в повторную
    проверку, даже если диапазоны целей пересекаются.
    """

    def __init__(self, expected_items: int = 1_000_000, fp_rate: float = 0.001):
        n = max(1, expected_items)
        self.size = self._optimal_bits(n, fp_rate)
        self.hash_count = self._optimal_hashes(self.size, n)
        self._bits = bytearray((self.size + 7) // 8)
        self._lock = threading.Lock()
        self.added = 0

    @staticmethod
    def _optimal_bits(n: int, p: float) -> int:
        return max(64, int(-(n * math.log(p)) / (math.log(2) ** 2)))

    @staticmethod
    def _optimal_hashes(m: int, n: int) -> int:
        return max(1, min(16, round((m / n) * math.log(2))))

    def _positions(self, item: str) -> Iterator[int]:
        h1 = int.from_bytes(hashlib.md5(item.encode()).digest()[:8], "big")
        h2 = int.from_bytes(hashlib.sha1(item.encode()).digest()[:8], "big") | 1
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def _contains_nolock(self, item: str) -> bool:
        bits = self._bits
        return all(bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))

    def check_and_add(self, item: str) -> bool:
        """True — элемент уже встречался. False — впервые (и он добавлен)."""
        with self._lock:
            if self._contains_nolock(item):
                return True
            for pos in self._positions(item):
                self._bits[pos >> 3] |= 1 << (pos & 7)
            self.added += 1
            return False

    def __contains__(self, item: str) -> bool:
        with self._lock:
            return self._contains_nolock(item)

# ---------------------------------------------------------------------------
#  GeoIP: страна + ASN
# ---------------------------------------------------------------------------

class GeoLocator:
    """
    Источники данных (по приоритету):
      1. Локальные базы GeoLite2-Country.mmdb / GeoLite2-ASN.mmdb (geoip2)
      2. Автоматический fallback — ip-api.com (бесплатный лимит ~45 запр/мин,
         поэтому запросы троттлятся и кэшируются; при серии сбоев отключается).

    lookup() -> (country_code, asn); при неудаче: ("", None)
    """

    ONLINE_URL = "http://ip-api.com/json/{ip}?fields=status,countryCode,as"
    ONLINE_MIN_INTERVAL = 1.5   # сек между онлайн-запросами (лимит API)
    ONLINE_MAX_FAILURES = 15    # подряд идущих сбоев до отключения fallback

    def __init__(self, country_db: Optional[str], asn_db: Optional[str], online: bool):
        self._reader_country = None
        self._reader_asn = None
        self._online = online
        self._cache: dict = {}
        self._cache_lock = threading.Lock()
        self._online_lock = threading.Lock()
        self._last_request = 0.0
        self._failures = 0
        self._online_disabled = False

        if GEOIP2_AVAILABLE:
            for db, attr in ((country_db, "_reader_country"), (asn_db, "_reader_asn")):
                if db:
                    try:
                        setattr(self, attr, geoip2.database.Reader(db))
                    except Exception as e:
                        print(yellow(f"[!] Не удалось открыть {db}: {e}"))
        elif country_db or asn_db:
            print(yellow("[!] Модуль geoip2 не установлен: pip install geoip2"))

    def lookup(self, ip: str) -> tuple:
        with self._cache_lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached

        country, asn = "", None

        if self._reader_country is not None:
            try:
                country = self._reader_country.country(ip).country.iso_code or ""
            except Exception:
                country = ""

        if self._reader_asn is not None:
            try:
                asn = self._reader_asn.asn(ip).autonomous_system_number
            except Exception:
                asn = None

        # онлайн-fallback: баз нет вообще или по этому IP ничего не нашлось
        if self._online and not self._online_disabled and country == "" and asn is None:
            country, asn = self._lookup_online(ip)

        result = (country, asn)
        with self._cache_lock:
            if len(self._cache) < 5_000_000:
                self._cache[ip] = result
        return result

    def _lookup_online(self, ip: str) -> tuple:
        with self._online_lock:  # соблюдаем лимит API (сериализация запросов)
            wait = self.ONLINE_MIN_INTERVAL - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            try:
                req = urllib.request.Request(
                    self.ONLINE_URL.format(ip=ip),
                    headers={"User-Agent": f"massip-scan/{__version__}"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                if data.get("status") == "success":
                    self._failures = 0
                    asn_field = str(data.get("as", ""))  # "AS15169 Google LLC"
                    asn = None
                    if asn_field.startswith("AS"):
                        try:
                            asn = int(asn_field[2:].split(" ", 1)[0])
                        except ValueError:
                            asn = None
                    return data.get("countryCode", "") or "", asn
                self._failures += 1
            except Exception:
                self._failures += 1
        if self._failures >= self.ONLINE_MAX_FAILURES:
            self._online_disabled = True
            print(yellow("[!] Онлайн-GeoIP недоступен, fallback отключён"))
        return "", None


def find_geoip_db(kind: str, override: Optional[str] = None) -> Optional[str]:
    """Ищет GeoLite2-<kind>.mmdb в типовых местах."""
    if override:
        return override if os.path.isfile(override) else None
    name = f"GeoLite2-{kind}.mmdb"
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, name),
        os.path.join(here, "geoip", name),
        name,
        os.path.join("/usr/share/GeoIP", name),
        os.path.join("/usr/local/share/GeoIP", name),
        os.path.join("/var/lib/GeoIP", name),
        os.path.join("C:\\GeoIP", name),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None

# ---------------------------------------------------------------------------
#  Пресеты портов
# ---------------------------------------------------------------------------

PORT_PRESETS = {
    "cam":     ("Камеры (RTSP, Hikvision, Dahua)",  [554, 1935, 8000, 8080, 8899, 34567, 49152]),
    "iot":     ("IoT (MQTT, CoAP, принтеры)",       [80, 443, 1883, 5683, 8080, 8883, 9100]),
    "routers": ("Маршрутизаторы",                   [21, 22, 23, 53, 80, 443, 8080, 8443]),
    "nas":     ("NAS (SMB, Synology, QNAP)",        [22, 139, 443, 445, 5000, 5001, 5006, 5007, 9000]),
    "rdp":     ("Удалённый доступ (SSH, RDP, VNC)", [22, 23, 3389, 4899, 5800, 5900, 5901, 5985]),
    "db":      ("Базы данных",                      [1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017]),
}

# ---------------------------------------------------------------------------
#  Разбор ввода
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> list:
    ports: set = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if not (0 < lo <= hi <= 65535):
                raise ValueError(f"некорректный диапазон портов: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (0 < p <= 65535):
                raise ValueError(f"некорректный порт: {part}")
            ports.add(p)
    if not ports:
        raise ValueError("не указано ни одного порта")
    if len(ports) > 4096:
        raise ValueError("слишком много портов (>4096)")
    return sorted(ports)


def parse_targets(tokens: Iterable[str]) -> list:
    """Принимает CIDR, одиночные IP и диапазоны (1.2.3.4-1.2.3.99 или 1.2.3.4-99)."""
    nets = []
    for chunk in tokens:
        for token in str(chunk).replace(",", " ").split():
            try:
                if "/" in token:
                    nets.append(ipaddress.ip_network(token, strict=False))
                elif "-" in token:
                    lo_s, hi_s = (s.strip() for s in token.split("-", 1))
                    lo = ipaddress.ip_address(lo_s)
                    hi = (ipaddress.ip_address(hi_s) if "." in hi_s
                          else ipaddress.ip_address(f"{lo_s.rsplit('.', 1)[0]}.{hi_s}"))
                    if int(hi) < int(lo):
                        raise ValueError("конец диапазона меньше начала")
                    nets.extend(ipaddress.summarize_address_range(lo, hi))
                else:
                    nets.append(ipaddress.ip_network(f"{token}/32", strict=False))
            except ValueError as e:
                raise ValueError(f"не удалось разобрать цель «{token}»: {e}") from e
    if not nets:
        raise ValueError("не указано ни одной цели")
    return nets


def iter_ips(networks: list) -> Iterator[str]:
    for net in networks:
        for ip in net:
            yield str(ip)

# ---------------------------------------------------------------------------
#  Сканер
# ---------------------------------------------------------------------------

def tcp_port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


class Stats:
    def __init__(self, total: int):
        self.total = total
        self.checked = 0
        self.open_hosts = 0
        self.open_ports = 0
        self._lock = threading.Lock()
        self._start = time.monotonic()

    def tick(self, opened: int) -> None:
        with self._lock:
            self.checked += 1
            if opened:
                self.open_hosts += 1
                self.open_ports += opened

    def snapshot(self):
        with self._lock:
            elapsed = max(time.monotonic() - self._start, 1e-6)
            return (self.checked, self.open_hosts,
                    self.open_ports, self.checked / elapsed, elapsed)


def progress_loop(stats: Stats, stop: threading.Event) -> None:
    while not stop.wait(2.0):
        checked, hosts, ports, rate, elapsed = stats.snapshot()
        line = (f"\r[*] {checked:,}/{stats.total:,} IP | хостов: {hosts:,} | "
                f"портов: {ports:,} | {rate:,.0f} IP/с | {elapsed:,.0f}с  ")
        sys.stdout.write(cyan(line))
        sys.stdout.flush()


class Scanner:
    def __init__(self, ports, threads, timeout, geo: Optional[GeoLocator], output: str):
        self.ports = ports
        self.threads = max(1, min(threads, 2000))
        self.timeout = timeout
        self.geo = geo
        self.output = output
        self.stop_event = threading.Event()

    def run(self, networks: list, countries: frozenset, asns: frozenset) -> None:
        need_geo = bool(countries or asns)
        if need_geo and self.geo is None:
            raise ValueError("фильтры по стране/ASN заданы, но GeoIP недоступен")

        total = sum(net.num_addresses for net in networks)
        bloom = BloomFilter(expected_items=min(max(total, 10_000), 50_000_000))
        stats = Stats(total)

        out = open(self.output, "a", encoding="utf-8")
        out_lock = threading.Lock()

        ip_iter = iter_ips(networks)
        it_lock = threading.Lock()

        def worker() -> None:
            while not self.stop_event.is_set():
                with it_lock:
                    try:
                        ip = next(ip_iter)
                    except StopIteration:
                        return
                # фильтр Блума: уже проверенные IP пропускаем
                if bloom.check_and_add(ip):
                    continue
                if need_geo:
                    country, asn = self.geo.lookup(ip)
                    if countries and country not in countries:
                        stats.tick(0)
                        continue
                    if asns and (asn is None or asn not in asns):
                        stats.tick(0)
                        continue
                opened = 0
                for port in self.ports:
                    if tcp_port_open(ip, port, self.timeout):
                        opened += 1
                        with out_lock:
                            out.write(f"{ip}:{port}\n")
                            out.flush()
                        print(green(f"\r    [+] {ip}:{port}"))
                stats.tick(opened)

        print(bold(f"\n[*] Целей: {total:,} IP | портов на IP: {len(self.ports)} | "
                   f"потоков: {self.threads} | timeout: {self.timeout}s | "
                   f"результаты: {self.output}"))
        print(bold("[*] Ctrl+C — остановить\n"))

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.threads)]
        progress = threading.Thread(target=progress_loop,
                                    args=(stats, self.stop_event), daemon=True)

        interrupted = False
        try:
            for t in threads:
                t.start()
            progress.start()
            for t in threads:
                while t.is_alive():
                    t.join(0.25)
        except KeyboardInterrupt:
            interrupted = True
            print(yellow("\n[!] Остановка..."))
            self.stop_event.set()
        finally:
            self.stop_event.set()
            for t in threads:
                t.join(timeout=3)
            progress.join(timeout=3)
            out.close()

        checked, hosts, ports_open, rate, elapsed = stats.snapshot()
        print("\n" + cyan("─" * 58))
        print(f"  Проверено IP      : {checked:,}")
        print(f"  Хостов с откр. портами : {hosts:,}")
        print(f"  Открытых портов   : {ports_open:,}")
        print(f"  Скорость          : {rate:,.0f} IP/с")
        print(f"  Время             : {elapsed:,.0f} с"
              + yellow("  (прервано)" if interrupted else ""))
        print(f"  Файл результатов  : {os.path.abspath(self.output)}")
        print(cyan("─" * 58))

# ---------------------------------------------------------------------------
#  Интерактивное меню
# ---------------------------------------------------------------------------

def show_banner() -> None:
    print(bold(cyan("═" * 58)))
    print(bold("   MASSIP SCAN · массовый сканер IP:портов"))
    print(bold("   страна/ASN · bloom-фильтр · многопоточность"))
    print(bold(cyan("═" * 58)))
    if not GEOIP2_AVAILABLE:
        print(yellow("[i] Для локального GeoIP: pip install geoip2"))


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(f"{prompt}{suffix}: ").strip() or default


def interactive_setup(base: argparse.Namespace) -> argparse.Namespace:
    show_banner()
    print()
    targets_raw = ask("Цели (CIDR / IP / диапазон, через запятую или пробел)")
    country = ask("Фильтр по стране (напр. RU,US — Enter = все)")
    asn = ask("Фильтр по ASN (напр. 13335,16509 — Enter = все)")

    print("\nРежим портов:")
    print("  [1] Один порт")
    print("  [2] Список / диапазон (напр. 80,443 или 1000-2000)")
    preset_items = list(PORT_PRESETS.items())
    for i, (_, (name, ports)) in enumerate(preset_items, start=3):
        print(f"  [{i}] Пресет: {name} ({','.join(map(str, ports))})")

    mode = ask("Выбор", "1")
    ports_spec, preset_key = None, None
    if mode == "1":
        ports_spec = ask("Порт", "80")
    elif mode == "2":
        ports_spec = ask("Порты", "80,443,8080")
    elif mode.isdigit() and 3 <= int(mode) < 3 + len(preset_items):
        preset_key = preset_items[int(mode) - 3][0]
    else:
        ports_spec = ask("Порты", "80,443,8080")

    threads = int(ask("Потоков", "250"))
    timeout = float(ask("Таймаут, сек", "1.0"))
    output = ask("Файл результатов", "results.txt")

    geo_online = base.geo_online
    if (country or asn) and not geo_online:
        cdb = find_geoip_db("Country", base.geo_country_db)
        adb = find_geoip_db("ASN", base.geo_asn_db)
        if not (cdb or adb):
            ans = ask("GeoIP-базы не найдены. Онлайн-fallback (медленно)? [y/N]", "N")
            geo_online = ans.lower().startswith("y")

    return argparse.Namespace(
        targets=targets_raw.replace(",", " ").split(),
        country=country, asn=asn,
        ports=ports_spec, preset=preset_key,
        threads=threads, timeout=timeout, output=output,
        geo_country_db=base.geo_country_db, geo_asn_db=base.geo_asn_db,
        geo_online=geo_online,
    )

# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="massip_scan.py",
        description="Массовый сканер IP:портов с фильтрами по стране/ASN и bloom-фильтром.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Примеры:\n"
               "  python massip_scan.py 192.168.1.0/24 -p 80,443\n"
               "  python massip_scan.py 10.0.0.0/8 --preset cam -c US -t 500\n"
               "  python massip_scan.py 1.2.3.0-1.2.3.99 -p 22 --geo-online\n"
               "Без аргументов запускается интерактивное меню.",
    )
    p.add_argument("targets", nargs="*", help="цели: CIDR / IP / диапазон (1.2.3.4-99)")
    p.add_argument("-c", "--country", default="", help="страны через запятую (RU,US)")
    p.add_argument("-a", "--asn", default="", help="ASN через запятую (13335,16509)")
    p.add_argument("-p", "--ports", default=None, help="порты: 80 | 80,443,8080 | 1000-2000")
    p.add_argument("--preset", choices=list(PORT_PRESETS), default=None,
                   help="пресет портов: " + ", ".join(PORT_PRESETS))
    p.add_argument("-t", "--threads", type=int, default=250, help="потоков (по умолчанию 250)")
    p.add_argument("-T", "--timeout", type=float, default=1.0, help="таймаут connect, сек")
    p.add_argument("-o", "--output", default="results.txt", help="файл результатов")
    p.add_argument("--geo-country-db", default=None, help="путь к GeoLite2-Country.mmdb")
    p.add_argument("--geo-asn-db", default=None, help="путь к GeoLite2-ASN.mmdb")
    p.add_argument("--geo-online", action="store_true",
                   help="онлайн-GeoIP fallback (ip-api.com, лимит ~45 запр/мин)")
    return p.parse_args()


def resolve_ports(args: argparse.Namespace) -> list:
    if args.preset:
        return list(PORT_PRESETS[args.preset][1])
    if args.ports:
        return parse_ports(args.ports)
    raise ValueError("порты не заданы: используйте -p/--ports или --preset")


def build_geo(args: argparse.Namespace, require: bool = False) -> GeoLocator:
    cdb = find_geoip_db("Country", args.geo_country_db)
    adb = find_geoip_db("ASN", args.geo_asn_db)
    if cdb:
        print(f"[i] GeoIP Country : {cdb}")
    if adb:
        print(f"[i] GeoIP ASN     : {adb}")
    if not (cdb or adb):
        if args.geo_online:
            print("[i] GeoIP: онлайн-fallback ip-api.com (лимит ~45 запр/мин)")
        elif require:
            raise ValueError(
                "GeoIP недоступен: положите GeoLite2-Country.mmdb / GeoLite2-ASN.mmdb "
                "рядом со скриптом (или в /usr/share/GeoIP), установите geoip2 "
                "(pip install geoip2) или добавьте --geo-online"
            )
        else:
            print(yellow("[i] GeoIP-базы не найдены (продолжаю без гео)"))
    return GeoLocator(cdb, adb, args.geo_online)


def run_scan(args: argparse.Namespace) -> None:
    networks = parse_targets(args.targets)
    ports = resolve_ports(args)
    if len(ports) > 200:
        print(yellow(f"[!] {len(ports)} портов на IP — будет медленно; увеличьте потоки"))

    countries = frozenset(s.strip().upper() for s in args.country.split(",") if s.strip())
    asns = frozenset(int(s.strip()) for s in args.asn.split(",") if s.strip())

    geo = build_geo(args, require=bool(countries or asns))
    Scanner(ports, args.threads, args.timeout, geo, args.output).run(networks, countries, asns)


def main() -> None:
    try:
        args = parse_args()
        if not args.targets:
            args = interactive_setup(args)
        run_scan(args)
    except ValueError as e:
        sys.exit(red(f"[-] {e}"))
    except KeyboardInterrupt:
        print(yellow("\n[!] Прервано пользователем"))


if __name__ == "__main__":
    main()
