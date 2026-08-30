# massip-scan

**Multi-threaded TCP port scanner for authorized network auditing, CTF labs, and asset inventory.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Cross--platform-lightgrey.svg)](#)

> **⚠️ Authorized use only**
>
> Scan only networks you own or have explicit written permission to test, including your own infrastructure, home labs, CTF environments (Hack The Box, TryHackMe, VulnHub), or client engagements within a signed scope.
>
> Unauthorized port scanning may violate applicable laws and regulations.

## ✨ Features

- **Flexible targets** — CIDR blocks, single IPs, and IP ranges
- **Multi-threaded scanning** — configurable worker count, with 250 threads by default
- **Bloom filter deduplication** — overlapping target ranges do not cause the same IP to be scanned repeatedly
- **Flexible port selection** — single ports, comma-separated ports, port ranges, or service presets
- **Service presets** — cameras, IoT, routers, NAS, remote access, and databases
- **Optional GeoIP filtering** — filter assets by country or ASN during authorized infrastructure audits
- **Simple output** — results are appended to a text file in `IP:PORT` format
- **Two interfaces** — interactive menu and full CLI
- **Dependency-light** — no required third-party dependencies for basic scanning

## 📦 Installation

```bash
git clone https://github.com/bladlvde/massip-scan.git
cd massip-scan
```

Requires **Python 3.8+**.

### Optional GeoIP support

Install `geoip2`:

```bash
pip install geoip2
```

Download the free MaxMind GeoLite2 databases:

- `GeoLite2-Country.mmdb`
- `GeoLite2-ASN.mmdb`

Place them next to `massip_scan.py` or in:

```text
/usr/share/GeoIP
```

Without local databases, the scanner can optionally fall back to an online GeoIP service. This is rate-limited and is recommended only for small, authorized scans.

## 🚀 Usage

### Interactive mode

```bash
python massip_scan.py
```

### CLI mode

#### Scan a subnet for common web ports

```bash
python massip_scan.py 192.168.1.0/24 -p 80,443,8080
```

#### Inventory a lab using the database preset

```bash
python massip_scan.py 10.10.0.0/16 --preset db -t 500
```

#### Check a host range for RDP and related remote-access services

```bash
python massip_scan.py 192.168.1.10-192.168.1.50 --preset rdp
```

## ⚙️ Arguments

| Argument | Description | Default |
|---|---|---|
| `targets` | CIDR, IP address, or IP range. Multiple targets can be supplied. | — |
| `-p, --ports` | Port(s), e.g. `80`, `80,443`, or `1000-2000` | — |
| `--preset` | Service preset: `cam`, `iot`, `routers`, `nas`, `rdp`, `db` | — |
| `-t, --threads` | Number of worker threads | `250` |
| `-T, --timeout` | TCP connection timeout in seconds | `1.0` |
| `-c, --country` | Country filter, e.g. `US,DE` | all |
| `-a, --asn` | ASN filter, e.g. `13335,16509` | all |
| `-o, --output` | Output file | `results.txt` |
| `--geo-country-db` | Path to `GeoLite2-Country.mmdb` | auto |
| `--geo-asn-db` | Path to `GeoLite2-ASN.mmdb` | auto |
| `--geo-online` | Enable online GeoIP fallback | off |

## 🔌 Service Presets

Presets group commonly associated ports by device or service class. They are intended for **authorized asset inventory and exposure auditing**.

| Preset | Ports | Intended use |
|---|---|---|
| `cam` | `554, 1935, 8000, 8080, 8899, 34567, 49152` | IP cameras |
| `iot` | `80, 443, 1883, 5683, 8080, 8883, 9100` | IoT devices, MQTT, printers |
| `routers` | `21, 22, 23, 53, 80, 443, 8080, 8443` | Network equipment |
| `nas` | `22, 139, 443, 445, 5000-5007, 9000` | NAS and file-sharing services |
| `rdp` | `22, 23, 3389, 4899, 5800-5901, 5985` | Remote-access services |
| `db` | `1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017` | Database exposure |

## 📄 Output

Results are appended to the configured output file, with one `IP:PORT` result per line:

```text
192.168.1.10:22
192.168.1.15:80
192.168.1.15:443
```

For example:

```bash
python massip_scan.py 192.168.1.0/24 -p 80,443 -o results.txt
```

## 🧠 How the Bloom Filter Works

`massip-scan` uses a Bloom filter to reduce duplicate IP scans when target ranges overlap.

Each IP is processed using two hash functions and represented in a compact bit array using **Kirsch–Mitzenmacher double hashing**.

Before an IP is scanned, the worker checks the Bloom filter:

1. Hash the IP address.
2. Check the corresponding bit positions.
3. Skip the IP when the filter indicates it has already been processed.
4. Otherwise, mark the IP and proceed with the scan.

This provides efficient deduplication while using substantially less memory than a Python `set`.

With the configured parameters, the implementation targets approximately a **0.1% false-positive rate** and roughly **1.2 MB per million IPs**, compared with significantly higher memory usage for a conventional Python set.

> **Note:** Bloom filters are probabilistic. A false positive can cause an IP to be skipped, so the filter should not be described as mathematically guaranteeing that every unique IP will be scanned.

## 🆚 Why massip-scan?

For many professional scanning tasks, **Nmap** remains the better choice because it provides:

- Service/version detection
- OS detection
- NSE scripting
- Extensive scanning options
- A mature ecosystem

`massip-scan` is intentionally smaller and easier to understand. It can be useful when you want:

- A lightweight TCP scanner
- Minimal dependencies
- Simple source code
- Concurrent scanning
- A practical example of Bloom-filter-based deduplication
- A project that is easy to modify for your own authorized lab or infrastructure

For large-scale Internet research, consider platforms designed for that purpose and their applicable terms and legal frameworks, such as **Shodan** or **Censys**.

## 🔐 Responsible Use

This project performs active TCP connection attempts.

Only scan systems for which you have explicit authorization.

Suitable environments include:

- Your own servers and networks
- Home labs
- CTF environments
- Hack The Box
- TryHackMe
- VulnHub
- Authorized penetration tests
- Client infrastructure covered by a signed scope

Do **not** use this project to scan systems or networks without permission.

The authors and contributors are not responsible for misuse of this software.

By using this software, you agree to use it only against authorized targets and in accordance with applicable laws and regulations.

## 📜 License

This project is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

## 👤 Author

**bladlvde**

GitHub: https://github.com/bladlvde

Repository: https://github.com/bladlvde/massip-scan

---

⭐ If you find `massip-scan` useful for authorized security research, consider starring the repository.
