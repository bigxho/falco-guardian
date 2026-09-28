# FALCO Guardian

**FALCO Guardian** is a free and open-source defensive security project for Linux systems. It combines high-performance packet telemetry in **eBPF/C** with a **Python** detection and response layer designed for local-first monitoring and controlled defensive deployments.

> Project status: early-stage / experimental. Test in an isolated environment before production use.

## Test view
<img width="1304" height="915" alt="Screenshot From 2026-09-28 15-45-37" src="https://github.com/user-attachments/assets/ac26541c-ace6-4b9e-9aca-3a4f2eb2d697" />


## Core capabilities

- Kernel-level IPv4 packet telemetry through eBPF/XDP.
- Unix-socket event pipeline between the C/eBPF capture layer and Python.
- Port-scan detection.
- SSH brute-force detection based on authentication logs.
- Anomalous successful-login detection using country allowlists and optional nighttime alerts.
- Heuristic detection of unusually large outbound transfers to external hosts.
- Optional IP blocking through `iptables`.
- Local MaxMind GeoLite2 lookup support.
- Lightweight Flask dashboard for recent alerts.
- systemd service definitions for the eBPF and Python components.

## Architecture

```text
                   Linux network interface
                            |
                            v
              +---------------------------+
              | eBPF / XDP capture layer  |
              | capture.bpf.c             |
              +-------------+-------------+
                            |
                       BPF ring buffer
                            |
                            v
              +---------------------------+
              | C userspace loader        |
              | loader.c                  |
              +-------------+-------------+
                            |
                 Unix socket / JSON events
                            |
                            v
              +---------------------------+
              | Python detection layer    |
              | capture + auth log input  |
              +-------------+-------------+
                            |
          +-----------------+------------------+
          |                 |                  |
          v                 v                  v
      Detectors          IP blocker       Alert logging
          |                                    |
          +------------------+-----------------+
                             v
                       Flask dashboard
```

The eBPF layer observes traffic and emits compact metadata. Detection and optional enforcement remain in Python so rules can be changed without recompiling the eBPF program.

## Repository structure

```text
falco-guardian/
├── ebpf/
│   ├── src/
│   │   ├── common.h
│   │   ├── capture.bpf.c
│   │   └── loader.c
│   ├── Makefile
│   └── README.md
├── python/
│   ├── main.py
│   ├── core/
│   ├── detectors/
│   └── dashboard/
├── config/config.yaml
├── systemd/
├── install.sh
├── requirements.txt
└── LICENSE.md
```

## Requirements

The current installer targets Debian-based Linux systems. The eBPF component requires a kernel with BTF support and sufficient privileges to load eBPF programs and attach XDP. Optional blocking requires privileges to manage `iptables` rules.

## Quick start

Clone the repository and enter the project directory:

```bash
git clone https://github.com/bigxho/falco-guardian.git
cd falco-guardian
```

Run the installer on a Debian test VM:

```bash
sudo ./install.sh
```

Review `config/config.yaml` before starting FALCO. In particular, verify the network interface, whitelist, detector thresholds, authentication-log path, and GeoIP configuration.

For an initial test, keep:

```yaml
blocker:
  enabled: false
```

This keeps enforcement in dry-run mode: suspicious activity is detected and logged without adding blocking rules.

Start the eBPF loader and Python layer:

```bash
sudo ./ebpf/build/loader eth0
./venv/bin/python python/main.py
```

Replace `eth0` with the actual interface on the host.

The dashboard is available by default on port `8080` according to `config/config.yaml`.

## GeoIP

GeoIP support uses a local MaxMind GeoLite2 City database. The database is not included in this repository. Download it separately and configure `geoip.database_path`, or disable GeoIP in `config/config.yaml`.

## Security notes

FALCO Guardian is defensive security software. Run it only on systems and networks you own or are explicitly authorized to administer.

Start with blocking disabled. Detection thresholds are deployment-specific and can generate false positives. Review alerts and tune the configuration before enabling automated blocking. The current exfiltration detector is heuristic and should not be treated as definitive evidence of data theft.

The dashboard binds to the address configured in `config/config.yaml`. Do not expose an unauthenticated development dashboard directly to the public Internet.

## Contributing

Issues, defensive improvements, documentation fixes, detector enhancements, tests, and portability improvements are welcome. Keep contributions focused on legitimate defensive monitoring, detection, observability, and incident-response use cases.

## License

FALCO Guardian is free and open-source software distributed under the **GNU General Public License v2.0**. See [`LICENSE.md`](LICENSE.md).

## Project website

Project information: **https://landos.us**

GitHub repository: **https://github.com/bigxho/falco-guardian**
