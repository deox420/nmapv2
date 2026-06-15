# ENVIRONMENT — lab & build setup

## Host
- Ubuntu 24.04.4 LTS, x86_64, 4 cores, ~31 GB free disk.
- Tools: gcc, g++, make, autoconf, automake, python3, pkg-config, docker.
- Dev libs present: libssl-dev (3.0.13), zlib1g-dev (1.3), libpcre2-dev (10.42).
- nmap bundles: libpcap, liblua, libdnet-stripped, libnetutil, liblinear, libssh2, libz, libpcre.

## Repo / fork
- Fork repo (origin): deox420/nmapv2 (via local_proxy). Work branch: claude/nmap-enhanced-fork-yn7y8t.
- Upstream nmap: https://github.com/nmap/nmap.git  — baseline commit recorded in `.upstream-nmap-commit`.

## Build recipe (baseline — verified)
```
cd /home/user/nmapv2
./configure --without-zenmap --without-ndiff
make -j$(nproc)
# binary: ./nmap   (run as ./nmap unless installed)
```
Notes:
- `--without-zenmap --without-ndiff` skips the Python GUI/diff tooling we don't need for engine work.
- Build log of baseline kept at /tmp/baseline-build.log during session 1.

## Lab services (docker) — bring up ON DEMAND per proposal
> Container is ephemeral. Re-create with these commands each session. Scan ONLY localhost / lab nets.

| Service        | Bring-up command (example)                                               | Port(s)      |
|----------------|--------------------------------------------------------------------------|--------------|
| HTTP/1.1+2     | `docker run -d --name lab-nginx -p 8080:80 -p 8443:443 nginx:alpine`     | 8080, 8443   |
| SSH            | `docker run -d --name lab-ssh -p 2222:22 linuxserver/openssh-server`     | 2222         |
| (others)       | added per proposal in the relevant ledger                                | —            |

## Test harness
- Per-proposal reproducible scripts: `tests/improvements/<id>/run.sh`
  Each: (a) bring up service, (b) run ./nmap with new feature, (c) assert expected output, (d) tear down.
- No-regression smoke: `tests/improvements/smoke/` — plain scan of localhost must keep working.

## Safety / scope
- All scanning restricted to 127.0.0.0/8, ::1, and docker-internal lab nets. Never external targets.
- NPSL license headers preserved on all upstream files; changes documented as derivative.
