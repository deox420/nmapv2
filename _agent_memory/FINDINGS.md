# FINDINGS — reusable technical notes about the nmap codebase

> Append code paths, key functions, build gotchas as discovered. Saves re-investigation after context renewal.

## Build system
- Autotools: `configure.ac` -> `./configure` -> top-level `Makefile.in`. Bundled libs each have own subdir + Makefile.
- Main binary sources live at repo top level (*.cc / *.h). Entry point: `nmap.cc` (`main`), core scan: `nmap.cc`,
  `scan_engine.cc`, `service_scan.cc`, `osscan*.cc`, output in `output.cc` / `output.h`.

## Output subsystem (relevant to P05/P06/P14/P15)
- `output.cc` / `output.h`: human (`-oN`), grepable (`-oG`), XML (`-oX`) writers.
- XML is emitted incrementally via `xml_*` helpers in `xml.cc` / `xml.h` and `log_write(LOG_XML, ...)`.
- Log targets are bitmask channels: LOG_NORMAL, LOG_MACHINE, LOG_XML, LOG_STDOUT (see `output.h`).
- CLI option parsing: `nmap.cc` getopt long-options table (search for `"oX"`, `struct option long_options`).

<!-- More findings appended as work proceeds. -->

## Upstream bug fixed (P27): serviceDeductions double-free
- getServiceDeductions (portlist.cc) shallow-copies port->service (borrowed cpe/product/... ptrs).
- Reused `serviceDeductions sd` + erase() on a later no-service port frees borrowed ptrs => UAF + double free.
- Repro on pristine upstream: `nmap -sV -p <open-with-CPE>,<closed>` e.g. python http.server on 8123 + 8124.
- Fix: serviceDeductions::reset() (non-freeing) at the borrowed-pointer call site.
- Tools: gdb shows late abort (malloc_consolidate); valgrind pinpoints real UAF/free site. Both installed.
