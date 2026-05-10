import os
import time

from modules.dns_resolver import resoudre_dns
from pipeline import runner


def main():
    domain = os.getenv("BENCH_DOMAIN", "www.example.com").strip()

    start_resolve = time.perf_counter()
    resolved = resoudre_dns([domain])
    resolve_time = time.perf_counter() - start_resolve

    scan_time = 0.0
    open_ports = 0
    ips = sum(len(item["ips"]) for item in resolved) if resolved else 0

    if resolved:
        start_scan = time.perf_counter()
        scanned = runner.scanner_ports(resolved)
        scan_time = time.perf_counter() - start_scan
        open_ports = sum(
            len(ports)
            for entry in scanned
            for ports in entry["ports_par_ip"].values()
        )

    print(f"DOMAIN={domain}")
    print(f"RESOLVE_TIME={resolve_time:.3f}")
    print(f"SCAN_TIME={scan_time:.3f}")
    print(f"IPS={ips}")
    print(f"OPEN_PORTS={open_ports}")
    print(f"PORT_SCANNER_MODE={os.getenv('PORT_SCANNER_MODE', '')}")
    print(f"TIMEOUT={os.getenv('TIMEOUT', '')}")
    print(f"THREADS={os.getenv('THREADS', '')}")
    print(f"PORT_SCAN_CONCURRENCY={os.getenv('PORT_SCAN_CONCURRENCY', '')}")
    print(f"MAX_PORTS={os.getenv('MAX_PORTS', '')}")


if __name__ == "__main__":
    main()
