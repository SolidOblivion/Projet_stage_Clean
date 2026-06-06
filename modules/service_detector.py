import asyncio
import re
import time
from typing import List, Dict, Any, Tuple, Optional
from config.settings import BANNER_TIMEOUT, BANNER_CONCURRENCY

PATTERNS = [
    (re.compile(r"^SSH-[\d.]+-(\S+)"), "ssh", 1),
    (re.compile(r"^220[\s-].*?(ProFTPD|vsftpd|FileZilla|Pure-FTPd)[^\d]*([\d.]+)?", re.IGNORECASE), "ftp", 2),
    (re.compile(r"^220\s.*?(Postfix|Sendmail|Exim|Exchange|MailEnable)[^\d]*([\d.]+)?", re.IGNORECASE), "smtp", 2),
    (re.compile(r"^220\s+\S+\s+(ESMTP|SMTP)", re.IGNORECASE), "smtp", None),
    (re.compile(r"^\+OK\s+(.*?)\s+ready", re.IGNORECASE), "pop3", 1),
    (re.compile(r"^\* OK\s+(.*?)\s+(IMAP\s+)?ready", re.IGNORECASE), "imap", 1),
    (re.compile(r"^(\+PONG|-ERR)"), "redis", None),
    (re.compile(r"\x0a([\d.]+)\x00"), "mysql", 1),
    (re.compile(r"^\xff[\xfb-\xfe]"), "telnet", None),
    (re.compile(r"\x00\x00\x00\x00.*mongodb", re.DOTALL), "mongodb", None)
]

def parser_banniere(banner: str) -> Tuple[Optional[str], Optional[str]]:
    for pattern, service, group_idx in PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.group(group_idx) if group_idx and len(match.groups()) >= group_idx else None
            return service, version
    return None, None

async def inspecter_port(ip: str, port_info: dict, semaphore: asyncio.Semaphore):
    port = port_info["port"]
    async with semaphore:
        reader, writer = None, None
        banner_phase1 = None
        service = "unknown"
        version = None
        banner_to_save = None

        try:
            # PHASE 1 - Passive
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=BANNER_TIMEOUT
                )
            except Exception:
                port_info["banner"] = None
                port_info["version"] = None
                print(f"[service_detector] ip={ip} port={port} → aucune bannière reçue")
                return

            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                if data:
                    banner_phase1 = data.decode("utf-8", errors="ignore").strip()
                    banner_to_save = banner_phase1
                    svc, ver = parser_banniere(banner_phase1)
                    if svc:
                        service = svc
                        version = ver
                        ver_str = f" version={version}" if version else ""
                        print(f"[service_detector] ip={ip} port={port} → service={service}{ver_str} (phase 1)")
            except Exception:
                pass

            # PHASE 2 - Active HTTP fallback
            if service == "unknown":
                fallback_success = False
                try:
                    req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("utf-8")
                    writer.write(req)
                    await writer.drain()

                    data2 = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                    if data2:
                        resp = data2.decode("utf-8", errors="ignore").strip()
                        if resp.startswith("HTTP/"):
                            service = "http"
                            banner_to_save = resp
                            print(f"[service_detector] ip={ip} port={port} → service=http (HTTP fallback)")
                            fallback_success = True
                except Exception:
                    pass

                if not fallback_success:
                    if banner_phase1:
                        preview = banner_phase1[:50].replace('\n', ' ') + ('...' if len(banner_phase1) > 50 else '')
                        print(f"[service_detector] ip={ip} port={port} → bannière reçue non identifiée : '{preview}'")
                    else:
                        print(f"[service_detector] ip={ip} port={port} → aucune bannière reçue")

        except Exception:
            pass
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        port_info["service"] = service
        port_info["banner"] = banner_to_save
        port_info["version"] = version

async def detecter_services_async(sous_domaines_scannes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    start_time = time.time()
    
    ports_par_ip_global = {}
    for entree in sous_domaines_scannes:
        for ip, ports_list in entree.get("ports_par_ip", {}).items():
            if ip not in ports_par_ip_global:
                ports_par_ip_global[ip] = ports_list

    ip_to_unknown_ports = {
        ip: [p for p in ports if p.get("service") == "unknown"]
        for ip, ports in ports_par_ip_global.items()
    }
    ip_to_unknown_ports = {
        ip: ports for ip, ports in ip_to_unknown_ports.items() if ports
    }

    total_unknown_unique = sum(len(ports) for ports in ip_to_unknown_ports.values())

    if total_unknown_unique == 0:
        return sous_domaines_scannes

    print(f"[service_detector] {total_unknown_unique} ports unknown détectés sur {len(ip_to_unknown_ports)} IPs uniques")

    semaphore = asyncio.Semaphore(BANNER_CONCURRENCY)
    tasks = []

    for ip, p_infos in ip_to_unknown_ports.items():
        for p_info in p_infos:
            tasks.append(inspecter_port(ip, p_info, semaphore))

    await asyncio.gather(*tasks)

    identifies = sum(1 for ip, p_infos in ip_to_unknown_ports.items() for p in p_infos if p.get("service", "unknown") != "unknown")
    elapsed = time.time() - start_time
    print(f"[service_detector] terminé en {elapsed:.1f}s — {identifies} identifiés / {total_unknown_unique} unknown traités")

    return sous_domaines_scannes

def detecter_services(sous_domaines_scannes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return asyncio.run(detecter_services_async(sous_domaines_scannes))
