import asyncio
import socket

from config.settings import MAX_PORTS, PORT_SCAN_CONCURRENCY, TIMEOUT
from modules.top_ports import TOP_1000_PORTS


def identifier_service(port):
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


async def scanner_un_port(ip, port, semaphore):
    # Le semaphore limite le nombre de connexions simultanées globales.
    async with semaphore:
        writer = None

        try:
            # open_connection essaie d'ouvrir une connexion TCP vers ip:port.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=TIMEOUT,
            )

            return {
                "ip": ip,
                "port": port,
                "protocole": "tcp",
                "service": identifier_service(port),
                "state": "open",
            }

        except Exception:
            return None

        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def scanner_ip_async(ip, semaphore, ports_list):
    """
    Scanner une IP sur une liste de ports spécifique (pas forcément séquentielle).
    Cela permet de passer le vrai Top-1000 Nmap plutôt que range(1, 1001).
    """
    print(f"\n  -> Début du scan de {ip} ({len(ports_list)} ports)...")

    taches = [
        scanner_un_port(ip, port, semaphore)
        for port in ports_list
    ]

    resultats = await asyncio.gather(*taches)
    ports_ouverts = [r for r in resultats if r is not None]
    ports_ouverts.sort(key=lambda x: x["port"])

    for port_info in ports_ouverts:
        print(f"     [IP: {ip}] port {port_info['port']} : {port_info['service']}")

    print(f"     [IP: {ip}] {len(ports_ouverts)} ports ouverts trouvés")
    return ip, ports_ouverts


def build_ports_list(max_ports):
    """
    Construit la liste de ports à scanner selon le mode :
    - max_ports=None ou 0 → Top-1000 Nmap (ports les plus utilisés dans le monde)
    - max_ports=65535     → Scan exhaustif de tous les ports
    - max_ports=N         → range(1, N+1) pour usage personnalisé
    """
    if max_ports is None or max_ports == 0:
        return TOP_1000_PORTS  # Vrais Top-1000 Nmap
    elif max_ports == 1000:
        return TOP_1000_PORTS  # Aussi Top-1000 quand passé explicitement
    else:
        return list(range(1, max_ports + 1))  # Scan séquentiel complet



async def scanner_tous_les_ports_async(sous_domaines_resolus, max_ports=None):
    semaphore = asyncio.Semaphore(PORT_SCAN_CONCURRENCY)

    # Construire la liste de ports adaptée au mode
    ports_list = build_ports_list(max_ports)
    mode_label = f"Top-1000 Nmap" if max_ports in (None, 0, 1000) else f"1-{max_ports}"
    print(f"\nMode de scan : {mode_label} ({len(ports_list)} ports par IP)")

    taches_par_ip = {}
    for entree in sous_domaines_resolus:
        for ip in entree["ips"]:
            if ip not in taches_par_ip:
                taches_par_ip[ip] = scanner_ip_async(ip, semaphore, ports_list)

    print(f"Scan de {len(taches_par_ip)} adresses IPs uniques avec concurrence max = {PORT_SCAN_CONCURRENCY}...")

    resultats_bruts = await asyncio.gather(*taches_par_ip.values())
    ports_scannes_par_ip = {ip: ports for ip, ports in resultats_bruts}

    resultats = []
    for entree in sous_domaines_resolus:
        sous_domaine = entree["subdomain"]
        ips = entree["ips"]
        ports_par_ip = {ip: ports_scannes_par_ip[ip] for ip in ips}
        resultats.append({
            "subdomain": sous_domaine,
            "ips": ips,
            "mx": entree["mx"],
            "ns": entree["ns"],
            "cname": entree["cname"],
            "ports_par_ip": ports_par_ip,
        })

    return resultats


def scanner_ports(sous_domaines_resolus, max_ports=None):
    print("\nScan des ports (Global et Parallèle)...")
    return asyncio.run(scanner_tous_les_ports_async(sous_domaines_resolus, max_ports))

