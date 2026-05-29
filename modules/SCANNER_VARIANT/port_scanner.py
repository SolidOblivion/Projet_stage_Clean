import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.settings import MAX_PORTS, THREADS, TIMEOUT


def identifier_service(port):
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


def scanner_un_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        resultat = sock.connect_ex((ip, port))
    finally:
        sock.close()

    if resultat == 0:
        return {
            "ip": ip,
            "port": port,
            "protocole": "tcp",
            "service": identifier_service(port),
            "state": "open",
        }

    return None


def scanner_ip(ip):
    print(f"\n  -> Scan de {ip} (ports 1-{MAX_PORTS}) avec {THREADS} threads...")

    ports_ouverts = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [
            executor.submit(scanner_un_port, ip, port)
            for port in range(1, MAX_PORTS + 1)
        ]

        for future in as_completed(futures):
            resultat = future.result()
            if resultat is not None:
                ports_ouverts.append(resultat)
                print(f"     port {resultat['port']} : {resultat['service']}")

    ports_ouverts = sorted(ports_ouverts, key=lambda x: x["port"])

    print(f"     {len(ports_ouverts)} ports ouverts trouvés")
    return ports_ouverts


def scanner_ports(sous_domaines_resolus):
    print("\nScan des ports (avec déduplication des IPs)...")

    # Étape 1 : collecter toutes les IPs uniques
    unique_ips = {}
    for entree in sous_domaines_resolus:
        for ip in entree["ips"]:
            if ip not in unique_ips:
                unique_ips[ip] = []
            unique_ips[ip].append(entree["subdomain"])

    # Étape 2 : scanner chaque IP une seule fois
    scan_results = {}
    print(f"Scan de {len(unique_ips)} IPs uniques...")
    for ip in unique_ips:
        scan_results[ip] = scanner_ip(ip)

    # Étape 3 : réassembler les résultats par sous-domaine
    resultats = []
    for entree in sous_domaines_resolus:
        ports_par_ip = {ip: scan_results[ip] for ip in entree["ips"]}
        resultats.append(
            {
                "subdomain": entree["subdomain"],
                "ips": entree["ips"],
                "mx": entree["mx"],
                "ns": entree["ns"],
                "cname": entree["cname"],
                "ports_par_ip": ports_par_ip,
            }
        )

    print(f"\nScan terminé pour {len(resultats)} sous-domaines")
    return resultats
