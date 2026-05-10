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
    print("\nScan des ports...")

    resultats = []

    for entree in sous_domaines_resolus:
        sous_domaine = entree["subdomain"]
        ips = entree["ips"]

        print(f"\n  {sous_domaine}")

        ports_par_ip = {}

        for ip in ips:
            ports_ouverts = scanner_ip(ip)
            ports_par_ip[ip] = ports_ouverts

        resultats.append(
            {
                "subdomain": sous_domaine,
                "ips": ips,
                "mx": entree["mx"],
                "ns": entree["ns"],
                "cname": entree["cname"],
                "ports_par_ip": ports_par_ip,
            }
        )

    print(f"\nScan terminé pour {len(resultats)} sous-domaines")
    return resultats
