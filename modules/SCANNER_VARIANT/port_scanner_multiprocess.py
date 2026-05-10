import os
import socket
from multiprocessing import Manager, Process, Queue

from config.settings import MAX_PORTS, THREADS, TIMEOUT


def identifier_service(port):
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


def worker(queue, resultats, worker_id):
    print(f"  [Worker {worker_id}] démarré (PID: {os.getpid()})")

    while True:
        tache = queue.get()

        if tache is None:
            print(f"  [Worker {worker_id}] terminé")
            break

        ip, port = tache

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        resultat = sock.connect_ex((ip, port))
        sock.close()

        if resultat == 0:
            resultats.append(
                {
                    "ip": ip,
                    "port": port,
                    "protocole": "tcp",
                    "service": identifier_service(port),
                    "state": "open",
                }
            )


def scanner_ip(ip):
    print(f"\n  -> Scan de {ip} (ports 1-{MAX_PORTS}) avec {THREADS} workers...")

    with Manager() as manager:
        resultats = manager.list()
        queue = Queue()

        for port in range(1, MAX_PORTS + 1):
            queue.put((ip, port))

        for _ in range(THREADS):
            queue.put(None)

        workers = []
        for worker_id in range(1, THREADS + 1):
            p = Process(target=worker, args=(queue, resultats, worker_id))
            workers.append(p)
            p.start()

        for p in workers:
            p.join()

        ports_ouverts = sorted(list(resultats), key=lambda x: x["port"])

    for port_info in ports_ouverts:
        print(f"     port {port_info['port']} : {port_info['service']}")

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
