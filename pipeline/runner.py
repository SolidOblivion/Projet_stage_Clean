import asyncio
import json
import platform
import sys
import time

from config.settings import PORT_SCANNER_MODE
from modules.data_mapper import assembler_resultats
from modules.dns_resolver import resoudre_dns
from modules.subdomain_discovery import trouver_sous_domaines
from modules.tech_detector import detecter_technologies
from modules.endpoint_discovery import lancer_decouverte_endpoints


def scanner_ports(sous_domaines_resolus):
    if PORT_SCANNER_MODE == "async":
        from modules.SCANNER_VARIANT.port_scanner_async import scanner_ports as scanner_impl
    elif PORT_SCANNER_MODE == "process":
        from modules.SCANNER_VARIANT.port_scanner_multiprocess import (
            scanner_ports as scanner_impl,
        )
    elif platform.system() == "Windows":
        from modules.SCANNER_VARIANT.port_scanner import scanner_ports as scanner_impl
    else:
        from modules.SCANNER_VARIANT.port_scanner_multiprocess import (
            scanner_ports as scanner_impl,
        )

    return scanner_impl(sous_domaines_resolus)


def lancer_scan(domaine):
    print("=" * 70)
    print(f"  LANCEMENT DU SCAN : {domaine}")
    print("=" * 70)

    debut_total = time.time()

    print("\n" + "-" * 70)
    print("  ETAPE 1/6 : Découverte des sous-domaines")
    print("-" * 70)

    debut = time.time()

    try:
        sous_domaines = trouver_sous_domaines(domaine)
    except Exception as e:
        print(f"\nECHEC ETAPE 1 : {e}")
        return None

    if not sous_domaines:
        print("\nAucun sous-domaine trouvé, arrêt du scan")
        return None

    duree = time.time() - debut
    print(f"\nEtape 1 terminée en {duree:.1f}s : {len(sous_domaines)} sous-domaines")

    print("\n" + "-" * 70)
    print("  ETAPE 2/6 : Résolution DNS")
    print("-" * 70)

    debut = time.time()

    try:
        sous_domaines_resolus = resoudre_dns(sous_domaines)
    except Exception as e:
        print(f"\nECHEC ETAPE 2 : {e}")
        return None

    if not sous_domaines_resolus:
        print("\nAucun sous-domaine résolu, arrêt du scan")
        return None

    duree = time.time() - debut
    print(
        f"\nEtape 2 terminée en {duree:.1f}s : "
        f"{len(sous_domaines_resolus)} sous-domaines résolus"
    )

    print("\n" + "-" * 70)
    print("  ETAPE 3/6 : Scan des ports")
    print("-" * 70)

    debut = time.time()

    try:
        sous_domaines_scannes = scanner_ports(sous_domaines_resolus)
    except Exception as e:
        print(f"\nECHEC ETAPE 3 : {e}")
        return None

    duree = time.time() - debut
    print(f"\nEtape 3 terminée en {duree:.1f}s")

    print("\n" + "-" * 70)
    print("  ETAPE 4/6 : Détection des technologies")
    print("-" * 70)

    debut = time.time()

    try:
        sous_domaines_enrichis = asyncio.run(
            detecter_technologies(sous_domaines_scannes)
        )
    except Exception as e:
        print(f"\nECHEC ETAPE 4 : {e}")
        return None

    duree = time.time() - debut
    print(f"\nEtape 4 terminée en {duree:.1f}s")

    print("\n" + "-" * 70)
    print("  ETAPE 5/6 : Découverte des endpoints")
    print("-" * 70)

    debut = time.time()

    try:
        sous_domaines_fuzzes = lancer_decouverte_endpoints(sous_domaines_enrichis)
    except Exception as e:
        print(f"\nECHEC ETAPE 5 : {e}")
        return None

    duree = time.time() - debut
    print(f"\nEtape 5 terminée en {duree:.1f}s")

    print("\n" + "-" * 70)
    print("  ETAPE 6/6 : Assemblage des résultats")
    print("-" * 70)

    debut = time.time()

    try:
        resultat_final = assembler_resultats(domaine, sous_domaines_fuzzes)
    except Exception as e:
        print(f"\nECHEC ETAPE 5 : {e}")
        return None

    duree = time.time() - debut
    print(f"\nEtape 5 terminée en {duree:.1f}s")

    duree_totale = time.time() - debut_total
    resultat_final["summary"]["total_duration"] = round(duree_totale, 1)

    print("\n" + "-" * 70)
    print("  SAUVEGARDE : MongoDB")
    print("-" * 70)

    try:
        from database.mongo_client import sauvegarder_scan

        mongo_id = sauvegarder_scan(resultat_final)
        if mongo_id:
            print(f"\nSauvegardé en base, MongoDB ID : {mongo_id}")
        else:
            print("\nSauvegarde échouée, résultat retourné sans MongoDB")
    except Exception as e:
        print(f"\nErreur MongoDB non bloquante : {e}")

    duree_totale = time.time() - debut_total

    print("\n" + "=" * 70)
    print(f"  SCAN TERMINE : {domaine}")
    print("=" * 70)
    print(f"  scan_id        : {resultat_final['scan_id']}")
    print(f"  sous-domaines  : {resultat_final['summary']['total_subdomains']}")
    print(f"  IPs uniques    : {resultat_final['summary']['total_ips']}")
    print(f"  ports ouverts  : {resultat_final['summary']['total_open_ports']}")
    print(f"  technologies   : {resultat_final['summary']['total_technologies']}")
    print(f"  endpoints      : {resultat_final['summary']['total_endpoints']}")
    print(f"  durée totale   : {duree_totale:.1f}s")
    print("=" * 70 + "\n")

    return resultat_final


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python -m pipeline.runner <domaine>")
        print("Exemple : python -m pipeline.runner nmap.org")
        sys.exit(1)

    domaine = sys.argv[1].strip().lower()
    resultat = lancer_scan(domaine)

    if resultat:
        print(json.dumps(resultat, indent=2, ensure_ascii=False, default=str))
