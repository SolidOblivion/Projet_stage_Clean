import uuid
from datetime import datetime, timezone


def calculer_summary(sous_domaines):
    toutes_les_ips = set()
    for sd in sous_domaines:
        for ip in sd["ips"]:
            toutes_les_ips.add(ip)

    total_ports = 0
    for sd in sous_domaines:
        for ports in sd["ports_par_ip"].values():
            total_ports += len(ports)

    toutes_les_techs = set()
    for sd in sous_domaines:
        for service in sd["services_web"]:
            for tech in service["technologies"]:
                toutes_les_techs.add(tech)

    total_endpoints = 0
    for sd in sous_domaines:
        for service in sd["services_web"]:
            total_endpoints += len(service.get("endpoints", []))

    return {
        "total_subdomains": len(sous_domaines),
        "total_ips": len(toutes_les_ips),
        "total_open_ports": total_ports,
        "total_technologies": len(toutes_les_techs),
        "total_endpoints": total_endpoints,
    }


def nettoyer_sous_domaine(sd):
    return {
        "subdomain": sd["subdomain"],
        "ips": sd["ips"],
        "dns": {
            "mx": sd["mx"],
            "ns": sd["ns"],
            "cname": sd["cname"],
        },
        "ports_par_ip": sd["ports_par_ip"],
        "services_web": sd["services_web"],
    }


def assembler_resultats(domaine, sous_domaines):
    print(f"\nAssemblage des résultats pour : {domaine}")

    sous_domaines_propres = [nettoyer_sous_domaine(sd) for sd in sous_domaines]
    summary = calculer_summary(sous_domaines)

    resultat_final = {
        "scan_id": str(uuid.uuid4()),
        "target": domaine,
        "scan_date": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subdomains": sous_domaines_propres,
        "summary": summary,
    }

    print("\nRésumé du scan :")
    print(f"   sous-domaines  : {summary['total_subdomains']}")
    print(f"   IPs uniques    : {summary['total_ips']}")
    print(f"   ports ouverts  : {summary['total_open_ports']}")
    print(f"   technologies   : {summary['total_technologies']}")
    print(f"   endpoints      : {summary['total_endpoints']}")

    return resultat_final
