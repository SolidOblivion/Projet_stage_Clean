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

    # Compteur CPE : nombre de détections avec un CPE valide
    total_cpe_matches = 0
    for sd in sous_domaines:
        for service in sd["services_web"]:
            for detail in service.get("technology_details", []):
                if detail.get("cpe_status") == "matched":
                    total_cpe_matches += 1

    return {
        "total_subdomains": len(sous_domaines),
        "total_ips": len(toutes_les_ips),
        "total_open_ports": total_ports,
        "total_technologies": len(toutes_les_techs),
        "total_endpoints": total_endpoints,
        "total_cpe_matches": total_cpe_matches,
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


def collecter_cpe_matches(sous_domaines):
    """
    Agrège tous les CPE matches de tous les services web de tous les sous-domaines.

    Retourne une liste dédoublonnée de CPE avec contexte.
    """
    cpe_matches = []
    cpe_uris_vues = set()

    for sd in sous_domaines:
        for service in sd.get("services_web", []):
            for detail in service.get("technology_details", []):
                cpe = detail.get("cpe")
                if not cpe:
                    continue

                uri = cpe.get("uri", "")
                if uri in cpe_uris_vues:
                    continue

                cpe_uris_vues.add(uri)
                cpe_matches.append({
                    "technology": detail["name"],
                    "version": detail.get("version"),
                    "cpe_uri": uri,
                    "method": cpe.get("method", "local_mapping"),
                    "confidence": detail.get("confidence", "medium"),
                    "found_on": sd["subdomain"],
                })

    return cpe_matches


def assembler_resultats(domaine, sous_domaines):
    print(f"\nAssemblage des résultats pour : {domaine}")

    sous_domaines_propres = [nettoyer_sous_domaine(sd) for sd in sous_domaines]
    summary = calculer_summary(sous_domaines)
    cpe_matches = collecter_cpe_matches(sous_domaines)

    resultat_final = {
        "scan_id": str(uuid.uuid4()),
        "target": domaine,
        "scan_date": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subdomains": sous_domaines_propres,
        "summary": summary,
        "cpe_matches": cpe_matches,
    }

    print("\nRésumé du scan :")
    print(f"   sous-domaines  : {summary['total_subdomains']}")
    print(f"   IPs uniques    : {summary['total_ips']}")
    print(f"   ports ouverts  : {summary['total_open_ports']}")
    print(f"   technologies   : {summary['total_technologies']}")
    print(f"   endpoints      : {summary['total_endpoints']}")
    print(f"   CPE matches    : {summary['total_cpe_matches']}")

    return resultat_final
