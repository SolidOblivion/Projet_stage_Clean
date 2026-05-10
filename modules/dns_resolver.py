import dns.resolver


def resoudre_ipv4(sous_domaine):
    ips = []

    try:
        reponse = dns.resolver.resolve(sous_domaine, "A")
        for record in reponse:
            ips.append(record.address)
    except Exception:
        pass

    return ips


def resoudre_mx(sous_domaine):
    mx_records = []

    try:
        reponse = dns.resolver.resolve(sous_domaine, "MX")
        for record in reponse:
            mx_records.append(
                {
                    "serveur": str(record.exchange).rstrip("."),
                    "priorite": record.preference,
                }
            )
    except Exception:
        pass

    return mx_records


def resoudre_ns(sous_domaine):
    ns_records = []

    try:
        reponse = dns.resolver.resolve(sous_domaine, "NS")
        for record in reponse:
            ns_records.append(str(record.target).rstrip("."))
    except Exception:
        pass

    return ns_records


def resoudre_cname(sous_domaine):
    try:
        reponse = dns.resolver.resolve(sous_domaine, "CNAME")
        for record in reponse:
            return str(record.target).rstrip(".")
    except Exception:
        return None

    return None


def resoudre_dns(sous_domaines):
    print(f"\nRésolution DNS pour {len(sous_domaines)} sous-domaines...")

    resultats = []

    for sous_domaine in sous_domaines:
        print(f"  -> {sous_domaine}")

        ips = resoudre_ipv4(sous_domaine)
        mx = resoudre_mx(sous_domaine)
        ns = resoudre_ns(sous_domaine)
        cname = resoudre_cname(sous_domaine)

        if not ips:
            print("     aucune IP trouvée, ignoré")
            continue

        resultats.append(
            {
                "subdomain": sous_domaine,
                "ips": ips,
                "mx": mx,
                "ns": ns,
                "cname": cname,
            }
        )

        print(f"     {ips}")

    print(f"\n{len(resultats)} sous-domaines résolus")
    return resultats
