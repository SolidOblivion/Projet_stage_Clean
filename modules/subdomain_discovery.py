import asyncio

import dns.resolver
import requests

try:
    import aiodns
except ImportError:
    aiodns = None

from config.settings import (
    CERTSPOTTER_RETRIES,
    CERTSPOTTER_TIMEOUT,
    HACKERTARGET_TIMEOUT,
    MAX_SUBDOMAINS,
    SUBDOMAIN_DNS_CONCURRENCY,
    SUBDOMAIN_DNS_NAMESERVERS,
    SUBDOMAIN_DNS_TIMEOUT,
    SUBDOMAINS_WORDLIST,
)


def normaliser_sous_domaine(valeur, domaine):
    sous_domaine = valeur.strip().lower().rstrip(".")

    if not sous_domaine:
        return None
    if "*" in sous_domaine:
        return None
    if sous_domaine == domaine:
        return None
    if not sous_domaine.endswith(f".{domaine}"):
        return None

    return sous_domaine


def log_diagnostic(source, brut=0, acceptes=0, statut=None, erreur=None, tentative=None):
    details = []
    if tentative is not None:
        details.append(f"tentative={tentative}")
    if statut is not None:
        details.append(f"http={statut}")
    details.append(f"brut={brut}")
    details.append(f"acceptes={acceptes}")
    if erreur:
        details.append(f"erreur={erreur}")

    print(f"  [{source}] diagnostic : " + ", ".join(details))


def chercher_via_hackertarget(domaine):
    print("recherche via HackerTarget...")

    url = f"https://api.hackertarget.com/hostsearch/?q={domaine}"
    raw = []
    sous_domaines = set()
    lignes_lues = 0

    try:
        response = requests.get(url, timeout=HACKERTARGET_TIMEOUT)

        if response.status_code != 200:
            print(f"  [hackertarget] Erreur lors de l'interrogation : {response.status_code}")
            print(f"[DEBUG][hackertarget] brut={len(raw)} / apres filtre={len(sous_domaines)}")
            log_diagnostic("hackertarget", statut=response.status_code)
            return sous_domaines

        lignes = response.text.splitlines()
        lignes_lues = len(lignes)

        for ligne in lignes:
            if "," not in ligne:
                continue

            brut = ligne.split(",", 1)[0]
            raw.append(brut)
            sous_domaine = normaliser_sous_domaine(brut, domaine)
            if sous_domaine:
                sous_domaines.add(sous_domaine)

    except Exception as e:
        print(f"  [hackertarget] Erreur : {e}")
        log_diagnostic("hackertarget", brut=lignes_lues, acceptes=len(sous_domaines), erreur=e)

    print(f"[DEBUG][hackertarget] brut={len(raw)} / apres filtre={len(sous_domaines)}")
    log_diagnostic("hackertarget", brut=lignes_lues, acceptes=len(sous_domaines))
    print(f"  [hackertarget] {len(sous_domaines)} sous-domaines trouves")
    return sous_domaines


def chercher_via_certspotter(domaine):
    print("recherche via CertSpotter...")

    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={domaine}&include_subdomains=true&expand=dns_names"
    )
    raw = []
    sous_domaines = set()

    for tentative in range(1, CERTSPOTTER_RETRIES + 2):
        noms_lus = 0

        try:
            response = requests.get(url, timeout=CERTSPOTTER_TIMEOUT)

            if response.status_code != 200:
                print(f"  [certspotter] Erreur HTTP : {response.status_code}")
                print(f"[DEBUG][certspotter] brut={len(raw)} / apres filtre={len(sous_domaines)}")
                log_diagnostic(
                    "certspotter",
                    brut=noms_lus,
                    acceptes=len(sous_domaines),
                    statut=response.status_code,
                    tentative=tentative,
                )
                continue

            data = response.json()
            for entry in data:
                for nom in entry.get("dns_names", []):
                    noms_lus += 1
                    raw.append(nom)
                    sous_domaine = normaliser_sous_domaine(nom, domaine)
                    if sous_domaine:
                        sous_domaines.add(sous_domaine)

            print(f"[DEBUG][certspotter] brut={len(raw)} / apres filtre={len(sous_domaines)}")
            log_diagnostic(
                "certspotter",
                brut=noms_lus,
                acceptes=len(sous_domaines),
                statut=response.status_code,
                tentative=tentative,
            )
            break

        except Exception as e:
            print(f"  [certspotter] Erreur : {e}")
            log_diagnostic(
                "certspotter",
                brut=noms_lus,
                acceptes=len(sous_domaines),
                erreur=e,
                tentative=tentative,
            )

    print(f"  [certspotter] {len(sous_domaines)} sous-domaines trouves")
    return sous_domaines


async def chercher_via_wordlist_async(domaine):
    sous_domaines = set()
    erreurs_dns = 0
    semaphore = asyncio.Semaphore(SUBDOMAIN_DNS_CONCURRENCY)

    if aiodns is not None:
        resolver = aiodns.DNSResolver(
            nameservers=SUBDOMAIN_DNS_NAMESERVERS or None,
            timeout=SUBDOMAIN_DNS_TIMEOUT,
        )
        backend = "aiodns"
    else:
        resolver = dns.resolver.Resolver(configure=True)
        if SUBDOMAIN_DNS_NAMESERVERS:
            resolver.nameservers = SUBDOMAIN_DNS_NAMESERVERS
        resolver.timeout = SUBDOMAIN_DNS_TIMEOUT
        resolver.lifetime = SUBDOMAIN_DNS_TIMEOUT
        backend = "dnspython-thread"

    print(
        "  [wordlist] backend="
        f"{backend}, concurrence={SUBDOMAIN_DNS_CONCURRENCY}, timeout={SUBDOMAIN_DNS_TIMEOUT}s"
    )

    async def probe(nom):
        nonlocal erreurs_dns
        candidat = f"{nom.strip().lower()}.{domaine}"
        async with semaphore:
            try:
                if aiodns is not None:
                    if hasattr(resolver, "query_dns"):
                        await resolver.query_dns(candidat, "A")
                    else:
                        await resolver.query(candidat, "A")
                else:
                    await asyncio.to_thread(resolver.resolve, candidat, "A")
                return candidat
            except Exception:
                erreurs_dns += 1
                return None

    noms = [nom for nom in dict.fromkeys(SUBDOMAINS_WORDLIST) if nom.strip()]
    print(f"[DEBUG][wordlist] taille wordlist = {len(SUBDOMAINS_WORDLIST)}")
    resultats = await asyncio.gather(*(probe(nom) for nom in noms))

    for candidat in resultats:
        if candidat:
            sous_domaines.add(candidat)
            print(f"  [wordlist] trouve : {candidat}")

    print(f"[DEBUG][wordlist] brut={len(noms)} / apres filtre={len(sous_domaines)}")
    print(f"[DEBUG][wordlist] erreurs_dns={erreurs_dns}")
    log_diagnostic("wordlist", brut=len(noms), acceptes=len(sous_domaines))
    return sous_domaines


def chercher_via_wordlist(domaine):
    print("recherche via wordlist...")

    try:
        sous_domaines = asyncio.run(chercher_via_wordlist_async(domaine))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            sous_domaines = loop.run_until_complete(chercher_via_wordlist_async(domaine))
        finally:
            loop.close()

    print(f"  [wordlist] {len(sous_domaines)} sous-domaines trouves")
    return sous_domaines


def trouver_sous_domaines(domaine):
    domaine = domaine.strip().lower().rstrip(".")

    resultats_hackertarget = chercher_via_hackertarget(domaine)
    resultats_certspotter = chercher_via_certspotter(domaine)
    resultats_wordlist = chercher_via_wordlist(domaine)

    tous_les_sous_domaines = (
        resultats_hackertarget
        | resultats_certspotter
        | resultats_wordlist
        | {domaine}
    )
    print(
        f"[DEBUG][fusion] avant cap={len(tous_les_sous_domaines)} / "
        f"MAX={MAX_SUBDOMAINS}"
    )
    tous_les_sous_domaines = sorted(tous_les_sous_domaines)[:MAX_SUBDOMAINS]

    print(f"\nTotal : {len(tous_les_sous_domaines)} sous-domaines decouverts")
    return tous_les_sous_domaines
