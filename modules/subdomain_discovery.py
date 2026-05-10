import dns.resolver
import requests

from config.settings import MAX_SUBDOMAINS, SUBDOMAINS_WORDLIST, TIMEOUT


def chercher_via_crtsh(domaine):
    print("recherche via crt.sh...")

    url = f"https://crt.sh/?q=%.{domaine}&output=json"
    sous_domaines = set()

    try:
        # crt.sh est souvent lent, on lui donne un timeout spécifique plus long (10s au lieu de TIMEOUT global)
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"  [crt.sh] Erreur lors de l'interrogation : {response.status_code}")
            return sous_domaines

        data = response.json()

        for entry in data:
            nom = entry.get("name_value", "")

            for sous_domaine in nom.split("\n"):
                sous_domaine = sous_domaine.strip().lower()

                if "*" in sous_domaine:
                    continue
                if sous_domaine == domaine:
                    continue
                if not sous_domaine.endswith(f".{domaine}"):
                    continue

                sous_domaines.add(sous_domaine)

    except Exception as e:
        print(f"  [crt.sh] Erreur : {e}")

    print(f"  [crt.sh] {len(sous_domaines)} sous-domaines trouvés")
    return sous_domaines


def chercher_via_hackertarget(domaine):
    print("recherche via HackerTarget...")

    url = f"https://api.hackertarget.com/hostsearch/?q={domaine}"
    sous_domaines = set()

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"  [hackertarget] Erreur lors de l'interrogation : {response.status_code}")
            return sous_domaines

        lignes = response.text.split("\n")
        for ligne in lignes:
            if "," in ligne:
                sous_domaine = ligne.split(",")[0].strip().lower()
                
                if "*" in sous_domaine:
                    continue
                if sous_domaine == domaine:
                    continue
                if not sous_domaine.endswith(f".{domaine}"):
                    continue

                sous_domaines.add(sous_domaine)

    except Exception as e:
        print(f"  [hackertarget] Erreur : {e}")

    print(f"  [hackertarget] {len(sous_domaines)} sous-domaines trouvés")
    return sous_domaines


def chercher_via_wordlist(domaine):
    print("recherche via wordlist...")

    sous_domaines = set()

    for nom in SUBDOMAINS_WORDLIST:
        candidat = f"{nom}.{domaine}"

        try:
            dns.resolver.resolve(candidat, "A")
            sous_domaines.add(candidat)
            print(f"  [wordlist] trouvé : {candidat}")
        except Exception:
            pass

    print(f"  [wordlist] {len(sous_domaines)} sous-domaines trouvés")
    return sous_domaines


def trouver_sous_domaines(domaine):
    resultats_crtsh = chercher_via_crtsh(domaine)
    resultats_hackertarget = chercher_via_hackertarget(domaine)
    resultats_wordlist = chercher_via_wordlist(domaine)

    tous_les_sous_domaines = resultats_crtsh | resultats_hackertarget | resultats_wordlist
    tous_les_sous_domaines.add(domaine)
    tous_les_sous_domaines = list(tous_les_sous_domaines)[:MAX_SUBDOMAINS]

    print(f"\nTotal : {len(tous_les_sous_domaines)} sous-domaines découverts")
    return tous_les_sous_domaines
