from pymongo import DESCENDING, MongoClient

from config.settings import MONGO_DB, MONGO_URI


try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    db = client[MONGO_DB]
    collection = db["scans"]

    client.server_info()
    collection.create_index("scan_id", unique=True)

    print("Connexion MongoDB établie")

except Exception as e:
    print(f"Connexion MongoDB échouée : {e}")
    print("Vérifiez que MongoDB est démarré")
    client = None
    db = None
    collection = None


def nettoyer_id(document):
    if document and "_id" in document:
        document["_id"] = str(document["_id"])
    return document


def sauvegarder_scan(resultat_final):
    if collection is None:
        print("Impossible de sauvegarder, MongoDB non connecté")
        return None

    try:
        resultat = collection.insert_one(resultat_final)
        print(f"Scan sauvegardé, ID : {resultat.inserted_id}")
        return str(resultat.inserted_id)
    except Exception as e:
        print(f"Erreur sauvegarde : {e}")
        return None


def trouver_scan(scan_id):
    if collection is None:
        return None

    try:
        document = collection.find_one({"scan_id": scan_id})
        return nettoyer_id(document)
    except Exception as e:
        print(f"Erreur recherche : {e}")
        return None


def lister_scans():
    if collection is None:
        return []

    try:
        curseur = collection.find(
            {},
            {
                "scan_id": 1,
                "target": 1,
                "scan_date": 1,
                "summary": 1,
                "_id": 1,
            },
        ).sort("scan_date", DESCENDING)

        scans = []
        for doc in curseur:
            scans.append(nettoyer_id(doc))

        return scans
    except Exception as e:
        print(f"Erreur listing : {e}")
        return []


def supprimer_scan(scan_id):
    if collection is None:
        return False

    try:
        resultat = collection.delete_one({"scan_id": scan_id})

        if resultat.deleted_count == 1:
            print(f"Scan {scan_id} supprimé")
            return True

        print(f"Scan {scan_id} introuvable")
        return False

    except Exception as e:
        print(f"Erreur suppression : {e}")
        return False
