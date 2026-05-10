# 📋 Liste des tâches - ASM Web Dashboard

Voici les dernières étapes pour finaliser le projet de stage et le rendre "prêt pour la production".

## 🛠 En cours / Prioritaire
- [ ] **Implémenter la Furtivité (Stealth)** :
    - [ ] Ajouter le `BATCH_SIZE` et le `JITTER` au scanner de ports.
    - [ ] Mettre en place la rotation aléatoire des `User-Agent` pour les requêtes HTTP.
- [ ] **Conteneurisation (Docker)** :
    - [ ] Créer le `Dockerfile` pour l'application FastAPI.
    - [ ] Créer le fichier `docker-compose.yml` pour lier l'API et MongoDB.

## 🚀 Améliorations (Bonus Soutenance)
- [ ] **Export de Rapport** : Ajouter un bouton "Télécharger en PDF" dans la modale de résultat.
- [ ] **Authentification** : Ajouter une page de login simple (JWT) pour sécuriser l'accès au dashboard.
- [ ] **Export CSV** : Permettre d'exporter la liste des sous-domaines et ports ouverts en CSV pour Excel.

## 📚 Documentation & Finition
- [ ] **README.md** : Mettre à jour les instructions d'installation avec Docker.
- [ ] **Commentaires** : Vérifier que chaque module a ses commentaires pédagogiques.
- [ ] **Démonstration** : Préparer une liste de cibles "sûres" (comme scanme.nmap.org) pour la présentation en direct.

---
*Note : Pour marquer une tâche comme faite, remplacez `[ ]` par `[x]`. Mais n'oubliez pas de me demander de les implémenter !*
