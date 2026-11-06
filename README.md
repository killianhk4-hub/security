# Système de sécurité — dossier de code

Dossier de travail du système de cyberdéfense adaptative. Il contient la
première brique opérationnelle (le contrôle d'intégrité) et les documents qui
décrivent le reste du système à construire.

Document de référence complet : « Architecture de cyberdéfense adaptative »
(analyse des attaques Binance, Bybit, Free, Bouygues, SFR, France Travail,
CAF, ministère de l'Intérieur, frigos de supermarchés ; matrice attaque →
parade ; feuille de route).

## Contenu

| Fichier | Rôle |
| --- | --- |
| `README.md` | Ce fichier |
| `ARCHITECTURE.md` | Les 7 portes d'entrée des pirates, les 6 couches de défense, la boucle d'amélioration |
| `AGENT.md` | Consignes pour l'agent (Jarvis) qui reprend le projet |
| `integrite.py` | Module d'intégrité : empreintes signées, vérification, journal chaîné |
| `test_integrite.py` | 23 tests unitaires du module |
| `CLAUDE.md` | Point d'entrée pour un agent Claude (renvoie vers `AGENT.md`) |

## Démarrage

```
git clone https://github.com/killianhk4-hub/security.git ~/projets/securite
cd ~/projets/securite
python3 -m unittest test_integrite -v          # 23 tests, Python 3.8+, aucune dépendance

export INTEGRITE_CLE="une-longue-phrase-secrete"   # jamais stockée dans le dossier surveillé
python3 integrite.py init     <dossier-a-proteger> ~/manifeste.json
python3 integrite.py verifier <dossier-a-proteger> ~/manifeste.json --journal ~/journal.log
```

Codes de sortie de `verifier` : `0` intact, `1` changement détecté, `2` manifeste
falsifié, clé absente ou erreur.

## État

- [x] Contrôle d'intégrité des fichiers (couche 3 et supervision)
- [ ] Vérification planifiée toutes les 5 minutes + alerte
- [ ] Inventaire des équipements connectés exposés (couche 4)
- [ ] Détection d'exfiltration massive : plafonds et fiches pièges (couche 6)
- [ ] Veille automatique CERT-FR / CVE (boucle d'amélioration, étape 1)
