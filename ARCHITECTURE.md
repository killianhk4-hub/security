# Architecture

Résumé technique du document « Architecture de cyberdéfense adaptative »
(6 novembre 2026).

Objectif réaliste : aucun système n'est inviolable. On vise à rendre l'attaque
trop chère, à la détecter en minutes et à limiter ce qu'elle peut voler.

## Les 7 portes d'entrée observées (2024–2026)

| # | Mécanisme | Incidents |
| --- | --- | --- |
| 1 | Manipulation humaine (faux support, faux recruteur) | Free 2024, France Travail 2024, Binance 2026 |
| 2 | Identifiants volés (infostealers, réutilisation) | Ministère de l'Intérieur 2025, France Travail 2025, CAF 2024 |
| 3 | Pas de double authentification résistante | Free, CAF, Intérieur |
| 4 | Prestataires / chaîne d'approvisionnement | Bybit (Safe{Wallet}), Bouygues fibre, France Travail Kairos |
| 5 | Équipements connectés exposés et non corrigés | Frigos de supermarchés, oct. 2026 |
| 6 | Postes de dev, jetons durables, outils IA internes | Binance 2026, Bybit 2025 |
| 7 | Exfiltration massive non détectée | Free (~3 sem.), France Travail (1 mois), Intérieur (26 j) |

## Les 6 couches

1. **Humains et procédures** : rappel obligatoire avant toute réinitialisation, code verbal.
2. **Identité** : passkeys / clés FIDO2 pour tous, droits minimaux, accès temporaires.
3. **Postes et développement** : EDR, code externe exécuté en machine jetable, jetons de quelques minutes.
4. **Réseau et équipements connectés** : Zero Trust, rien d'exposé sur Internet, OT segmentée, capteurs indépendants.
5. **Applications et prestataires** : accès tiers nominatifs et journalisés, pipeline signé, SBOM.
6. **Données** : plafonds de consultation, IBAN chiffrés à part, sauvegardes immuables.

**Supervision 24/7**, isolée du reste du SI, reçoit les journaux de chaque couche.

## Boucle d'amélioration

Veille → attaque simulée → détection → réaction → retour d'expérience →
mise en production (validée par un humain) → veille.

## Auto-protection de la défense

- Infrastructure de supervision séparée, comptes et clés propres.
- Journaux inaltérables (cf. `Journal` dans `integrite.py`).
- Battement de cœur : un agent de sécurité silencieux déclenche une alerte.
- Toute modification des règles exige deux personnes.
- L'IA de défense analyse et propose ; elle n'a aucun droit d'écriture seule.
- Leurres : faux comptes, faux fichiers, fausses clés.
