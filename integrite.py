"""
Module d'intégrité — détecte toute modification des fichiers critiques.

Trois fonctions :
  1. Empreintes : calcule une empreinte SHA-256 de chaque fichier surveillé
     et l'enregistre dans un manifeste signé (HMAC) pour qu'un intrus ne
     puisse pas réécrire le manifeste sans que cela se voie.
  2. Vérification : compare l'état actuel au manifeste et liste les fichiers
     modifiés, ajoutés ou supprimés.
  3. Journal protégé : chaque entrée contient l'empreinte de la précédente
     et une signature HMAC. Supprimer, modifier ou réordonner une entrée
     casse la chaîne.

Uniquement la bibliothèque standard Python (3.8+).

Utilisation en ligne de commande :
    export INTEGRITE_CLE="une-longue-phrase-secrete"
    python3 integrite.py init     <dossier> <manifeste.json>
    python3 integrite.py verifier <dossier> <manifeste.json> [--journal journal.log]

La clé ne doit JAMAIS être stockée dans le dossier surveillé.
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

VERSION_MANIFESTE = 1
TAILLE_BLOC = 1024 * 1024
EXCLUSIONS_PAR_DEFAUT = ("__pycache__/*", "*.pyc", ".git/*")
CHAINE_INITIALE = "0" * 64


class ErreurIntegrite(Exception):
    """Le manifeste ou le journal a été altéré, ou la clé est absente."""


# --------------------------------------------------------------------------
# Clé et signature
# --------------------------------------------------------------------------

def charger_cle(cle=None):
    """Retourne la clé en octets : argument, sinon variable INTEGRITE_CLE."""
    if cle is None:
        cle = os.environ.get("INTEGRITE_CLE")
    if not cle:
        raise ErreurIntegrite(
            "Clé absente : définissez INTEGRITE_CLE (au moins 16 caractères)."
        )
    if isinstance(cle, str):
        cle = cle.encode("utf-8")
    if len(cle) < 16:
        raise ErreurIntegrite("Clé trop courte : au moins 16 caractères.")
    return cle


def _signer(cle, donnees):
    return hmac.new(cle, donnees, hashlib.sha256).hexdigest()


def _json_canonique(objet):
    return json.dumps(objet, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------
# Empreintes
# --------------------------------------------------------------------------

def empreinte_fichier(chemin):
    """SHA-256 d'un fichier, lu par blocs (fonctionne sur les gros fichiers)."""
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(TAILLE_BLOC), b""):
            h.update(bloc)
    return h.hexdigest()


def _est_exclu(chemin_relatif, exclusions):
    return any(fnmatch.fnmatch(chemin_relatif, motif) or
               fnmatch.fnmatch(Path(chemin_relatif).name, motif)
               for motif in exclusions)


def calculer_empreintes(dossier, exclusions=EXCLUSIONS_PAR_DEFAUT):
    """Dictionnaire {chemin relatif: empreinte} pour tout le dossier.

    Les liens symboliques sont enregistrés comme tels (leur cible) et ne
    sont jamais suivis : un lien qui pointe ailleurs est une modification.
    """
    dossier = Path(dossier)
    if not dossier.is_dir():
        raise ErreurIntegrite(f"Dossier introuvable : {dossier}")
    resultat = {}
    for racine, sous_dossiers, fichiers in os.walk(dossier, followlinks=False):
        sous_dossiers.sort()
        for nom in sorted(fichiers):
            complet = Path(racine) / nom
            relatif = complet.relative_to(dossier).as_posix()
            if _est_exclu(relatif, exclusions):
                continue
            if complet.is_symlink():
                resultat[relatif] = "lien:" + os.readlink(complet)
            else:
                resultat[relatif] = empreinte_fichier(complet)
    return resultat


# --------------------------------------------------------------------------
# Manifeste signé
# --------------------------------------------------------------------------

def creer_manifeste(dossier, chemin_manifeste, cle=None,
                    exclusions=EXCLUSIONS_PAR_DEFAUT):
    """Prend les empreintes du dossier et écrit un manifeste signé."""
    cle = charger_cle(cle)
    corps = {
        "version": VERSION_MANIFESTE,
        "cree_le": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exclusions": list(exclusions),
        "fichiers": calculer_empreintes(dossier, exclusions),
    }
    manifeste = {"corps": corps, "signature": _signer(cle, _json_canonique(corps))}
    chemin_manifeste = Path(chemin_manifeste)
    temporaire = chemin_manifeste.with_suffix(chemin_manifeste.suffix + ".tmp")
    temporaire.write_text(json.dumps(manifeste, indent=2, ensure_ascii=False),
                          encoding="utf-8")
    os.replace(temporaire, chemin_manifeste)  # écriture atomique
    return corps


def lire_manifeste(chemin_manifeste, cle=None):
    """Lit le manifeste et refuse tout manifeste dont la signature est fausse."""
    cle = charger_cle(cle)
    try:
        manifeste = json.loads(Path(chemin_manifeste).read_text(encoding="utf-8"))
        corps, signature = manifeste["corps"], manifeste["signature"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ErreurIntegrite(f"Manifeste illisible : {e}") from e
    attendu = _signer(cle, _json_canonique(corps))
    if not hmac.compare_digest(attendu, signature):
        raise ErreurIntegrite("Signature du manifeste invalide : il a été modifié "
                              "ou la clé est différente.")
    if corps.get("version") != VERSION_MANIFESTE:
        raise ErreurIntegrite(f"Version de manifeste inconnue : {corps.get('version')}")
    return corps


# --------------------------------------------------------------------------
# Vérification
# --------------------------------------------------------------------------

@dataclass
class Rapport:
    modifies: list = field(default_factory=list)
    ajoutes: list = field(default_factory=list)
    supprimes: list = field(default_factory=list)

    @property
    def intact(self):
        return not (self.modifies or self.ajoutes or self.supprimes)

    def resume(self):
        if self.intact:
            return "OK : aucun changement détecté."
        lignes = ["ALERTE : changements détectés."]
        for titre, liste in (("Modifiés", self.modifies),
                             ("Ajoutés", self.ajoutes),
                             ("Supprimés", self.supprimes)):
            for chemin in liste:
                lignes.append(f"  {titre:<10} {chemin}")
        return "\n".join(lignes)

    def en_dict(self):
        return {"modifies": self.modifies, "ajoutes": self.ajoutes,
                "supprimes": self.supprimes}


def verifier(dossier, chemin_manifeste, cle=None):
    """Compare le dossier au manifeste signé et retourne un Rapport."""
    corps = lire_manifeste(chemin_manifeste, cle)
    attendu = corps["fichiers"]
    actuel = calculer_empreintes(dossier, tuple(corps.get("exclusions", ())))
    rapport = Rapport(
        modifies=sorted(c for c in attendu.keys() & actuel.keys()
                        if attendu[c] != actuel[c]),
        ajoutes=sorted(actuel.keys() - attendu.keys()),
        supprimes=sorted(attendu.keys() - actuel.keys()),
    )
    return rapport


# --------------------------------------------------------------------------
# Journal chaîné et signé
# --------------------------------------------------------------------------

class Journal:
    """Journal en ajout seul : chaque ligne est liée à la précédente.

    Format : une ligne JSON par entrée
      {"n": numéro, "horodatage": ..., "evenement": ..., "details": ...,
       "precedent": empreinte de l'entrée précédente, "signature": HMAC}

    Limite connue : supprimer les DERNIÈRES lignes ne casse pas la chaîne.
    Pour le détecter, conservez ailleurs (supervision séparée) le dernier
    numéro et la dernière signature, puis passez-les à verifier().
    """

    def __init__(self, chemin, cle=None):
        self.chemin = Path(chemin)
        self.cle = charger_cle(cle)

    def _lignes(self):
        if not self.chemin.exists():
            return []
        return [l for l in self.chemin.read_text(encoding="utf-8").splitlines() if l]

    def _signature_entree(self, entree):
        sans_sig = {k: v for k, v in entree.items() if k != "signature"}
        return _signer(self.cle, _json_canonique(sans_sig))

    def ajouter(self, evenement, details=None):
        lignes = self._lignes()
        if lignes:
            derniere = json.loads(lignes[-1])
            numero, precedent = derniere["n"] + 1, derniere["signature"]
        else:
            numero, precedent = 0, CHAINE_INITIALE
        entree = {
            "n": numero,
            "horodatage": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "evenement": evenement,
            "details": details if details is not None else {},
            "precedent": precedent,
        }
        entree["signature"] = self._signature_entree(entree)
        with open(self.chemin, "a", encoding="utf-8") as f:
            f.write(json.dumps(entree, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entree

    def verifier(self, dernier_numero_attendu=None, derniere_signature_attendue=None):
        """Retourne la liste des problèmes trouvés ([] si le journal est sain)."""
        problemes = []
        precedent = CHAINE_INITIALE
        derniere = None
        for i, ligne in enumerate(self._lignes()):
            try:
                entree = json.loads(ligne)
            except ValueError:
                problemes.append(f"Ligne {i + 1} illisible.")
                break
            if entree.get("n") != i:
                problemes.append(f"Ligne {i + 1} : numéro {entree.get('n')} au lieu de {i} "
                                 "(entrée supprimée ou déplacée).")
            if entree.get("precedent") != precedent:
                problemes.append(f"Ligne {i + 1} : chaîne rompue.")
            if not hmac.compare_digest(self._signature_entree(entree),
                                       str(entree.get("signature", ""))):
                problemes.append(f"Ligne {i + 1} : signature invalide (contenu modifié).")
            precedent = entree.get("signature", "")
            derniere = entree
        if dernier_numero_attendu is not None:
            vu = derniere["n"] if derniere else -1
            if vu < dernier_numero_attendu:
                problemes.append(f"Journal tronqué : dernière entrée {vu}, "
                                 f"attendue au moins {dernier_numero_attendu}.")
        if derniere_signature_attendue is not None and derniere is not None:
            if dernier_numero_attendu is not None and derniere["n"] == dernier_numero_attendu \
                    and derniere["signature"] != derniere_signature_attendue:
                problemes.append("Dernière entrée différente de celle attendue.")
        return problemes


# --------------------------------------------------------------------------
# Ligne de commande
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Contrôle d'intégrité des fichiers critiques.")
    sous = parser.add_subparsers(dest="commande", required=True)

    p_init = sous.add_parser("init", help="prendre les empreintes de référence")
    p_init.add_argument("dossier")
    p_init.add_argument("manifeste")

    p_verif = sous.add_parser("verifier", help="comparer le dossier à la référence")
    p_verif.add_argument("dossier")
    p_verif.add_argument("manifeste")
    p_verif.add_argument("--journal", help="journal où consigner le résultat")
    p_verif.add_argument("--json", action="store_true", help="sortie JSON")

    args = parser.parse_args(argv)
    try:
        if args.commande == "init":
            corps = creer_manifeste(args.dossier, args.manifeste)
            print(f"Référence créée : {len(corps['fichiers'])} fichiers.")
            return 0

        rapport = verifier(args.dossier, args.manifeste)
        if args.journal:
            Journal(args.journal).ajouter(
                "verification_ok" if rapport.intact else "alerte_integrite",
                rapport.en_dict())
        print(json.dumps(rapport.en_dict(), ensure_ascii=False, indent=2)
              if args.json else rapport.resume())
        return 0 if rapport.intact else 1
    except ErreurIntegrite as e:
        print(f"ERREUR : {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
