"""Tests du module d'intégrité.

Lancer :  python3 -m unittest test_integrite -v
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

import integrite
from integrite import ErreurIntegrite, Journal

CLE = "cle-de-test-suffisamment-longue"


class BaseTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.dossier = base / "surveille"
        self.dossier.mkdir()
        (self.dossier / "config.ini").write_text("seuil=50\n")
        (self.dossier / "regles").mkdir()
        (self.dossier / "regles" / "detection.yml").write_text("regle: export_massif\n")
        self.manifeste = base / "manifeste.json"  # hors du dossier surveillé
        self.journal = base / "journal.log"

    def tearDown(self):
        self._tmp.cleanup()


class TestCle(unittest.TestCase):
    def test_cle_absente_refusee(self):
        ancien = os.environ.pop("INTEGRITE_CLE", None)
        try:
            with self.assertRaises(ErreurIntegrite):
                integrite.charger_cle()
        finally:
            if ancien is not None:
                os.environ["INTEGRITE_CLE"] = ancien

    def test_cle_trop_courte_refusee(self):
        with self.assertRaises(ErreurIntegrite):
            integrite.charger_cle("court")

    def test_cle_lue_depuis_environnement(self):
        os.environ["INTEGRITE_CLE"] = CLE
        try:
            self.assertEqual(integrite.charger_cle(), CLE.encode())
        finally:
            del os.environ["INTEGRITE_CLE"]


class TestEmpreintes(BaseTest):
    def test_empreinte_stable(self):
        a = integrite.calculer_empreintes(self.dossier)
        b = integrite.calculer_empreintes(self.dossier)
        self.assertEqual(a, b)
        self.assertEqual(set(a), {"config.ini", "regles/detection.yml"})

    def test_un_octet_change_l_empreinte(self):
        avant = integrite.empreinte_fichier(self.dossier / "config.ini")
        (self.dossier / "config.ini").write_text("seuil=51\n")
        self.assertNotEqual(avant, integrite.empreinte_fichier(self.dossier / "config.ini"))

    def test_exclusions(self):
        (self.dossier / "__pycache__").mkdir()
        (self.dossier / "__pycache__" / "x.pyc").write_bytes(b"\x00")
        self.assertNotIn("__pycache__/x.pyc", integrite.calculer_empreintes(self.dossier))

    def test_dossier_introuvable(self):
        with self.assertRaises(ErreurIntegrite):
            integrite.calculer_empreintes(self.dossier / "absent")

    @unittest.skipUnless(hasattr(os, "symlink"), "liens symboliques non disponibles")
    def test_lien_symbolique_non_suivi(self):
        os.symlink("/etc/passwd", self.dossier / "lien")
        empreintes = integrite.calculer_empreintes(self.dossier)
        self.assertEqual(empreintes["lien"], "lien:/etc/passwd")


class TestVerification(BaseTest):
    def setUp(self):
        super().setUp()
        integrite.creer_manifeste(self.dossier, self.manifeste, cle=CLE)

    def test_dossier_intact(self):
        rapport = integrite.verifier(self.dossier, self.manifeste, cle=CLE)
        self.assertTrue(rapport.intact)
        self.assertIn("OK", rapport.resume())

    def test_fichier_modifie_detecte(self):
        (self.dossier / "config.ini").write_text("seuil=999999\n")
        rapport = integrite.verifier(self.dossier, self.manifeste, cle=CLE)
        self.assertEqual(rapport.modifies, ["config.ini"])
        self.assertFalse(rapport.intact)

    def test_fichier_ajoute_detecte(self):
        (self.dossier / "porte_derobee.py").write_text("import os\n")
        rapport = integrite.verifier(self.dossier, self.manifeste, cle=CLE)
        self.assertEqual(rapport.ajoutes, ["porte_derobee.py"])

    def test_fichier_supprime_detecte(self):
        (self.dossier / "regles" / "detection.yml").unlink()
        rapport = integrite.verifier(self.dossier, self.manifeste, cle=CLE)
        self.assertEqual(rapport.supprimes, ["regles/detection.yml"])

    def test_manifeste_falsifie_refuse(self):
        # L'intrus modifie un fichier PUIS met à jour le manifeste pour se cacher.
        (self.dossier / "config.ini").write_text("seuil=999999\n")
        donnees = json.loads(self.manifeste.read_text())
        donnees["corps"]["fichiers"]["config.ini"] = integrite.empreinte_fichier(
            self.dossier / "config.ini")
        self.manifeste.write_text(json.dumps(donnees))
        with self.assertRaises(ErreurIntegrite):
            integrite.verifier(self.dossier, self.manifeste, cle=CLE)

    def test_mauvaise_cle_refusee(self):
        with self.assertRaises(ErreurIntegrite):
            integrite.verifier(self.dossier, self.manifeste, cle="une-autre-cle-tres-longue")

    def test_manifeste_illisible(self):
        self.manifeste.write_text("pas du json")
        with self.assertRaises(ErreurIntegrite):
            integrite.verifier(self.dossier, self.manifeste, cle=CLE)


class TestJournal(BaseTest):
    def setUp(self):
        super().setUp()
        self.j = Journal(self.journal, cle=CLE)
        for i in range(5):
            self.j.ajouter("evenement", {"i": i})

    def _lignes(self):
        return self.journal.read_text().splitlines()

    def _ecrire(self, lignes):
        self.journal.write_text("\n".join(lignes) + "\n")

    def test_journal_sain(self):
        self.assertEqual(self.j.verifier(), [])

    def test_entree_modifiee_detectee(self):
        lignes = self._lignes()
        entree = json.loads(lignes[2])
        entree["details"] = {"i": "effacé"}
        lignes[2] = json.dumps(entree)
        self._ecrire(lignes)
        self.assertTrue(any("signature invalide" in p for p in self.j.verifier()))

    def test_entree_supprimee_detectee(self):
        lignes = self._lignes()
        del lignes[1]
        self._ecrire(lignes)
        self.assertNotEqual(self.j.verifier(), [])

    def test_entrees_inversees_detectees(self):
        lignes = self._lignes()
        lignes[1], lignes[2] = lignes[2], lignes[1]
        self._ecrire(lignes)
        self.assertNotEqual(self.j.verifier(), [])

    def test_troncature_detectee_avec_repere_externe(self):
        repere = json.loads(self._lignes()[-1])
        self._ecrire(self._lignes()[:-2])
        self.assertEqual(self.j.verifier(), [])  # limite connue sans repère
        problemes = self.j.verifier(dernier_numero_attendu=repere["n"])
        self.assertTrue(any("tronqué" in p for p in problemes))

    def test_entree_forgee_sans_cle_detectee(self):
        faux = Journal(self.journal, cle="cle-du-pirate-assez-longue")
        faux.ajouter("tout_va_bien")
        self.assertTrue(any("signature invalide" in p for p in self.j.verifier()))


class TestLigneDeCommande(BaseTest):
    def setUp(self):
        super().setUp()
        os.environ["INTEGRITE_CLE"] = CLE

    def tearDown(self):
        del os.environ["INTEGRITE_CLE"]
        super().tearDown()

    def _lancer(self, *args):
        sortie, erreur = io.StringIO(), io.StringIO()
        with redirect_stdout(sortie), redirect_stderr(erreur):
            code = integrite.main([str(a) for a in args])
        return code, sortie.getvalue(), erreur.getvalue()

    def test_cycle_complet(self):
        code, sortie, _ = self._lancer("init", self.dossier, self.manifeste)
        self.assertEqual(code, 0)
        self.assertIn("2 fichiers", sortie)

        code, _, _ = self._lancer("verifier", self.dossier, self.manifeste,
                                  "--journal", self.journal)
        self.assertEqual(code, 0)

        (self.dossier / "config.ini").write_text("pirate\n")
        code, sortie, _ = self._lancer("verifier", self.dossier, self.manifeste,
                                       "--journal", self.journal)
        self.assertEqual(code, 1)
        self.assertIn("ALERTE", sortie)

        j = Journal(self.journal)
        self.assertEqual(j.verifier(), [])
        evenements = [json.loads(l)["evenement"] for l in self.journal.read_text().splitlines()]
        self.assertEqual(evenements, ["verification_ok", "alerte_integrite"])

    def test_manifeste_falsifie_code_2(self):
        self._lancer("init", self.dossier, self.manifeste)
        self.manifeste.write_text(self.manifeste.read_text().replace("seuil", "x"))
        data = json.loads(self.manifeste.read_text())
        data["corps"]["fichiers"]["config.ini"] = "0" * 64
        self.manifeste.write_text(json.dumps(data))
        code, _, erreur = self._lancer("verifier", self.dossier, self.manifeste)
        self.assertEqual(code, 2)
        self.assertIn("Signature", erreur)


if __name__ == "__main__":
    unittest.main()
