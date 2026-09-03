#!/usr/bin/env python3
"""Repasse, triage et KPI du balayage de secrets.

POURQUOI CET OUTIL EXISTE
-------------------------
Le job rendait un seul nombre : le compte de trouvailles. Un nombre qui
vaut zero ne dit pas si le balayeur a regarde ; un nombre non nul ne dit
pas si ce sont des secrets ou du bruit. CCO demande une repasse, un
triage, et des KPI sur les faux positifs et leur taux.

CE QU'IL MESURE, ET POURQUOI CES TROIS-LA
-----------------------------------------
    brut       ce que le balayeur trouve SANS la configuration d'exclusion
    residuel   ce qu'il reste APRES exclusions et annotations en ligne
    faux positifs = brut - residuel, et leur TAUX = FP / brut

Le `brut` est indispensable : sans lui, un taux de faux positifs se
calculerait sur un denominateur qu'on ne connait pas, et une exclusion
trop large deviendrait invisible. C'est le meme motif que le complement
d'un filtre - on juge une exclusion sur ce qu'elle laisse passer ET sur
ce qu'elle retire.

POURQUOI LE KPI SE COMPARE AU LIEU DE S'ECRIRE
----------------------------------------------
Le workflow declare `permissions: contents: read` et ne publie rien.
Un job qui ecrirait ses KPI dans le depot demanderait le droit
d'ecriture, c'est-a-dire exactement ce que la chaine de garde s'interdit.
La reference est donc VERSIONNEE et l'outil VERIFIE : un ecart fait
echouer, et corriger l'ecart est un commit humain, relu.

Consequence voulue : une exclusion ajoutee en douce fait tomber le taux
de faux positifs, l'ecart avec la reference leve, et le changement se
voit en relecture au lieu de passer.

LE CONTROLE ACTIF
-----------------
`--controle-actif` plante deux temoins - une fausse clef AWS et un faux
jeton GitHub - et exige que le balayeur les trouve TOUS LES DEUX, l'un
par motif et l'autre par entropie. Un balayage qui rend zero sur un
arbre propre ne prouve rien tant qu'on n'a pas montre qu'il sait rendre
autre chose. Il est joue AVANT la mesure : sans lui, pas de KPI.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile

REFERENCE = ".github/kpi-secrets.json"

# Deux temoins de familles DIFFERENTES. Un seul ne prouverait qu'une
# moitie : la clef AWS est attrapee par un detecteur de MOTIF, le jeton
# par l'heuristique d'ENTROPIE. Si l'un des deux manque, la
# configuration a aveugle une des deux voies.
# LES TEMOINS SE COMPOSENT, ILS NE S'ECRIVENT PAS EN CLAIR. Ecrits en
# litteral, ils sont trouves par le balayage DANS CE FICHIER : l'outil
# polluait la mesure qu'il produit. Mesure du defaut avant correction :
# residuel 3 au lieu de 0, et un `amazon.aws-api-key` fantome dans le
# brut. Une annotation `nosecret` aurait masque le symptome ; composer
# les chaines supprime la cause, et le fichier ne porte plus aucune
# suite de caracteres qui ressemble a un secret.
# Les deux fragments restent SEPARES jusqu'a l'execution : un balayeur
# qui lit ce fichier ne voit que deux chaines courtes, dont aucune n'a
# la forme d'un identifiant. C'est la meme raison qui interdisait le
# `%` d'origine d'etre remplace par un litteral complet.
_TEMOIN_MOTIF = "AKIA" + "IOSFODNN7EXAMPLE"
_TEMOIN_ENTROPIE = "ghp_" + "".join(
    random.Random(1337).choices(
        # `string` plutot que l'alphabet en clair : ecrit en litteral,
        # il est LUI-MEME a haute entropie et se faisait trouver ici.
        # Meme defaut que dans `tools/registres.py`, meme remede : on
        # supprime la chaine au lieu de l'annoter.
        string.ascii_letters + string.digits, k=36))

TEMOINS = {
    "_temoin_motif.py": f'AWS_KEY = "{_TEMOIN_MOTIF}"\n',
    "_temoin_entropie.py": f'TOK = "{_TEMOIN_ENTROPIE}"\n',
}


def balayer(racine: str, config: str | None) -> list:
    """Rend la liste des trouvailles. LEVE si l'outil ne rend rien.

    trufflehog3 sort 2 quand il TROUVE quelque chose et 0 quand il ne
    trouve rien : son code de retour ne distingue donc pas le succes de
    la panne. C'est le fichier de sortie qui fait foi, et son absence
    est une PANNE, pas un resultat vide.
    """
    sortie = os.path.join(tempfile.mkdtemp(), "th.json")
    cmd = ["trufflehog3", "--no-history", "--format", "json", "--output", sortie]
    if config:
        cmd += ["-c", config]
    else:
        # `--config /dev/null` ne desactive pas la decouverte automatique
        # de `.trufflehog3.yml` ; on balaye donc une COPIE de l'arbre
        # dont le fichier de configuration a ete retire.
        pass
    cmd.append(racine)
    # `check=False` EXPLICITE : trufflehog3 sort 2 quand il TROUVE
    # quelque chose et 0 quand il ne trouve rien. Son code de retour
    # ne distingue pas le succes de la panne, donc on ne s'en sert
    # pas ; c'est le fichier de sortie qui fait foi, et son absence
    # est traitee juste en dessous.
    subprocess.run(cmd, capture_output=True, text=True, check=False)
    if not os.path.exists(sortie):
        raise SystemExit("ARRET: trufflehog3 n'a produit aucun fichier de sortie")
    with open(sortie, encoding="utf-8") as f:
        return json.load(f)


def arbre_suivi(racine: str, sans_config: bool = False) -> str:
    """Copie les fichiers SUIVIS PAR GIT dans un arbre neuf.

    POURQUOI PAS L'ARBRE DE TRAVAIL. Un artefact local non suivi change
    le KPI sans changer le depot. Paye en ecrivant cet outil : un
    `.ruff_cache/CACHEDIR.TAG`, cree par une execution de ruff en local,
    ajoutait une trouvaille residuelle que la CI n'aurait jamais vue.
    L'instrument mesurait son propre environnement.

    `git ls-files` rend exactement ce que la CI recupere au checkout, ni
    plus ni moins : la mesure locale et la mesure en CI sont alors la
    MEME mesure, par construction et non par discipline.

    On copie plutot que de deplacer : modifier l'arbre pendant qu'on le
    mesure est interdit par le chapitre 12.
    """
    # `check=False` : le code de retour est lu explicitement a la
    # ligne suivante, avec un message qui nomme le depot en cause.
    out = subprocess.run(["git", "-C", racine, "ls-files", "-z"],
                         capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise SystemExit(f"ARRET: git ls-files a echoue dans {racine}")
    fichiers = [f for f in out.stdout.split("\0") if f]
    if not fichiers:
        raise SystemExit("ARRET: git ls-files rend zero fichier - "
                         "un depot vide n'est pas un depot propre")
    cible = os.path.join(tempfile.mkdtemp(), "arbre")
    for rel in fichiers:
        if sans_config and rel == ".trufflehog3.yml":
            continue
        src = os.path.join(racine, rel)
        if not os.path.exists(src):          # supprime mais encore indexe
            continue
        if os.path.isdir(src):
            # Un lien de sous-module figure dans `git ls-files` comme une
            # entree unique alors que c'est un REPERTOIRE. Son contenu
            # appartient a l'autre depot et s'y balaye ; le copier ici
            # compterait ses trouvailles dans nos KPI.
            continue
        dst = os.path.join(cible, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
    return cible


def controle_actif(racine: str) -> None:
    """Prouve que le balayeur sait rendre AUTRE CHOSE que zero.

    Les temoins sont poses dans une COPIE, jamais dans l'arbre reel :
    un temoin oublie dans le depot serait un faux secret commite.
    """
    cible = arbre_suivi(racine)
    zone = os.path.join(cible, "tools")
    os.makedirs(zone, exist_ok=True)
    for nom, contenu in TEMOINS.items():
        with open(os.path.join(zone, nom), "w", encoding="utf-8") as f:
            f.write(contenu)

    cfg = os.path.join(cible, ".trufflehog3.yml")
    trouve = balayer(cible, cfg if os.path.exists(cfg) else None)
    regles = {t.get("rule", {}).get("id") for t in trouve}

    manquants = []
    if not any(r and r != "high-entropy" for r in regles):
        manquants.append("aucun detecteur de MOTIF ne s'est declenche")
    if "high-entropy" not in regles:
        manquants.append("la regle high-entropy ne s'est pas declenchee")
    if manquants:
        raise SystemExit(
            "ARRET: controle actif en echec - " + " ; ".join(manquants)
            + "\n       la configuration a aveugle le balayeur, ses KPI ne"
              " valent rien.")
    print("controle actif : les deux voies se declenchent (motif + entropie)")


def mesurer(racine: str) -> dict:
    brut = balayer(arbre_suivi(racine, sans_config=True), None)
    suivi = arbre_suivi(racine)
    cfg = os.path.join(suivi, ".trufflehog3.yml")
    res = balayer(suivi, cfg if os.path.exists(cfg) else None)
    n_brut, n_res = len(brut), len(res)
    fp = n_brut - n_res
    par_regle: dict = {}
    for t in brut:
        rid = t.get("rule", {}).get("id", "?")
        par_regle[rid] = par_regle.get(rid, 0) + 1
    return {
        "brut": n_brut,
        "residuel": n_res,
        "faux_positifs": fp,
        "taux_faux_positifs": round(fp / n_brut, 4) if n_brut else 0.0,
        "par_regle": dict(sorted(par_regle.items())),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--racine", default=".")
    p.add_argument("--ecrire", action="store_true",
                   help="ecrit la reference au lieu de la verifier")
    a = p.parse_args()

    # LE CONTROLE ACTIF OUVRE LE DROIT DE MESURER. Il n'y a rien a
    # penser a verifier : il leve, donc la suite n'est pas atteinte.
    controle_actif(a.racine)
    m = mesurer(a.racine)

    print(f'brut {m["brut"]}  residuel {m["residuel"]}  '
          f'faux positifs {m["faux_positifs"]}  '
          f'taux {100 * m["taux_faux_positifs"]:.1f} %')
    for r, n in m["par_regle"].items():
        print(f"   {n:5d}  {r}")

    chemin = os.path.join(a.racine, REFERENCE)
    if a.ecrire:
        with open(chemin, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"reference ecrite : {REFERENCE}")
        return 0

    # LE RESIDUEL EST UN INVARIANT, PAS UNE VALEUR ENREGISTREE.
    #
    # Sans cette garde, l'outil accepte n'importe quel residuel du moment
    # qu'il correspond a la reference : un vrai secret commite aujourd'hui
    # et inscrit dans la reference demain passerait pour toujours, et le
    # job serait vert en le portant. Le defaut a ete trouve en deployant,
    # sur un residuel de 6 qui n'a leve nulle part.
    #
    # Une trouvaille residuelle se traite de deux facons et pas d'une
    # troisieme : c'est un secret, on le retire et on le REVOQUE ; ou
    # c'est un faux positif, et on ecrit l'exclusion QUI DIT POURQUOI.
    # L'enregistrer telle quelle n'est ni l'un ni l'autre.
    if m["residuel"] > 0:
        print(f'ARRET: {m["residuel"]} trouvaille(s) NON EXCLUE(S).')
        print("  Un residuel non nul ne s'enregistre pas. Soit c'est un")
        print("  secret - le retirer et le REVOQUER, le retrait seul ne")
        print("  suffit pas, il reste dans l'historique - soit c'est un")
        print("  faux positif, et l'exclusion doit dire pourquoi.")
        return 1

    if not os.path.exists(chemin):
        print(f"ARRET: {REFERENCE} absent. Le produire avec --ecrire"
              " et le RELIRE avant de le commiter.")
        return 1
    with open(chemin, encoding="utf-8") as f:
        ref = json.load(f)
    if ref != m:
        print("ARRET: les KPI ont change depuis la reference.")
        print(f'  reference : brut {ref.get("brut")} '
              f'residuel {ref.get("residuel")} '
              f'FP {ref.get("faux_positifs")} '
              f'taux {ref.get("taux_faux_positifs")}')
        print(f'  mesure    : brut {m["brut"]} '
              f'residuel {m["residuel"]} '
              f'FP {m["faux_positifs"]} '
              f'taux {m["taux_faux_positifs"]}')
        print("  Un residuel qui MONTE est un secret potentiel.")
        print("  Un taux de FP qui monte est une exclusion trop large.")
        print("  Regenerer avec --ecrire, RELIRE le diff, puis commiter.")
        return 1
    print("KPI conformes a la reference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
