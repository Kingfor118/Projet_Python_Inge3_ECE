"""Point d'entrée du programme.

Affiche un petit menu pour choisir quoi analyser, puis lance le pipeline
défini dans main.py avec les fichiers choisis.
"""
# sur certains mac et linux tkinter est pas installe avec python
# donc on essaye de l'importer, et si ca marche pas on retient juste qu'il est pas la
try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_DISPONIBLE = True
except ImportError:
    TKINTER_DISPONIBLE = False

from main import lancer_pipeline
from src.generation_logs import generer_fichier_exemple

BLACKLIST_PAR_DEFAUT = "demo_data/blacklist.txt"


def choisir_fichiers_existants():
    """Ouvre l'explorateur Windows et renvoie la liste des fichiers choisis."""
    # On crée une fenêtre tkinter puis on la cache tout de suite :
    # on ne veut que la boîte de dialogue, pas une fenêtre vide en plus.
    fenetre = tk.Tk()
    fenetre.withdraw()

    fichiers = filedialog.askopenfilenames(
        title="Choisir un ou plusieurs fichiers de log",
        initialdir="demo_data",
        filetypes=[("Fichiers de log", "*.log *.txt"), ("Tous les fichiers", "*.*")]
    )

    fenetre.destroy()

    return list(fichiers)


# marche partout (windows, mac, linux) car on utilise juste input()
def taper_chemins_fichiers():
    print("Tape le chemin des fichiers de log, separes par une virgule")
    print("exemple : demo_data/auth.log, demo_data/server.log")
    texte = input("Fichiers : ")

    # on coupe le texte a chaque virgule et on enleve les espaces autour
    fichiers = []
    for morceau in texte.split(","):
        chemin = morceau.strip()
        if chemin != "":
            fichiers.append(chemin)

    return fichiers


def afficher_menu():
    print("=== Analyseur de logs ===")
    print("1. Choisir un ou plusieurs fichiers de log existants (explorateur)")
    print("2. Taper le chemin des fichiers de log")
    print("3. Générer un exemple de log et l'utiliser")
    print("4. Quitter")


def main():
    afficher_menu()
    choix = input("Ton choix : ").strip()

    if choix == "1":
        # si tkinter est pas installe on peut pas ouvrir l'explorateur,
        # alors on demande de taper les chemins a la place
        if TKINTER_DISPONIBLE:
            fichiers_logs = choisir_fichiers_existants()
        else:
            print("L'explorateur n'est pas disponible sur cet ordinateur (tkinter manquant).")
            fichiers_logs = taper_chemins_fichiers()

        if not fichiers_logs:
            print("Aucun fichier sélectionné, on arrête ici.")
            return

    elif choix == "2":
        fichiers_logs = taper_chemins_fichiers()

        if not fichiers_logs:
            print("Aucun fichier sélectionné, on arrête ici.")
            return

    elif choix == "3":
        fichier_genere = generer_fichier_exemple()
        print(f"Fichier d'exemple généré : {fichier_genere}")
        fichiers_logs = [fichier_genere]

    elif choix == "4":
        print("À bientôt !")
        return

    else:
        print("Choix invalide, on arrête ici.")
        return

    lancer_pipeline(fichiers_logs, BLACKLIST_PAR_DEFAUT)


if __name__ == "__main__":
    main()
