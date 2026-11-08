# tkinter n'est pas toujours installe sur mac et linux
try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_DISPONIBLE = True
except ImportError:
    TKINTER_DISPONIBLE = False

from main import lancer_pipeline
from src.generation_logs import generer_fichier_exemple

BLACKLIST_PAR_DEFAUT = "demo_data/blacklist.txt"


# ouvre l'explorateur de fichiers
def choisir_fichiers_existants() -> list[str]:
    fenetre = tk.Tk()
    fenetre.withdraw()  # cache la fenetre vide

    fichiers = filedialog.askopenfilenames(
        title="Choisir un ou plusieurs fichiers de log",
        initialdir="demo_data",
        filetypes=[("Fichiers de log", "*.log *.txt"), ("Tous les fichiers", "*.*")]
    )

    fenetre.destroy()

    return list(fichiers)


def taper_chemins_fichiers() -> list[str]:
    print("Tape le chemin des fichiers de log, separes par une virgule")
    print("exemple : demo_data/auth.log, demo_data/server.log")
    texte = input("Fichiers : ")

    fichiers = []
    for morceau in texte.split(","):
        chemin = morceau.strip()
        if chemin != "":
            fichiers.append(chemin)

    return fichiers


def afficher_menu() -> None:
    print("=== Analyseur de logs ===")
    print("1. Choisir un ou plusieurs fichiers de log existants (explorateur)")
    print("2. Taper le chemin des fichiers de log")
    print("3. Générer un exemple de log et l'utiliser")
    print("4. Quitter")


def main() -> None:
    afficher_menu()
    choix = input("Ton choix : ").strip()

    if choix == "1" and TKINTER_DISPONIBLE:
        fichiers_logs = choisir_fichiers_existants()
    elif choix == "1":
        print("L'explorateur n'est pas disponible (tkinter manquant).")
        fichiers_logs = taper_chemins_fichiers()
    elif choix == "2":
        fichiers_logs = taper_chemins_fichiers()
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

    if not fichiers_logs:
        print("Aucun fichier sélectionné, on arrête ici.")
        return

    lancer_pipeline(fichiers_logs, BLACKLIST_PAR_DEFAUT)


if __name__ == "__main__":
    main()
