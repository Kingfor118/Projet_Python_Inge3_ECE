"""Point d'entrée du programme.

Affiche un petit menu pour choisir quoi analyser, puis lance le pipeline
défini dans main.py avec les fichiers choisis.
"""
import tkinter as tk
from tkinter import filedialog

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


def afficher_menu():
    print("=== Analyseur de logs ===")
    print("1. Choisir un ou plusieurs fichiers de log existants")
    print("2. Générer un exemple de log et l'utiliser")
    print("3. Quitter")


def main():
    afficher_menu()
    choix = input("Ton choix : ").strip()

    if choix == "1":
        fichiers_logs = choisir_fichiers_existants()

        if not fichiers_logs:
            print("Aucun fichier sélectionné, on arrête ici.")
            return

    elif choix == "2":
        fichier_genere = generer_fichier_exemple()
        print(f"Fichier d'exemple généré : {fichier_genere}")
        fichiers_logs = [fichier_genere]

    elif choix == "3":
        print("À bientôt !")
        return

    else:
        print("Choix invalide, on arrête ici.")
        return

    lancer_pipeline(fichiers_logs, BLACKLIST_PAR_DEFAUT)


if __name__ == "__main__":
    main()
