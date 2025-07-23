# Password Manager

---

## Description

**Password Manager** est une application sécurisée développée en Python avec une interface graphique moderne utilisant `customtkinter`.  

Elle permet de stocker, générer, afficher et supprimer des mots de passe chiffrés localement avec un chiffrement AES-GCM 256 bits.  

Le mot de passe maître est utilisé directement pour protéger le coffre (vault) chiffré, garantissant que sans ce mot de passe, il est impossible d’accéder aux données. Aucune donnée sensible n’est stockée en clair sur le disque ou dans le code.  

---

## Fonctionnalités

- Création d’un mot de passe maître sécurisé au premier lancement  
- Chiffrement fort avec AES-GCM et dérivation de clé via Scrypt  
- Gestion complète des entrées : ajout, suppression, affichage masqué, copie sécurisée dans le presse-papier  
- Générateur de mots de passe robustes intégré  
- Interface claire, intuitive et fluide  
- Protection contre la réinitialisation non autorisée du mot de passe maître  
- Stockage unique et chiffré du coffre (vault) dans `data/vault.enc`

---

## Prérequis

- Python 3.8+  
- Packages Python :  
pip install cryptography customtkinter pyperclip

yaml
Toujours afficher les détails

Copier

---

## Utilisation en développement

1. Cloner ou télécharger ce projet  
2. Installer les dépendances (voir ci-dessus)  
3. Lancer l’application :  
python main.py

yaml
Toujours afficher les détails

Copier
4. Au premier lancement, définir un mot de passe maître  
5. Ajouter, supprimer ou copier des mots de passe facilement  
6. Le vault est stocké chiffré dans `data/vault.enc`

---

## Compilation en application autonome

Pour créer un exécutable (ex : `.exe` sous Windows) et distribuer l’application sans dépendre de Python installé :

1. Installer PyInstaller :  
pip install pyinstaller

bash
Toujours afficher les détails

Copier
2. Depuis le dossier du projet, lancer la compilation :  
pyinstaller --noconsole --onefile main.py

yaml
Toujours afficher les détails

Copier
3. L’exécutable sera généré dans le dossier `dist/`  
4. Copier et distribuer ce fichier directement  
5. Le dossier `data/` sera créé automatiquement au premier lancement de l’exécutable

---

## Notes de sécurité importantes

- **Le mot de passe maître est la clé unique du coffre**. Si tu le perds, tu ne pourras plus accéder à tes mots de passe.  
- La suppression ou la modification du fichier `data/vault.enc` rendra tes données irrécupérables.  
- Ne partage jamais ton mot de passe maître.  
- Le chiffrement est local, aucune donnée n’est envoyée sur un serveur.  

---

## Suggestions & Améliorations futures

- Ajout d’un mécanisme de sauvegarde automatique / export chiffré  
- Recherche rapide dans les entrées  
- Edition d’entrées existantes  
- Intégration d’un timeout de verrouillage automatique  
- Interface plus personnalisable  

---

## Licence

Apache2.0 Licence
