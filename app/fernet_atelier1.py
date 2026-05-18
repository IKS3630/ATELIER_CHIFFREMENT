"""
Atelier 1 : Chiffrement/Déchiffrement avec Fernet via GitHub Secret

Ce programme utilise une clé Fernet stockée dans un GitHub Secret
pour chiffrer et déchiffrer des fichiers de manière sécurisée.

Configuration du GitHub Secret :
1. Aller sur https://github.com/[owner]/[repo]/settings/secrets/actions
2. Créer un nouveau secret nommé FERNET_KEY
3. Générer une clé Fernet :
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
4. Coller la clé générée dans le secret GitHub
5. La clé sera injectée comme variable d'environnement dans GitHub Actions/Codespaces
"""

import argparse
import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


def get_fernet_key_from_secret() -> bytes:
    """
    Récupère la clé Fernet depuis le GitHub Secret (variable d'environnement FERNET_KEY).
    
    Returns:
        bytes: La clé Fernet encodée
        
    Raises:
        SystemExit: Si la clé n'est pas définie
    """
    key = os.environ.get("FERNET_KEY")
    if not key:
        raise SystemExit(
            "❌ Erreur: FERNET_KEY non défini.\n\n"
            "Pour configurer la clé Fernet depuis un GitHub Secret :\n"
            "1. Générez une clé :\n"
            "   python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
            "2. Allez sur : https://github.com/[owner]/[repo]/settings/secrets/actions\n"
            "3. Créez un secret nommé FERNET_KEY avec la clé générée\n"
            "4. La clé sera injectée comme variable d'environnement\n\n"
            "Pour tester localement :\n"
            "   export FERNET_KEY='[votre-clé-ici]'"
        )
    return key.encode()


def encrypt_file(input_path: Path, output_path: Path, fernet: Fernet) -> None:
    """
    Chiffre un fichier avec Fernet.
    
    Args:
        input_path: Chemin du fichier à chiffrer
        output_path: Chemin du fichier chiffré en sortie
        fernet: Instance Fernet initialisée avec la clé
    """
    try:
        data = input_path.read_bytes()
        encrypted_token = fernet.encrypt(data)
        output_path.write_bytes(encrypted_token)
        print(f"✅ Chiffrement réussi : {input_path} → {output_path}")
    except FileNotFoundError:
        raise SystemExit(f"❌ Fichier introuvable : {input_path}")
    except Exception as e:
        raise SystemExit(f"❌ Erreur lors du chiffrement : {e}")


def decrypt_file(input_path: Path, output_path: Path, fernet: Fernet) -> None:
    """
    Déchiffre un fichier avec Fernet.
    
    Args:
        input_path: Chemin du fichier chiffré
        output_path: Chemin du fichier déchiffré en sortie
        fernet: Instance Fernet initialisée avec la clé
        
    Raises:
        InvalidToken: Si le fichier est corrompu ou la clé est incorrecte
    """
    try:
        encrypted_data = input_path.read_bytes()
        data = fernet.decrypt(encrypted_data)
        output_path.write_bytes(data)
        print(f"✅ Déchiffrement réussi : {input_path} → {output_path}")
    except FileNotFoundError:
        raise SystemExit(f"❌ Fichier introuvable : {input_path}")
    except InvalidToken:
        raise SystemExit(
            "❌ Erreur de déchiffrement :\n"
            "- Le fichier est peut-être corrompu\n"
            "- Ou la clé FERNET_KEY utilisée est incorrecte\n"
            "- Ou le fichier n'a pas été chiffré avec cette clé"
        )
    except Exception as e:
        raise SystemExit(f"❌ Erreur lors du déchiffrement : {e}")


def main():
    """Fonction principale - Interface CLI."""
    parser = argparse.ArgumentParser(
        description="Chiffrement/Déchiffrement de fichiers avec Fernet (GitHub Secret)",
        epilog="Exemple: python fernet_atelier1.py encrypt secret.txt secret.enc"
    )
    parser.add_argument(
        "mode",
        choices=["encrypt", "decrypt"],
        help="Mode opération"
    )
    parser.add_argument(
        "input",
        help="Fichier d'entrée"
    )
    parser.add_argument(
        "output",
        help="Fichier de sortie"
    )

    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    # Récupérer la clé depuis le GitHub Secret
    try:
        key = get_fernet_key_from_secret()
        fernet = Fernet(key)
    except Exception as e:
        raise SystemExit(f"❌ Erreur d'initialisation de Fernet : {e}")

    # Exécuter l'opération demandée
    if args.mode == "encrypt":
        encrypt_file(input_path, output_path, fernet)
    else:  # decrypt
        decrypt_file(input_path, output_path, fernet)


if __name__ == "__main__":
    main()
