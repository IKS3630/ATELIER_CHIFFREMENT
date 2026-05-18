"""
Atelier 2 : Chiffrement/Déchiffrement avec SecretBox (PyNaCl) via GitHub Secret

Ce programme utilise SecretBox de PyNaCl pour un chiffrement/déchiffrement sécurisé.
La clé secrète est stockée dans un GitHub Secret.

Comparaison Fernet vs SecretBox :
- Fernet (cryptography) : AES-128-CBC + HMAC, supporte l'expiration de token
- SecretBox (PyNaCl) : XSalsa20 + Poly1305 (courbe elliptique), plus moderne, pas d'expiration

Configuration du GitHub Secret :
1. Aller sur https://github.com/[owner]/[repo]/settings/secrets/actions
2. Créer un nouveau secret nommé NACL_KEY
3. Générer une clé SecretBox :
   python -c "import nacl.utils, base64; print(base64.b64encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode())"
4. Coller la clé générée dans le secret GitHub
5. La clé sera injectée comme variable d'environnement dans GitHub Actions/Codespaces
"""

import argparse
import os
import base64
from pathlib import Path
from typing import Tuple

import nacl.utils
import nacl.secret
import nacl.exceptions


def generate_key() -> str:
    """
    Génère une nouvelle clé SecretBox et la retourne encodée en Base64.
    
    Returns:
        str: Clé Base64 encodée prête pour le GitHub Secret
    """
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    return base64.b64encode(key).decode()


def get_secretbox_from_secret() -> nacl.secret.SecretBox:
    """
    Récupère la clé SecretBox depuis le GitHub Secret (variable d'environnement NACL_KEY).
    
    Returns:
        nacl.secret.SecretBox: Instance SecretBox initialisée avec la clé
        
    Raises:
        SystemExit: Si la clé n'est pas définie ou invalide
    """
    key_b64 = os.environ.get("NACL_KEY")
    if not key_b64:
        raise SystemExit(
            "❌ Erreur: NACL_KEY non défini.\n\n"
            "Pour configurer la clé SecretBox depuis un GitHub Secret :\n"
            "1. Générez une clé :\n"
            "   python -c \"import nacl.utils, base64; "
            "print(base64.b64encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode())\"\n"
            "2. Allez sur : https://github.com/[owner]/[repo]/settings/secrets/actions\n"
            "3. Créez un secret nommé NACL_KEY avec la clé générée\n"
            "4. La clé sera injectée comme variable d'environnement\n\n"
            "Pour tester localement :\n"
            "   export NACL_KEY='[votre-clé-base64-ici]'"
        )
    
    try:
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) != nacl.secret.SecretBox.KEY_SIZE:
            raise ValueError(
                f"Clé invalide: doit faire {nacl.secret.SecretBox.KEY_SIZE} bytes "
                f"(base64 encodée), reçu {len(key_bytes)} bytes"
            )
        return nacl.secret.SecretBox(key_bytes)
    except Exception as e:
        raise SystemExit(f"❌ Erreur lors de l'initialisation de SecretBox : {e}")


def encrypt_file(input_path: Path, output_path: Path, secretbox: nacl.secret.SecretBox) -> None:
    """
    Chiffre un fichier avec SecretBox.
    
    SecretBox utilise XSalsa20 pour le chiffrement et Poly1305 pour l'authentification.
    Le format de sortie est : Nonce (24 bytes) + Ciphertext
    
    Args:
        input_path: Chemin du fichier à chiffrer
        output_path: Chemin du fichier chiffré en sortie
        secretbox: Instance SecretBox initialisée avec la clé
    """
    try:
        data = input_path.read_bytes()
        # EncryptedMessage contient automatiquement le nonce + ciphertext
        encrypted = secretbox.encrypt(data)
        # Écrire la totalité du message chiffré (nonce + ciphertext)
        output_path.write_bytes(bytes(encrypted))
        print(f"✅ Chiffrement réussi : {input_path} → {output_path}")
        print(f"   Taille originale : {len(data)} bytes")
        print(f"   Taille chiffrée : {len(bytes(encrypted))} bytes (nonce 24 bytes + ciphertext + tag)")
    except FileNotFoundError:
        raise SystemExit(f"❌ Fichier introuvable : {input_path}")
    except Exception as e:
        raise SystemExit(f"❌ Erreur lors du chiffrement : {e}")


def decrypt_file(input_path: Path, output_path: Path, secretbox: nacl.secret.SecretBox) -> None:
    """
    Déchiffre un fichier chiffré avec SecretBox.
    
    Args:
        input_path: Chemin du fichier chiffré
        output_path: Chemin du fichier déchiffré en sortie
        secretbox: Instance SecretBox initialisée avec la clé
        
    Raises:
        SystemExit: Si le déchiffrement échoue
    """
    try:
        encrypted_data = input_path.read_bytes()
        # SecretBox.decrypt() reconnaît automatiquement le format nonce + ciphertext
        data = secretbox.decrypt(encrypted_data)
        output_path.write_bytes(data)
        print(f"✅ Déchiffrement réussi : {input_path} → {output_path}")
        print(f"   Taille déchiffrée : {len(data)} bytes")
    except FileNotFoundError:
        raise SystemExit(f"❌ Fichier introuvable : {input_path}")
    except nacl.exceptions.CryptoError:
        raise SystemExit(
            "❌ Erreur de déchiffrement :\n"
            "- Le fichier est peut-être corrompu\n"
            "- Ou la clé NACL_KEY utilisée est incorrecte\n"
            "- Ou le fichier n'a pas été chiffré avec cette clé"
        )
    except Exception as e:
        raise SystemExit(f"❌ Erreur lors du déchiffrement : {e}")


def main():
    """Fonction principale - Interface CLI."""
    parser = argparse.ArgumentParser(
        description="Chiffrement/Déchiffrement de fichiers avec SecretBox (PyNaCl + GitHub Secret)",
        epilog="Exemple: python nacl_atelier2.py encrypt secret.txt secret.enc"
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

    # Récupérer la clé depuis le GitHub Secret et initialiser SecretBox
    secretbox = get_secretbox_from_secret()

    # Exécuter l'opération demandée
    if args.mode == "encrypt":
        encrypt_file(input_path, output_path, secretbox)
    else:  # decrypt
        decrypt_file(input_path, output_path, secretbox)


if __name__ == "__main__":
    main()
