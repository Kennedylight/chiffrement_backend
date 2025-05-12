from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os
import time
from pyfiglet import Figlet

def clear_screen():
    """Efface l'écran de la console"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Affiche le titre avec FIGlet"""
    clear_screen()
    f = Figlet(font='slant')
    title = "CHIFFREMENT AES 128/192/256 - TEXTE & FICHIERS"
    
    # Centrer le titre
    terminal_width = os.get_terminal_size().columns
    for line in f.renderText(title).splitlines():
        print(line.center(terminal_width))
    print("")

def generate_key(password, key_size, salt=None):
    """Génère une clé AES à partir d'un mot de passe"""
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=key_size//8, count=100000)
    return key, salt

def aes_encrypt_text(plaintext, key, key_size):
    """Chiffre un texte avec AES-CBC"""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt_text(ciphertext, key):
    """Déchiffre un texte chiffré avec AES-CBC"""
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def aes_encrypt_file(file_path, key, key_size):
    """Chiffre un fichier avec AES-CBC"""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # Si la taille n'est pas multiple de 16, on pad
    if len(plaintext) % AES.block_size != 0:
        plaintext = pad(plaintext, AES.block_size)
    
    ciphertext = cipher.encrypt(plaintext)
    
    # Sauvegarde du fichier chiffré
    encrypted_file_path = file_path + '.aes'
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    return encrypted_file_path

def aes_decrypt_file(encrypted_file_path, key):
    """Déchiffre un fichier chiffré avec AES-CBC"""
    with open(encrypted_file_path, 'rb') as f:
        data = f.read()
    
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Sauvegarde du fichier déchiffré
    if encrypted_file_path.endswith('.aes'):
        decrypted_file_path = encrypted_file_path[:-4]  # Retire .aes
    else:
        decrypted_file_path = encrypted_file_path + '.clair'
    
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)
    
    return decrypted_file_path

def matrix_operations_demo():
    """Affiche les explications des opérations matricielles AES"""
    operations = [
        ("SubBytes", "Substitution non-linéaire des octets"),
        ("ShiftRows", "Décalage des lignes de la matrice d'état"),
        ("MixColumns", "Mélange des colonnes avec multiplication matricielle"),
        ("AddRoundKey", "Application de la sous-clé de tour par XOR")
    ]
    
    print("\nFonctions matricielles AES:")
    for i, (name, desc) in enumerate(operations, 1):
        print(f"{i}. {name}: {desc}")

def performance_test(key_sizes):
    """Test de performance pour différentes tailles de clé"""
    test_data = "Test de performance " * 1000  # Données plus volumineuses
    
    print("\nTest de performance (100 itérations):")
    print(f"Taille des données: {len(test_data)} octets\n")
    
    results = []
    for size in key_sizes:
        password = f"password_{size}".encode('utf-8')
        key, _ = generate_key(password, size)
        
        # Test chiffrement
        start = time.time()
        for _ in range(100):
            aes_encrypt_text(test_data, key, size)
        encrypt_time = time.time() - start
        
        # Test déchiffrement
        ciphertext = aes_encrypt_text(test_data, key, size)
        start = time.time()
        for _ in range(100):
            aes_decrypt_text(ciphertext, key)
        decrypt_time = time.time() - start
        
        results.append((size, encrypt_time, decrypt_time))
        print(f"{size} bits - Chiffrement: {encrypt_time:.4f}s | Déchiffrement: {decrypt_time:.4f}s")

def get_file_type(file_path):
    """Détecte le type de fichier"""
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
        return 'image'
    elif file_path.lower().endswith('.pdf'):
        return 'pdf'
    else:
        return 'autre'

def handle_encryption():
    """Gère le processus de chiffrement"""
    print("\nChoisissez le type de donnée à chiffrer:")
    print("1. Texte")
    print("2. Fichier (image/PDF)")
    
    choice = input("Votre choix (1-2): ")
    
    if choice == '1':
        # Chiffrement de texte
        plaintext = input("Entrez le texte à chiffrer: ")
        password = input("Entrez le mot de passe: ").encode('utf-8')
        key_size = int(input("Taille de clé (128, 192, 256): "))
        
        if key_size not in (128, 192, 256):
            print("Taille invalide. Utilisation de 256 bits.")
            key_size = 256
        
        key, salt = generate_key(password, key_size)
        encrypted = aes_encrypt_text(plaintext, key, key_size)
        
        print("\nRésultat du chiffrement:")
        print(f"Clé (hex): {key.hex()}")
        print(f"Sel (hex): {salt.hex()}")
        print(f"Texte chiffré (base64): {base64.b64encode(encrypted).decode('utf-8')}")
    
    elif choice == '2':
        # Chiffrement de fichier
        file_path = input("Entrez le chemin du fichier à chiffrer: ")
        if not os.path.exists(file_path):
            print("Le Fichier est introuvable!")
            return
        
        file_type = get_file_type(file_path)
        if file_type not in ('image', 'pdf'):
            print("Type de fichier non supporté. Seules les images et PDF sont acceptés.")
            return
        
        password = input("Entrez le mot de passe: ").encode('utf-8')
        key_size = int(input("Taille de clé (128, 192, 256): "))
        
        if key_size not in (128, 192, 256):
            print("Taille invalide. Utilisation de 256 bits.")
            key_size = 256
        
        key, salt = generate_key(password, key_size)
        encrypted_file = aes_encrypt_file(file_path, key, key_size)
        
        print("\nRésultat du chiffrement:")
        print(f"Clé (hex): {key.hex()}")
        print(f"Sel (hex): {salt.hex()}")
        print(f"Fichier chiffré sauvegardé sous: {encrypted_file}")
    
    else:
        print("Option invalide!")

def handle_decryption():
    """Gère le processus de déchiffrement"""
    print("\nChoisissez le type de donnée à déchiffrer:")
    print("1. Texte (base64)")
    print("2. Fichier (.enc)")
    
    choice = input("Votre choix (1-2): ")
    
    if choice == '1':
        # Déchiffrement de texte
        ciphertext_b64 = input("Entrez le texte chiffré (base64): ")
        password = input("Entrez le mot de passe: ").encode('utf-8')
        salt_hex = input("Entrez le sel (hex): ")
        key_size = int(input("Taille de clé utilisée (128, 192, 256): "))
        
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            salt = bytes.fromhex(salt_hex)
            key, _ = generate_key(password, key_size, salt)
            
            decrypted = aes_decrypt_text(ciphertext, key)
            print("\nTexte déchiffré:", decrypted)
        except Exception as e:
            print(f"Erreur: {str(e)}")
    
    elif choice == '2':
        # Déchiffrement de fichier
        encrypted_file = input("Entrez le chemin du fichier chiffré: ")
        if not os.path.exists(encrypted_file):
            print("Fichier introuvable!")
            return
        
        password = input("Entrez le mot de passe: ").encode('utf-8')
        salt_hex = input("Entrez le sel (hex): ")
        key_size = int(input("Taille de clé utilisée (128, 192, 256): "))
        
        try:
            salt = bytes.fromhex(salt_hex)
            key, _ = generate_key(password, key_size, salt)
            
            decrypted_file = aes_decrypt_file(encrypted_file, key)
            print(f"\nFichier déchiffré sauvegardé sous: {decrypted_file}")
        except Exception as e:
            print(f"Erreur: {str(e)}")
    
    else:
        print("Option invalide!")

def main():
    display_banner()
    
    while True:
        print("\nMENU PRINCIPAL:")
        print("1. Chiffrer des données")
        print("2. Déchiffrer des données")
        print("3. Fonctions matricielles AES")
        print("4. Test de performance")
        print("5. Quitter")
        
        choice = input("\nVotre choix (1-5): ")
        
        if choice == '1':
            handle_encryption()
        elif choice == '2':
            handle_decryption()
        elif choice == '3':
            matrix_operations_demo()
        elif choice == '4':
            performance_test([128, 192, 256])
        elif choice == '5':
            print("\nMerci d'avoir utilisé notre système de chiffrement AES!")
            break
        else:
            print("Option invalide. Veuillez choisir entre 1 et 5.")
        
        input("\nAppuyez sur Entrée pour continuer...")
        display_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOpération annulée par l'utilisateur.")
    except Exception as e:
        print(f"\nErreur: {str(e)}")