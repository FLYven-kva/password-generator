import os
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from typing import Optional

def derive_key(password, salt=None):
    """
    Derive an encryption key from a password.
    
    Args:
        password (str): Password for encryption/decryption
        salt (bytes, optional): Salt for key derivation
        
    Returns:
        tuple: (key, salt) - The encryption key and salt used
    """
    if salt is None:
        salt = os.urandom(16)
    
    password_bytes = password.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key, salt

def encrypt_file(source_path, target_path, password):
    """
    Encrypt a file with a password.
    
    Args:
        source_path (str): Path to the file to encrypt
        target_path (str): Path where to save the encrypted file
        password (str): Password for encryption
        
    Returns:
        bool: True if encryption was successful
    """
    try:
        # Generate encryption key from password
        key, salt = derive_key(password)
        
        # Create a Fernet cipher with the key
        cipher = Fernet(key)
        
        # Read the file content
        with open(source_path, 'rb') as f:
            data = f.read()
        
        # Encrypt the data
        encrypted_data = cipher.encrypt(data)
        
        # Save the salt and encrypted data
        with open(target_path, 'wb') as f:
            f.write(salt)  # First 16 bytes will be the salt
            f.write(encrypted_data)
        
        logging.info(f"File encrypted: {source_path} -> {target_path}")
        return True
    
    except Exception as e:
        logging.error(f"Error encrypting file {source_path}: {str(e)}")
        return False

def decrypt_file(source_path, target_path, password):
    """
    Decrypt a file with a password.
    
    Args:
        source_path (str): Path to the encrypted file
        target_path (str): Path where to save the decrypted file
        password (str): Password for decryption
        
    Returns:
        bool: True if decryption was successful
    """
    try:
        # Read the file content
        with open(source_path, 'rb') as f:
            # First 16 bytes are the salt
            salt = f.read(16)
            encrypted_data = f.read()
        
        # Derive key with the salt
        key, _ = derive_key(password, salt)
        
        # Create a Fernet cipher with the key
        cipher = Fernet(key)
        
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Save the decrypted data
        with open(target_path, 'wb') as f:
            f.write(decrypted_data)
        
        logging.info(f"File decrypted: {source_path} -> {target_path}")
        return True
    
    except Exception as e:
        logging.error(f"Error decrypting file {source_path}: {str(e)}")
        return False

def encrypt_text(text, password):
    """
    Encrypt text with a password.
    
    Args:
        text (str): Text to encrypt
        password (str): Password for encryption
        
    Returns:
        tuple: (encrypted_text, salt) - The encrypted text and salt used
    """
    try:
        # Generate encryption key from password
        key, salt = derive_key(password)
        
        # Create a Fernet cipher with the key
        cipher = Fernet(key)
        
        # Encrypt the text
        text_bytes = text.encode('utf-8')
        encrypted_bytes = cipher.encrypt(text_bytes)
        encrypted_text = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        
        # Return the encrypted text and salt (both encoded as strings)
        salt_str = base64.urlsafe_b64encode(salt).decode('utf-8')
        return encrypted_text, salt_str
    
    except Exception as e:
        logging.error(f"Error encrypting text: {str(e)}")
        return None, None

def decrypt_text(encrypted_text, salt_str, password):
    """
    Decrypt text with a password.
    
    Args:
        encrypted_text (str): Encrypted text
        salt_str (str): Salt used for encryption (base64 encoded)
        password (str): Password for decryption
        
    Returns:
        str: Decrypted text
    """
    try:
        # Decode the salt
        salt = base64.urlsafe_b64decode(salt_str.encode('utf-8'))
        
        # Derive key with the salt
        key, _ = derive_key(password, salt)
        
        # Create a Fernet cipher with the key
        cipher = Fernet(key)
        
        # Decode and decrypt the text
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        return decrypted_text
    
    except Exception as e:
        logging.error(f"Error decrypting text: {str(e)}")
        return None

def generate_key() -> bytes:
    """
    Генерирует ключ шифрования.
    
    Returns:
        bytes: Сгенерированный ключ
    """
    return Fernet.generate_key()

def save_key(key: bytes, key_file: str = "encryption.key") -> None:
    """
    Сохраняет ключ шифрования в файл.
    
    Args:
        key (bytes): Ключ для сохранения
        key_file (str): Путь к файлу ключа
    """
    try:
        with open(key_file, "wb") as f:
            f.write(key)
        logging.info(f"Ключ шифрования сохранен в {key_file}")
    except Exception as e:
        logging.error(f"Ошибка при сохранении ключа: {str(e)}")
        raise

def load_key(key_file: str = "encryption.key") -> Optional[bytes]:
    """
    Загружает ключ шифрования из файла.
    
    Args:
        key_file (str): Путь к файлу ключа
    
    Returns:
        Optional[bytes]: Загруженный ключ или None в случае ошибки
    """
    try:
        with open(key_file, "rb") as f:
            return f.read()
    except FileNotFoundError:
        logging.warning(f"Файл ключа {key_file} не найден")
        return None
    except Exception as e:
        logging.error(f"Ошибка при загрузке ключа: {str(e)}")
        return None

def encrypt_directory(directory_path: str, key: bytes) -> bool:
    """
    Шифрует все файлы в указанной директории.
    
    Args:
        directory_path (str): Путь к директории
        key (bytes): Ключ шифрования
    
    Returns:
        bool: True если все файлы успешно зашифрованы
    """
    try:
        success = True
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not encrypt_file(file_path, file_path, key):
                    success = False
        return success
    except Exception as e:
        logging.error(f"Ошибка при шифровании директории {directory_path}: {str(e)}")
        return False

def decrypt_directory(directory_path: str, key: bytes) -> bool:
    """
    Расшифровывает все файлы в указанной директории.
    
    Args:
        directory_path (str): Путь к директории
        key (bytes): Ключ шифрования
    
    Returns:
        bool: True если все файлы успешно расшифрованы
    """
    try:
        success = True
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not decrypt_file(file_path, file_path, key):
                    success = False
        return success
    except Exception as e:
        logging.error(f"Ошибка при расшифровке директории {directory_path}: {str(e)}")
        return False

if __name__ == "__main__":
    # Example usage
    test_file = "test_passwords.txt"
    encrypted_file = "test_passwords.encrypted"
    decrypted_file = "test_passwords_decrypted.txt"
    password = "my_secure_password"
    
    # Create a test file
    with open(test_file, "w") as f:
        f.write("This is a test file with sensitive password data.\n")
        f.write("password1: MySuperSecretPassword123!\n")
        f.write("password2: AnotherComplicatedP@ssw0rd\n")
    
    # Encrypt the file
    print(f"Encrypting {test_file}...")
    success = encrypt_file(test_file, encrypted_file, password)
    print(f"Encryption {'successful' if success else 'failed'}")
    
    # Decrypt the file
    print(f"Decrypting {encrypted_file}...")
    success = decrypt_file(encrypted_file, decrypted_file, password)
    print(f"Decryption {'successful' if success else 'failed'}")
    
    # Test text encryption/decryption
    text = "This is a secret message with a password: MySecretPassword123!"
    print(f"Encrypting text...")
    encrypted, salt = encrypt_text(text, password)
    print(f"Encrypted: {encrypted[:20]}...")
    
    print(f"Decrypting text...")
    decrypted = decrypt_text(encrypted, salt, password)
    print(f"Decrypted: {decrypted}")
    
    # Clean up test files
    for file in [test_file, encrypted_file, decrypted_file]:
        if os.path.exists(file):
            os.remove(file) 