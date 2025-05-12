import string
import secrets
import logging
import re
import os
import json
from pathlib import Path
from typing import Dict, Any

# Create data directory if it doesn't exist
data_dir = Path("data")
data_dir.mkdir(exist_ok=True)

# Path to common passwords file
COMMON_PASSWORDS_FILE = data_dir / "common_passwords.txt"

# Create an empty common passwords file if it doesn't exist
if not COMMON_PASSWORDS_FILE.exists():
    with open(COMMON_PASSWORDS_FILE, "w") as f:
        f.write("password\n123456\nadmin\nqwerty\n12345678\n")

# Список распространенных паролей для проверки
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "admin", "welcome",
    "letmein", "monkey", "dragon", "baseball", "football",
    "superman", "trustno1", "butterfly", "shadow", "master",
    "hello123", "freedom", "whatever", "qazwsx", "michael",
    "football", "jennifer", "hunter", "joshua", "maggie",
    "mustang", "sunshine", "welcome", "password1", "abc123"
]

def get_common_passwords():
    """Load common passwords from file."""
    try:
        with open(COMMON_PASSWORDS_FILE, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        logging.warning(f"Common passwords file not found: {COMMON_PASSWORDS_FILE}")
        return set()

def generate_password(length: int = 12, **options: bool) -> str:
    """
    Генерирует безопасный пароль заданной длины с указанными опциями.
    
    Args:
        length (int): Длина пароля (по умолчанию 12)
        **options: Опции для генерации пароля:
            - uppercase: Включить заглавные буквы
            - lowercase: Включить строчные буквы
            - digits: Включить цифры
            - symbols: Включить специальные символы
    
    Returns:
        str: Сгенерированный пароль
    
    Raises:
        ValueError: Если указаны недопустимые параметры
    """
    # Проверка минимальной длины
    if length < 8:
        raise ValueError("Длина пароля должна быть не менее 8 символов")
    
    # Настройка символов для генерации
    chars = ""
    if options.get('uppercase', True):
        chars += string.ascii_uppercase
    if options.get('lowercase', True):
        chars += string.ascii_lowercase
    if options.get('digits', True):
        chars += string.digits
    if options.get('symbols', True):
        chars += string.punctuation
    
    if not chars:
        raise ValueError("Должен быть выбран хотя бы один тип символов")
    
    # Генерация пароля
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        if check_password_complexity(password, options):
            if password.lower() not in COMMON_PASSWORDS:
                return password

def check_password_complexity(password: str, options: Dict[str, bool]) -> bool:
    """
    Проверяет сложность пароля.
    
    Args:
        password (str): Пароль для проверки
        options (Dict[str, bool]): Опции генерации пароля
    
    Returns:
        bool: True если пароль соответствует требованиям сложности
    """
    # Проверка длины
    if len(password) < 8:
        return False
    
    # Проверка наличия требуемых типов символов
    if options.get('uppercase', True) and not any(c.isupper() for c in password):
        return False
    if options.get('lowercase', True) and not any(c.islower() for c in password):
        return False
    if options.get('digits', True) and not any(c.isdigit() for c in password):
        return False
    if options.get('symbols', True) and not any(c in string.punctuation for c in password):
        return False
    
    # Проверка на повторяющиеся символы
    if re.search(r'(.)\1{2,}', password):
        return False
    
    # Проверка на последовательности
    sequences = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        'qwertyuiopasdfghjklzxcvbnm',
        'QWERTYUIOPASDFGHJKLZXCVBNM',
        '1234567890'
    ]
    
    for seq in sequences:
        if any(seq[i:i+3] in password.lower() for i in range(len(seq)-2)):
            return False
    
    return True

def is_common_password(password: str) -> bool:
    """
    Проверяет, является ли пароль распространенным.
    
    Args:
        password (str): Пароль для проверки
    
    Returns:
        bool: True если пароль является распространенным
    """
    return password.lower() in COMMON_PASSWORDS

def add_common_password(password):
    """
    Add a password to the common passwords list.
    
    Args:
        password (str): The password to add
    """
    if not password.strip():
        return
    
    with open(COMMON_PASSWORDS_FILE, "a") as f:
        f.write(f"{password}\n")
    
    logging.info(f"Added password to common passwords list")

def load_custom_dictionary(file_path):
    """
    Load a custom dictionary of passwords.
    
    Args:
        file_path (str): Path to the dictionary file
        
    Returns:
        set: Set of passwords from the dictionary
    """
    try:
        with open(file_path, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        logging.error(f"Dictionary file not found: {file_path}")
        return set()
    except Exception as e:
        logging.error(f"Error loading dictionary: {str(e)}")
        return set()

if __name__ == "__main__":
    # Example usage
    password = generate_password(16)
    print(f"Generated password: {password}") 