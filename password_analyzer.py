import re
import string
import logging
import math
from pathlib import Path
from password_generator import get_common_passwords, load_custom_dictionary, is_common_password
from typing import Dict, Any, List

def analyze_password(password: str) -> Dict[str, Any]:
    """
    Анализирует пароль и возвращает информацию о его надежности.
    
    Args:
        password (str): Пароль для анализа
    
    Returns:
        Dict[str, Any]: Словарь с результатами анализа, содержащий:
            - strength: Общая оценка надежности ("strong", "medium", "weak")
            - details: Детальная информация о пароле
    """
    details = {}
    score = 0
    
    # Проверка длины
    length = len(password)
    details["Длина"] = f"{length} символов"
    if length < 8:
        score -= 2
        details["Длина"] += " (слишком короткий)"
    elif length < 12:
        score += 1
    elif length < 16:
        score += 2
    else:
        score += 3
    
    # Проверка сложности
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':\"\\|,.<>\/?]', password))
    
    details["Сложность"] = []
    if has_uppercase:
        score += 1
        details["Сложность"].append("Заглавные буквы")
    if has_lowercase:
        score += 1
        details["Сложность"].append("Строчные буквы")
    if has_digit:
        score += 1
        details["Сложность"].append("Цифры")
    if has_symbol:
        score += 2
        details["Сложность"].append("Специальные символы")
    
    # Проверка на распространенные пароли
    if is_common_password(password):
        score -= 3
        details["Предупреждение"] = "Этот пароль находится в списке распространенных паролей"
    
    # Проверка на повторяющиеся символы
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        details["Предупреждение"] = "Пароль содержит повторяющиеся символы"
    
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
            score -= 1
            details["Предупреждение"] = "Пароль содержит последовательности символов"
            break
    
    # Определение общей оценки
    if score >= 4:
        strength = "strong"
    elif score >= 0:
        strength = "medium"
    else:
        strength = "weak"
    
    details["Оценка"] = f"{score} баллов"
    details["Сложность"] = ", ".join(details["Сложность"])
    
    return {
        "strength": strength,
        "details": details
    }

def calculate_entropy(password):
    """
    Calculate the entropy (randomness) of a password in bits.
    Higher entropy means more randomness and potentially stronger password.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        float: Entropy in bits
    """
    if not password:
        return 0
    
    # Count character classes used
    char_sets = 0
    if re.search(r'[a-z]', password):
        char_sets += 26
    if re.search(r'[A-Z]', password):
        char_sets += 26
    if re.search(r'[0-9]', password):
        char_sets += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        char_sets += 33  # Approximation for special characters
    
    # If no character class is detected, use a minimum value
    if char_sets == 0:
        char_sets = 1
    
    # Calculate entropy: log2(char_sets^length)
    return len(password) * math.log2(char_sets)

def analyze_password_file(file_path: str) -> Dict[str, Any]:
    """
    Анализирует файл с паролями и возвращает статистику.
    
    Args:
        file_path (str): Путь к файлу с паролями (по одному на строку)
    
    Returns:
        Dict[str, Any]: Словарь с результатами анализа, содержащий:
            - total: Общее количество паролей
            - strong: Количество надежных паролей
            - medium: Количество средних паролей
            - weak: Количество слабых паролей
            - details: Детальная информация по каждому паролю
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        results = {
            "total": len(passwords),
            "strong": 0,
            "medium": 0,
            "weak": 0,
            "details": {}
        }
        
        for password in passwords:
            analysis = analyze_password(password)
            results["details"][password] = analysis
            results[analysis["strength"]] += 1
        
        logging.info(f"Проанализирован файл {file_path}: {results['total']} паролей")
        return results
    
    except Exception as e:
        logging.error(f"Ошибка при анализе файла {file_path}: {str(e)}")
        raise

if __name__ == "__main__":
    # Example usage
    test_password = "Example123!"
    result = analyze_password(test_password)
    print(f"Password: {test_password}")
    print(f"Strength: {result['strength']}")
    for key, value in result['details'].items():
        print(f"{key}: {value}") 