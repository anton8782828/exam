
import hashlib

def sha256_hash(input_string):  # Створення об'єкта хешу
    sha256 = hashlib.sha256()  # Оновлення хешу з введеним рядком
    sha256.update(input_string.encode('utf-8'))  # Отримання геш-значення у шістнадцятковому форматі
    hex_hash = sha256.hexdigest()  # Виведення результату
    print("SHA-256:", hex_hash)  # Введення результату

# Введення рядка користувачем
message = input("Enter the message to hash: ")

sha256_hash(message)
