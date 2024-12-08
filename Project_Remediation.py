from Crypto.Cipher import AES
import base64
import os
from getpass import getpass

AES_KEY = os.environ.get('AES_KEY', 'default_secure_key_1234')[:32].encode()
#AES key is 32 bytes instead of DES's 8 bytes and is created as an environment variable to make it more secure

users = {}

def pad(text):
    """Pads cipher text to be 16 bytes instead of DES's 8"""
    while len(text) % 16 != 0:
        text += ' '
    return text

def unpad(text):
    return text.rstrip(' ')

def encrypt_password(password):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_password = pad(password)
    encrypted_password = cipher.encrypt(padded_password.encode())
    return base64.b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decoded_encrypted_password = base64.b64decode(encrypted_password)
    decrypted_password = cipher.decrypt(decoded_encrypted_password)
    return unpad(decrypted_password.decode())

def create_account():
    username = input("Enter a username: ")
    if username in users:
        print("Username already exists!")
        return

    password = getpass("Enter a password: ")
    email = input("Enter your email for password recovery: ")

    encrypted_password = encrypt_password(password)
    users[username] = {
        "password": encrypted_password,
        "email": email
    }
    print(f"Account for {username} created successfully!")
    print("""To ensure your account remains secure, please follow these guidelines:
Avoid sharing passwords or recovery links with anyone.
Be cautious of phishing attempts, especially emails thatmimic legitimate communications.
Regularly update passwords to reduce the impact of compromised credentials.""")

def login():
    username = input("Enter your username: ")
    if username not in users:
        print("Username not found!")
        return
    
    password = getpass("Enter your password: ")
    encrypted_password = users[username]["password"]
    decrypted_password = decrypt_password(encrypted_password)

    if password == decrypted_password:
        print("Login successful!")
    else:
        print("Incorrect password!")

def recover_password():
    #Simulated email password recovery. Would send an email in real-world applications
    username = input("Enter your username: ")
    if username not in users:
        print("Username not found!")
        return

    email = input("Enter your recovery email: ")
    if email == users[username]["email"]:
        print(f"Recovery successful! Your password is: {decrypt_password(users[username]['password'])}")
    else:
        print("Recovery failed. Email does not match.")

def menu():
    while True:
        print("\n1. Create Account")
        print("2. Log In")
        print("3. Recover Password")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            create_account()
        elif choice == '2':
            login()
        elif choice == '3':
            recover_password()
        elif choice == '4':
            print("Exiting program...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    menu()
