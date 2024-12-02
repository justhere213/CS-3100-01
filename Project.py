from Crypto.Cipher import DES
import base64

DES_KEY = b'DES_KEY1'

users = {}

def pad(text):
    """Pads text to make it a multiple of 8 for encryption"""
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_password(password):
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    padded_password = pad(password)
    encrypted_password = cipher.encrypt(padded_password.encode())
    return base64.b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password):
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    decoded_encrypted_password = base64.b64decode(encrypted_password)
    decrypted_password = cipher.decrypt(decoded_encrypted_password)
    return decrypted_password.decode().strip()

def create_account():
    username = input("Enter a username: ")
    if username in users:
        print("Username already exists!")
        return

    password = input("Enter a password: ")
    security_question_1 = input("What's your favorite color? ")
    security_question_2 = input("What's your first pet's name? ")

    encrypted_password = encrypt_password(password)
    users[username] = {
        "password": encrypted_password,
        "security_question_1": security_question_1,
        "security_question_2": security_question_2
    }
    print(f"Account for {username} created successfully!")

def login():
    username = input("Enter your username: ")
    if username not in users:
        print("Username not found!")
        return
    
    password = input("Enter your password: ")
    encrypted_password = users[username]["password"]
    decrypted_password = decrypt_password(encrypted_password)

    if password == decrypted_password:
        print("Login successful!")
    else:
        print("Incorrect password!")

def recover_password():
    """Password recovery using security questions"""
    username = input("Enter your username: ")
    if username not in users:
        print("Username not found!")
        return

    answer_1 = input("What's your favorite color? ")
    answer_2 = input("What's your first pet's name? ")

    if (answer_1 == users[username]["security_question_1"] and
        answer_2 == users[username]["security_question_2"]):
        print(f"Security questions passed. Your password is: {decrypt_password(users[username]['password'])}")
    else:
        print("Security questions failed. Cannot recover password.")

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