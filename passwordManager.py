import json
import os
import time
import base64
import argparse
import getpass
from cryptography.fernet import Fernet

# File to store passwords
DATA_FILE = "passwords.json"
KEY_FILE = "key.key"
MASTER_PASS_FILE = "master_pass.json"
LOCKOUT_FILE = "lockout.json"
LOCKOUT_DURATION = 86400  # 24 hours in seconds

def generate_key():
    """Generate and save a new encryption key."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    """Load the encryption key from the file."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt_password(password, key):
    """Encrypt a password."""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, key):
    """Decrypt a password."""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def load_data():
    """Load password data from the JSON file."""
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as file:
        return json.load(file)

def save_data(data):
    """Save password data to the JSON file."""
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

def update_password(website, username, new_password):
    """Update an existing password entry."""
    if not verify_master_password():
        return
    key = load_key()
    data = load_data()
    if website in data:
        data[website] = {"username": username, "password": encrypt_password(new_password, key)}
        save_data(data)
        print(f"Password for {website} updated successfully!")
    else:
        print("No password found for this website.")

def setup_master_password():
    """Set up a master password and security question."""
    if os.path.exists(MASTER_PASS_FILE):
        return
    master_password = getpass.getpass("Set a master password: ")
    security_question = input("Set a security question (e.g., Your pet's name?): ")
    security_answer = getpass.getpass("Answer: ")
    key = load_key()
    encrypted_pass = encrypt_password(master_password, key)
    encrypted_answer = encrypt_password(security_answer, key)
    master_data = {"password": encrypted_pass, "security_question": security_question, "security_answer": encrypted_answer}
    with open(MASTER_PASS_FILE, "w") as file:
        json.dump(master_data, file, indent=4)
    print("Master password set successfully!")

def verify_master_password():
    """Verify the master password before granting access."""
    if check_lockout():
        return False
    if not os.path.exists(MASTER_PASS_FILE):
        setup_master_password()
    with open(MASTER_PASS_FILE, "r") as file:
        master_data = json.load(file)
    key = load_key()
    attempts = 3
    while attempts > 0:
        entered_password = getpass.getpass("Enter master password: ")
        if decrypt_password(master_data["password"], key) == entered_password:
            return True
        attempts -= 1
        print(f"Incorrect password. {attempts} attempts remaining.")
    print("Forgot password? Answer the security question.")
    print(master_data["security_question"])
    sec_attempts = 2
    while sec_attempts > 0:
        answer = getpass.getpass("Answer: ")
        if decrypt_password(master_data["security_answer"], key) == answer:
            print("Access granted. Reset your master password.")
            setup_master_password()
            return True
        sec_attempts -= 1
        print(f"Incorrect answer. {sec_attempts} attempts remaining.")
    print("Access denied. You are locked out for 24 hours.")
    set_lockout()
    return False

def main():
    setup_master_password()
    parser = argparse.ArgumentParser(description="Simple CLI Password Manager")
    parser.add_argument("action", choices=["add", "get", "update", "delete", "list"], help="Action to perform")
    parser.add_argument("--website", help="Website name")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password")
    
    args = parser.parse_args()
    
    if args.action == "add":
        if args.website and args.username and args.password:
            add_password(args.website, args.username, args.password)
        else:
            print("Missing arguments for adding a password.")
    elif args.action == "get":
        if args.website:
            retrieve_password(args.website)
        else:
            print("Please provide a website name.")
    elif args.action == "update":
        if args.website and args.username and args.password:
            update_password(args.website, args.username, args.password)
        else:
            print("Missing arguments for updating a password.")
    elif args.action == "delete":
        if args.website:
            delete_password(args.website)
        else:
            print("Please provide a website name.")
    elif args.action == "list":
        list_passwords()

if __name__ == "__main__":
    main()
