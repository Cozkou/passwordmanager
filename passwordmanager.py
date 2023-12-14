import rsa
import time
import sys
import hashlib
import getpass

key = "d0e317465e29b1b19fa8ad3dcdef2f2d63130e3d7ab4f78ed2484022ee1e19a0"  # SHA-256 hashed master key

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

def main_menu():
    # Main menu
    print("--------PASSWORD MANAGER--------")
    time.sleep(0.5)
    print("\nPlease enter corresponding number:")
    print("1. View password")
    print("2. Add password")
    print("3. Remove password")
    print("4. Quit")

    is_running = True

    while is_running:
        user_input = input("> ")
        if user_input == "1":
            verify_password(key)
            view_password(private_key)
            is_running = False

        elif user_input == "2":
            verify_password(key)
            add_passwords()
            is_running = False

        elif user_input == "3":
            verify_password(key)
            # remove_passwords()
            is_running = False

        elif user_input == "4":
            sys.exit()
        else:
            print("Please enter valid input.")


def keys_management(user_site_password):
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    encrypted_password = rsa.encrypt(user_site_password.encode(), public_key)
    return encrypted_password


def database(site, email, username, password):
    """
    FORMAT:
    SITE NAME, EMAIL (null if N/A), USERNAME, PASSWORD
    """
    with open("database", "a") as f:
        f.write(f"Site: {site} | Email: {email} | Username: {username} | Password: (Next line)\n{password}\n\n")


def verify_password(key) -> bool:
    is_running = True
    while is_running:
        user_login = getpass.getpass("Enter master key: ")
        time.sleep(0.5)

        # Hash user_password and compare to the key.
        hashed_password = hashlib.sha256(user_login.encode()).hexdigest()
        if hashed_password == key:
            print("Access granted.")
            is_running = False
        else:
            print("Access denied.")
    return True


def view_password(private_key):

    retrieved_password = None
    selected_website = input("Enter site you want to view password for: ").capitalize()
    valid_website = False

    with open("database") as f:
        for line in f:
            if valid_website:
                retrieved_password = line.strip()[1:-1].encode()
                break

            if selected_website in line:
                valid_website = True

    if valid_website:
        try:
            decrypted_password = rsa.decrypt(retrieved_password, private_key)
            print(decrypted_password.decode())
        except rsa.pkcs1.DecryptionError as e:
            print("Error: ", str(e))
    else:
        print("Website not found in database.")

def add_passwords():
    is_running = True

    user_site = input("Enter the site you want to save a password for: ").capitalize()
    user_email = input("Enter the email for this account (Null if N/A): ").lower()
    user_name = input("Enter username (Null if N/A): ")

    while is_running:
        user_password = getpass.getpass("Enter password: ")
        user_password_verification = getpass.getpass("Re-enter password: ")

        if user_password == user_password_verification:
            keys_management(user_password)
            database(user_site, user_email, user_name, keys_management(user_password))
            print("Details stored in database.")
            is_running = False
        else:
            print("Passwords not matching. Please try again.")
    """
    FORMAT: 
    SITE NAME, EMAIL (null if N/A), USERNAME, PASSWORD
    """


def remove_passwords():
    # To remove password, you must enter site name and password.
    user_site_remove = input("Enter the site you want to remove a password for: ")
    user_password_remove = input("Enter password: ")

    with open("database") as f:
        for line in f:
            for character in line:
                pass


if __name__ == "__main__":
    main_menu()
