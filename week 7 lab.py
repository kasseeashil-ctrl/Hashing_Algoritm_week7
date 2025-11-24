import bcrypt
import os

USER_DATA_FILE = "users.txt"


# ===== CORE SECURITY FUNCTIONS =====

def hash_password(plain_text_password):
    # TODO: Encode the password to bytes (bcrypt requires byte strings)
    password_bytes = plain_text_password.encode('utf-8')

    # TODO: Generate a salt using bcrypt.gensalt()
    salt = bcrypt.gensalt()

    # TODO: Hash the password using bcrypt.hashpw()
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)

    # TODO: Decode the hash back to a string to store in a text file return
    return hashed_bytes.decode('utf-8')


def verify_password(plain_text_password, hashed_password):
    # TODO: Encode both the plaintext password and the stored hash to bytes
    password_bytes = plain_text_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')

    # TODO: Use bcrypt.checkpw() to verify the password
    # This function extracts the salt from the hash and compares
    return bcrypt.checkpw(password_bytes, hashed_bytes)


# ===== TESTING HASHING FUNCTIONS =====

# TEMPORARY TEST CODE - Remove after testing
if __name__ == "__main__" and False:  # Change to True to test
    test_password = "SecurePassword123"

    # Test hashing
    hashed = hash_password(test_password)
    print(f"Original password: {test_password}")
    print(f"Hashed password: {hashed}")
    print(f"Hash length: {len(hashed)} characters")

    # Test verification with correct password
    is_valid = verify_password(test_password, hashed)
    print(f"\nVerification with correct password: {is_valid}")

    # Test verification with incorrect password
    is_invalid = verify_password("WrongPassword", hashed)
    print(f"Verification with incorrect password: {is_invalid}")


# ===== USER REGISTRATION =====

def user_exists(username):
    # TODO: Handle the case where the file doesn't exist yet
    if not os.path.exists(USER_DATA_FILE):
        return False

    # TODO: Read the file and check each line for the username
    try:
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                if line.strip():
                    parts = line.strip().split(',')
                    if parts[0] == username:
                        return True
    except FileNotFoundError:
        return False

    return False


def register_user(username, password):
    # TODO: Check if the username already exists
    if user_exists(username):
        return False

    # TODO: Hash the password
    hashed_password = hash_password(password)

    # TODO: Append the new user to the file
    # Format: username,hashed_password
    with open(USER_DATA_FILE, 'a') as file:
        file.write(f"{username},{hashed_password}\n")

    return True


# ===== USER LOGIN =====

def login_user(username, password):
    # TODO: Handle the case where no users are registered yet
    if not os.path.exists(USER_DATA_FILE):
        return False

    # TODO: Search for the username in the file
    try:
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                if line.strip():
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        stored_username = parts[0]
                        stored_hash = parts[1]

                        # TODO: If username matches, verify the password
                        if stored_username == username:
                            return verify_password(password, stored_hash)
    except FileNotFoundError:
        return False

    # TODO: If we reach here, the username was not found
    return False


# ===== INPUT VALIDATION =====

def validate_username(username):
    """
    Validates username format.

    Args:
        username (str): The username to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters long."

    if not username.replace('_', '').isalnum():
        return False, "Username can only contain letters, numbers, and underscores."

    return True, ""


def validate_password(password):
    """
    Validates password strength.

    Args:
        password (str): The password to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if len(password) < 6 or len(password) > 50:
        return False, "Password must be between 6 and 50 characters long."

    return True, ""


# ===== MAIN MENU =====

def display_menu():
    """Displays the main menu options."""
    print("\n" + "=" * 50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("=" * 50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("=" * 50)


def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()

            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            if register_user(username, password):
                print(f"Success: User '{username}' registered successfully!")
            else:
                print(f"Error: Username '{username}' already exists.")

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the database)")

                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")
            else:
                print("Error: Invalid username or password.")

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()