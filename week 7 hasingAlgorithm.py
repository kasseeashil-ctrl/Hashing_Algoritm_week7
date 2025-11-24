import bcrypt
import os

# File to store user credentials (username and hashed password)
USER_DATA_FILE = "users.txt"


#PASSWORD SECURITY FUNCTIONS

def hash_password(plain_text_password):
    """
    Securely hash a password using bcrypt.
    Steps:
    1. Convert the plain text password to bytes (bcrypt works with bytes)
    2. Generate a random salt - this adds uniqueness to each hash
    3. Combine the password with salt and hash them together
    4. Convert the resulting hash back to string for storage
    """
    # Convert password string to bytes so bcrypt can process it
    password_bytes = plain_text_password.encode('utf-8')

    # Generate a cryptographically secure random salt
    # This ensures even identical passwords get different hashes
    salt = bcrypt.gensalt()

    # Create the hash by combining password and salt
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)

    # Convert the bytes hash back to string for text file storage
    return hashed_bytes.decode('utf-8')


def verify_password(plain_text_password, hashed_password):
    """
    Verify if a plain text password matches the stored hash.
    How it Operates:
    - The stored hash contains the salt used during hashing
    - bcrypt extracts this salt and uses it to hash the provided password
    - Compares the newly generated hash with the stored hash
    """
    # Convert both inputs to bytes for bcrypt
    password_bytes = plain_text_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')

    # Let bcrypt handle the verification
    # It automatically extracts the salt from the stored hash
    return bcrypt.checkpw(password_bytes, hashed_bytes)


#USER MANAGEMENT FUNCTIONS

def user_exists(username):
    """
    Check if a username is already registered in our system.
    We need to check this before allowing new registrations
    to prevent duplicate usernames.
    """
    # If the user database file doesn't exist yet, no users are registered
    if not os.path.exists(USER_DATA_FILE):
        return False

    try:
        # Open the file and check each line for the username
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                line = line.strip()  # Remove any extra spaces or newlines
                if line:  # Make sure it's not an empty line
                    # Split the line into username and password hash
                    parts = line.split(',')
                    if parts[0] == username:
                        return True  # Username found!
    except FileNotFoundError:
        # This shouldn't happen since we checked above, but just in case
        return False

    return False  # Username not found in the file


def register_user(username, password):
    """
    Register a new user by storing their username and hashed password.
    Security note: We never store plain text passwords.
    """
    # First, make sure this username isn't already taken
    if user_exists(username):
        print(f"Registration failed: Username '{username}' is already taken.")
        return False

    # Convert the plain password to a secure hash
    hashed_password = hash_password(password)

    # Save the user credentials to our database file
    with open(USER_DATA_FILE, 'a') as file:
        # Format: username,hashed_password (comma separated)
        file.write(f"{username},{hashed_password}\n")

    print(f"Success: User '{username}' has been registered!")
    return True


def login_user(username, password):
    """
    Authenticate a user by verifying their password against the stored hash.
    Returns True if credentials are valid,return False otherwise.
    """
    # Can't log in if no users are registered yet
    if not os.path.exists(USER_DATA_FILE):
        print("No users registered in the system yet.")
        return False

    try:
        # Search through all registered users
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    parts = line.split(',')
                    # Make sure we have both username and password in the line
                    if len(parts) >= 2:
                        stored_username = parts[0]
                        stored_hash = parts[1]

                        # Found our user! Now verify their password
                        if stored_username == username:
                            # This is the critical security check
                            return verify_password(password, stored_hash)
    except FileNotFoundError:
        return False

    # If we get here, the username doesn't exist in our system
    print(f"Login failed: User '{username}' not found.")
    return False


#INPUT VALIDATION FUNCTIONS

def validate_username(username):
    """
    Make sure usernames meet our requirements.
    Why validate a usernames?
    Prevent extremely long usernames that could cause issues
    Maintain consistency in our user database
    Basic security against weird inputs
    """
    # Check length requirements
    if len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if len(username) > 20:
        return False, "Username cannot exceed 20 characters."

    # Check for valid characters (letters, numbers, underscores only)
    # We replace underscores temporarily to check alphanumeric status
    if not username.replace('_', '').isalnum():
        return False, "Username can only contain letters, numbers, and underscores."

    return True, "Username is valid!"


def validate_password(password):
    """
    Basic password strength validation.
    """
    # Check password length
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if len(password) > 50:
        return False, "Password cannot exceed 50 characters."

    return True, "Password meets requirements."


#USER INTERFACE FUNCTIONS

def display_menu():
    """Show the main menu options to the user."""
    print("\n" + "=" * 50)
    print("        SECURE AUTHENTICATION SYSTEM")
    print("=" * 50)
    print("\nWhat would you like to do?")
    print("1. Register a new account")
    print("2. Login to your account")
    print("3. Exit the system")
    print("=" * 50)


def handle_registration():
    """Guide the user through the registration process."""
    print("\n--- Create New Account ---")

    # Get and validate username
    username = input("Choose a username: ").strip()
    is_valid, message = validate_username(username)
    if not is_valid:
        print(f"Invalid username: {message}")
        return

    # Get and validate password
    password = input("Choose a password: ").strip()
    is_valid, message = validate_password(password)
    if not is_valid:
        print(f"Invalid password: {message}")
        return

    # Confirm the password (common security practice)
    password_confirm = input("Please re-enter your password: ").strip()
    if password != password_confirm:
        print("Error: Passwords don't match. Please try again.")
        return

    # Everything looks good - register the user!
    register_user(username, password)


def handle_login():
    """Guide the user through the login process."""
    print("\n--- Login to Your Account ---")

    username = input("Username: ").strip()
    password = input("Password: ").strip()

    # Try to authenticate the user
    if login_user(username, password):
        print(f"\n Login successful! Welcome back, {username}!")
        print("You now have access to the system.")

        # In a real app, this is where you'd show the main application
        input("\nPress Enter to return to main menu...")
    else:
        print("Login failed. Please check your username and password.")


def main():
    """
    Main program that runs the authentication system.

    This is like the reception desk - it greets users and
    directs them to where they need to go.
    """
    print(" Welcome to the Secure Authentication System!")

    # Keep the program running until the user chooses to exit
    while True:
        display_menu()
        choice = input("\nEnter your choice (1-3): ").strip()

        if choice == '1':
            handle_registration()
        elif choice == '2':
            handle_login()
        elif choice == '3':
            print("\nThank you for using our system. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


# This is where the program actually starts when you run the file
if __name__ == "__main__":
    main()