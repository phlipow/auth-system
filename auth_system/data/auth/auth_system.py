import hashlib
import secrets
import os
from getpass import getpass
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# set colors for messages:
ERROR = '\033[91m'
SUCCESS = '\033[92m'
MSG = '\033[94m'
RESET = '\033[0m'

# function that checks if username is valid


def find_username(username):

    # connects to SQL database
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM authentication WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result is None:
        print(ERROR + 'Username does not exist' + RESET)

    conn.close()
    return result is not None

# function that checks password strength


def is_it_strong(password):
    it_is = True
    # checks password size
    if not (8 <= len(password) <= 20):
        it_is = False
        print(ERROR + 'Password must have between 8 and 20 characters' + RESET)
    # checks if password has a auppercase chatacter
    if not any(character.isupper() for character in password):
        it_is = False
        print(ERROR + 'Password must have at least one uppercase character' + RESET)
    # checks if password has a lowercase character
    if not any(character.islower() for character in password):
        it_is = False
        print(ERROR + 'Password must have at least one lowercase character' + RESET)
    # checks if password has numbers
    if not any(character.isdigit() for character in password):
        it_is = False
        print(ERROR + 'Password must have at least one character digit' + RESET)
    # Checks if password has special characters
    if not any(not character.isalnum() for character in password):
        it_is = False
        print(ERROR + 'Password must have at least one special character' + RESET)
    if it_is:
        if password != getpass('Confirm Password: '):
            print(ERROR + 'Passwords do not match' + RESET)
            it_is = False
    return it_is

# function that hashes a password with a salt


def hash_password(password, salt):
    hasher = hashlib.sha256()
    salt_password = password + salt
    hasher.update(salt_password.encode('utf-8'))
    return hasher.hexdigest()

# function that checks if username is available


def check_username(username):

    # connects to SQL database
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM authentication WHERE username = ?', (username,))
    result = cursor.fetchone()
    if not result is None:
        print(ERROR + 'Username already exists' + RESET)

    conn.close()
    return result is None

# function that finds user salt


def find_salt(username):

    # connects to SQL database
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT salt FROM authentication WHERE username = ?', (username,))
    salt = cursor.fetchone()

    conn.close()
    return salt

# function that checks if the password is right:


def is_it_right(username, password):

    # connects to SQL database
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    it_is = False
    # Finds user's salt and hashed password
    cursor.execute(
        'SELECT salt, hashed FROM authentication WHERE username = ?', (username,))
    result = cursor.fetchone()
    salt, right = result
    hashed_attempt = hash_password(password, salt)

    conn.close()
    if hashed_attempt == right:
        return True
    else:
        return False

# function that gets user id:


def get_id(username):

    # connects to SQL database
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id FROM authentication WHERE username = ?', (username,))
    id = cursor.fetchone()

    conn.close()
    return id

# function that generates and saves user's key pair
def key_pair(id):

    # connects to SQL database using a relative path from main.py
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.abspath(os.path.join(
        module_dir, '..', 'friends and chats', 'database.db'))
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private and public keys to bytes before storing in the database
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    cursor.execute('INSERT INTO keys (id, private, public) VALUES (?, ?, ?)',
                   (id, private_key_bytes, public_key_bytes,))

    conn.commit()
    conn.close()

# function that generates user friends table
def create_user_data(username):
    # connects to SQL database using a relative path from main.py
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.abspath(os.path.join(
        module_dir, '..', 'friends and chats', 'database.db'))
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    table_name = f'{username}_friends'
    
    cursor.execute(f'''
        CREATE TABLE {table_name} (
            id INTEGER
        )
    ''')

    conn.commit()
    conn.close()



# function that writes user data on database
def save_user(username, salt, hashed):
    # connects to SQL database
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # writes user data on database
    cursor.execute(
        'INSERT INTO authentication (username, salt, hashed) VALUES (?, ?, ?)', (username, salt, hashed,))

    conn.commit()
    conn.close()


class Auth():

    # register a new user
    def register(self):
        # init flags for breaking loops
        success_username = False
        success_password = False

        print(MSG + 'Register' + RESET)

        # checks if username already exists
        while not success_username:
            username = input('Username: ')
            success_username = check_username(username)

        # checks password strength
        while not success_password:
            password = getpass('Password: ')
            success_password = is_it_strong(password)

        # generates a salt
        salt = secrets.token_hex(16)

        # hashes the password with salt
        hashed = hash_password(password, salt)

        # generates and saves user's key pair
        key_pair(get_id(username))

        # generates user friends table
        create_user_data(username)

        # writes user data on database
        save_user(username, salt, hashed)

        print(SUCCESS + 'User created' + RESET)

    # logs a user in
    def login(self):
        # init flags for breaking loops
        success_username = False
        success_password = False

        print(MSG + 'Log in' + RESET)

        # checks if username exists
        while not success_username:
            username = input('Username: ')
            success_username = find_username(username)

        # checks if password is right
        attempt = 1
        while not success_password and attempt <= 10:
            password = getpass('Password: ')
            success_password = is_it_right(username, password)
            if not success_password:
                print(
                    ERROR + f'Wrong password \nAttempt {attempt} of 10' + RESET)
                attempt += 1

        if not success_password:
            print(ERROR + 'Attempt limit exceeded' + RESET)
            os._exit(0)
        else:
            print(SUCCESS + 'Logged in' + RESET)
            return get_id(username)


def auth():
    x = Auth()
    while True:
        try:
            print(SUCCESS + 'Wellcome')
            print(MSG + '1', RESET + ' - Log in')
            print(MSG + '2', RESET + ' - Sign up')
            print(MSG + 'ctrl + c', RESET + ' - Return to menu')
            print(MSG + '0', RESET + ' - Exit')
            instruction = input(MSG + 'Type your instruction: ' + RESET)

            if instruction == '1':
                return x.login()
            elif instruction == '2':
                x.register()
            elif instruction == '0':
                print(MSG + 'Good bye' + RESET)
                os._exit(0)
            else:
                print(ERROR + 'Invalid instruction' + RESET)
        except KeyboardInterrupt:
            pass