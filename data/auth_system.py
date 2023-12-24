import hashlib
import secrets
import os
from getpass import getpass
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from data.pseudo_frontend import error, success, message, clear_terminal

def connect_db():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'database.db')
    return sqlite3.connect(db_path)

# function that checks if username is valid
def find_username(username):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM auth WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result is None:
        error('Username does not exist')

    conn.close()
    return result is not None

# function that checks password strength
def is_it_strong(password):
    it_is = True
    # checks password size
    if not (8 <= len(password) <= 20):
        it_is = False
        error('Password must contain between 8 and 20 characters')
    # checks if password has a uppercase chatacter
    if not any(character.isupper() for character in password):
        it_is = False
        error('Password must contain at least one uppercase character')
    # checks if password has a lowercase character
    if not any(character.islower() for character in password):
        it_is = False
        error('Password must contain at least one lowercase character')
    # checks if password has numbers
    if not any(character.isdigit() for character in password):
        it_is = False
        error('Password must contain at least one character digit')
    # Checks if password has special characters
    if not any(not character.isalnum() for character in password):
        it_is = False
        error('Password must contain at least one special character')
    if it_is:
        if password != getpass('Confirm Password: '):
            error('Passwords do not match')
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
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM auth WHERE username = ?', (username,))
    result = cursor.fetchone()
    if not result is None:
        error('Username already exists')

    conn.close()
    return result is None

# function that finds user salt
def find_salt(username):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT salt FROM auth WHERE username = ?', (username,))
    salt = cursor.fetchone()

    conn.close()
    return salt

# function that checks if the password is right:
def is_it_right(username, password):
    conn = connect_db()
    cursor = conn.cursor()

    it_is = False
    # Finds user's salt and hashed password
    cursor.execute(
        'SELECT salt, hashed_password FROM auth WHERE username = ?', (username,))
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
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id FROM auth WHERE username = ?', (username,))
    id = cursor.fetchone()
    if id:
        id = id[0]

    conn.close()
    return id

# function that generates and saves user's key pair
def key_pair(id):
    conn = connect_db()
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
def create_user_data(id):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS user_{id}_friends (
            id INTEGER UNIQUE,
            name TEXT UNIQUE,
            added INTEGER

        )
    ''')

    conn.commit()
    conn.close()



# function that writes user data on database
def save_user(username, salt, hashed):
    conn = connect_db()
    cursor = conn.cursor()

    # writes user data on database
    cursor.execute(
        'INSERT INTO auth (username, salt, hashed_password) VALUES (?, ?, ?)', (username, salt, hashed,))

    conn.commit()
    conn.close()


class Auth():

    # register a new user
    def register(self):
        # init flags for breaking loops
        success_username = False
        success_password = False

        success('Register')

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

        # writes user data on database
        save_user(username, salt, hashed)

        # generates and saves user's key pair
        key_pair(get_id(username))

        # generates user friends table
        create_user_data(str(get_id(username)))

        clear_terminal()

        success('User successfully created')

    # logs a user in
    def login(self):
        # init flags for breaking loops
        success_username = False
        success_password = False

        success('Log in' )

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
                error(f'Wrong password \nAttempt {attempt} of 10')

        if not success_password:
            error('Exceeded attempt limit')
            os._exit(0)
        else:
            clear_terminal()
            success('Logged in')
            return get_id(username)


def auth():
    x = Auth()
    while True:
        try:
            success('Welcome')

            message('1 - ', no_newline=True)
            print('Log in')

            message('2 - ', no_newline=True)
            print('Sign up')

            message('0 - ', no_newline=True)
            print('Exit')

            message('Enter your instruction: ', no_newline=True)
            instruction = input('')
            
            clear_terminal()

            if instruction == '1':
                message('ctrl + c - ', no_newline=True)
                print('Return')
                return x.login()
            elif instruction == '2':
                message('ctrl + c - ', no_newline=True)
                print('Return')
                x.register()
            elif instruction == '0':
                clear_terminal()
                success('Goodbye')
                os._exit(0)
            else:
                error('Invalid Instruction')
        except KeyboardInterrupt:
            clear_terminal()
            pass