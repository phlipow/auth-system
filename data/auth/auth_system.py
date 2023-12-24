import hashlib
import secrets
import os
from getpass import getpass
import sqlite3

#connects to SQL database
module_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(module_dir, 'auth_data.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

def check_username(username):
    cursor.execute("SELECT * FROM authentication WHERE username = ?", (username,))
    resultado = cursor.fetchone()
    return resultado is None

#function that hashes password with a salt
def hash_password(password, salt):
    hasher = hashlib.sha256()
    salt_password = password + salt
    hasher.update(salt_password.encode('utf-8'))
    return hasher.hexdigest()

#function that checks password strength
def is_it_strong(password):
    it_is = True
    #checks password size
    if not (8 <= len(password) <= 20):
        it_is = False
        print('Password must have between 8 and 20 characters')
    #checks if password has uppercase
    if not any(character.isupper() for character in password):
        it_is = False
        print('Password must have at least one uppercase character')
    #checks if password has lowercase
    if not any(character.islower() for character in password):
        it_is = False
        print('Password must have at least one lowercase character')
    #checks if password has numbers
    if not any(character.isdigit() for character in password):
        it_is = False
        print('Password must have at least one character digit')
    # Checks if password has special characters
    if not any(not character.isalnum() for character in password):
        it_is = False
        print('Password must have at least one special character')
    if it_is:
        if password != getpass('Confirm Password: '):
            print('Passwords do not match')
            it_is = False
    return it_is

class Auth():

    #register a new user
    def register(self):
        # init flags for breaking loops
        success_username = False
        success_password = False
        
        print('Register')

        # checks if username already exists
        while not success_username:
            username = input('Username: ')
            success_username = check_username(username)
 
        
        #checks password strength
        while not success_password:
            password = getpass('Password: ')
            success_password = is_it_strong(password)

        #generate salt
        salt = secrets.token_hex(16)

        #hashers password with salt
        hashed = hash_password(password, salt)

        #combine user data
        cursor.execute("INSERT INTO authentication (username, salt, hashed) VALUES (?, ?, ?)", (username, salt, hashed,))
