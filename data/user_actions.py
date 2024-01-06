import hashlib
import os
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from data.pseudo_frontend import error, success, message, clear_terminal, you, him
from getpass import getpass


def connect_db():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'database.db')
    return sqlite3.connect(db_path)

# Function that gets the user's username
def get_username(id):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute('SELECT username FROM auth WHERE id = ?', (id,))
    username = cursor.fetchone()
    if username:
        username = username[0]
        return username

# Function that gets the user's ID
def get_id(username):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute('SELECT id FROM auth WHERE username = ?', (username,))
    id = cursor.fetchone()
    if id:
        id = id[0]

    conn.close()
    return id

# Function that gets the friends and requests of a user
def get_people(id, added):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(f'SELECT id, name FROM user_{id}_friends WHERE added = ?', (added,))
    
    user_data = cursor.fetchall()
    people = [(row[0], row[1]) for row in user_data]
    
    conn.close()
    return people

# Function that adds a user to friends
def add_to_friends(user_id, friend_id):
    conn = connect_db()
    cursor = conn.cursor()
    
    username = get_username(user_id)

    cursor.execute(f'INSERT INTO user_{friend_id}_friends (id, name, added) VALUES (?, ?, ?)',
                   (user_id, username, 0,))
    
    conn.commit()
    conn.close()
    success('Request sent')

# Function that sorts IDs
def id_sort(id1, id2):
    if id1 < id2:
        return id1, id2
    else:
        return id2, id1

# Function that confirms or deny a friend request
def confirm_friend(user_id, friend_id, added):
    conn = connect_db()
    cursor = conn.cursor()
    username = get_username(user_id)

    if added == 'y':
        cursor.execute(f'UPDATE user_{user_id}_friends SET added = 1 WHERE id = ?', (friend_id,))
        cursor.execute(f'INSERT INTO user_{friend_id}_friends (id, name, added) VALUES (?, ?, ?)',
                (user_id, username, 1,))
       
        id1, id2 = id_sort(user_id, friend_id)       

        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS chat_{id1}_{id2}(
                id INTEGER,
                message TEXT
            )
        ''')

        conn.commit()
        conn.close()
        success('Request accepted')
    
    elif added == 'n':
        cursor.execute(f'DELETE FROM user_{user_id}_friends WHERE id = ?', (friend_id,))

        conn.commit()
        conn.close()
        success('Request denied')

# Function that gets chat history
def get_messages(user_id, friend_id):
    conn = connect_db()
    cursor = conn.cursor()

    id1, id2 = id_sort(user_id, friend_id)

    cursor.execute(f'SELECT * FROM chat_{id1}_{id2}')
    
    messages = cursor.fetchall()
    history = [{'id': row[0], 'text': row[1]} for row in messages]
    return history

# Function that sends a message
def send_message(user_id, friend_id, txt):
    conn = connect_db()
    cursor = conn.cursor()

    id1, id2 = id_sort(user_id, friend_id)
    cursor.execute(f'INSERT INTO chat_{id1}_{id2} (id, message) VALUES (?, ?)',
                   (user_id, txt,))
    
    conn.commit()
    conn.close()

# Function that encrypts a message
def encrypt_message(public_key_bytes, plaintext):
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

# Function that decrypts a message
def decrypt_message(private_key_bytes, ciphertext):
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

    return plaintext

# Function that gets public or private key
def get_key(id, privacy):
    conn = connect_db()
    cursor = conn.cursor()
    
    if privacy == 'public':
        cursor.execute('SELECT public FROM keys WHERE id = ?', (id,))
    elif privacy == 'private':
        cursor.execute('SELECT public FROM keys WHERE id = ?', (id,))
    
    key = cursor.fetchone()
    return key

class User():

    def __init__(self, id):
        self.id = id
        self.username = get_username(id)

    # Show user's friend List
    def show_friends(self):
        friends_list = get_people(self.id, 1)
        for friend in friends_list:
            id, username = friend
            message(f'{id} - ', no_newline=True)
            print(username)
        message('Enter to return')
        getpass('')

        clear_terminal()

    # Send a friend request
    def add_friend(self):
        try:
            message('Friends\'s username: ', no_newline=True)
            friend = input('')
            friend_id = get_id(friend)

            clear_terminal()

            if not friend_id:
                error('Username doesn\'t exist')
            else:
                add_to_friends(self.id, friend_id)
        except sqlite3.IntegrityError:
            error('Request already invited to this user')

    # Accept or deny a request
    def interact_requests(self):
        requests_list = get_people(self.id, 0)
        for request in requests_list:
            while True:
                friend_id, friend_username = request
                message(f'{friend_id} - ', no_newline=True)
                print(friend_username)
                message('Confirm(y/n)?: ', no_newline=True)
                added = input('')

                clear_terminal()

                if added == 'y' or added == 'n':
                    confirm_friend(self.id, friend_id, added)
                    break
                else:
                    clear_terminal()
                    error('Invalid command')
    # Greets the user
    def greet(self):
        success(f'Hello {self.username}!')

    # Show and send messages to a friend
    def chat(self, friend_id):
        try:
            # Show messages
            while True:
                clear_terminal()
                messages = get_messages(self.id, friend_id)
                friend_username = get_username(friend_id)
                success(friend_username)
                for register in messages:
                    if register['id'] == self.id:
                        you()
                    elif register['id'] == friend_id:
                        him(friend_username, decrypt_message(self.id, register['text']))
                        
                # Send a message
                message('Type your message: ')
                new_msg = input()
                send_message(self.id, friend_id, encrypt_message(get_key(friend_id, 'public'), new_msg))
        except KeyboardInterrupt:
            clear_terminal()

def friends(user):
    while True:
        try:
            success('Friends')

            message('1 - ', no_newline=True)
            print('Friend\'s List')

            message('2 - ', no_newline=True)
            print('Add Friend')

            message('3 - ', no_newline=True)
            print('Requests')

            message('0 - ', no_newline=True)
            print('Return to Menu')

            message('Enter your instruction: ', no_newline=True)
            instruction = input('')

            clear_terminal()

            if instruction == '1':
                user.show_friends()
            elif instruction == '2':
                message('ctrl + c - ', no_newline=True)
                print('Return')
                user.add_friend()
            elif instruction == '3':
                message('ctrl + c - ', no_newline=True)
                print('Return')
                user.interact_requests()
            elif instruction == '0':
                break
            else:
                error('Invalid Instruction')
        except KeyboardInterrupt:
            clear_terminal()
            pass

def messages(user):
    success('Messages')

    friends_list = get_people(user.id, 1)
    friends_ids = []
    while True:
        message('0 - ', no_newline=True)
        print('return')

        for friend in friends_list:
            id, username = friend
            friends_ids.append(id)
            message(f'{id} - ', no_newline=True)
            print(username)

        message('Enter friend ID: ', no_newline=True)
        friend_id = int(input())
        if friend_id == 0:
            clear_terminal()
            break
        elif not friend_id in friends_ids:
            error('This user is not your friend')
        else:
            user.chat(friend_id)

def logged(id):
    user = User(id)
    while True:
        try:
            user.greet()

            message('1 - ', no_newline=True)
            print('Friends')

            message('2 - ', no_newline=True)
            print('Messages')

            message('3 - ', no_newline=True)
            print('Log Out')

            message('0 - ', no_newline=True)
            print('Exit')

            message('Enter your instruction: ', no_newline=True)
            instruction = input('')

            clear_terminal()

            if instruction == '1':
                friends(user)
            elif instruction == '2':
                messages(user)
            elif instruction == '3':
                success('Logged out')
                break
            elif instruction == '0':
                success('Goodbye')
                os._exit(0)
            else:
                error('Invalid Instruction')
        except KeyboardInterrupt:
            clear_terminal()
            pass
