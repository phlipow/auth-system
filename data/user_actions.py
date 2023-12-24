import hashlib
import os
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from data.pseudo_frontend import error, success, message, clear_terminal
from getpass import getpass

def connect_db():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'database.db')
    return sqlite3.connect(db_path)


def get_username(id):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute( 'SELECT username FROM auth WHERE id = ?', (id,))
    username = cursor.fetchone()
    if username:
        username = username[0]
        return username
    
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

def get_people(id, added):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(f'SELECT id, name FROM user_{id}_friends WHERE added = ?', (added,))
    
    user_data = cursor.fetchall()
    people = [(row[0], row[1]) for row in user_data]
    return people

def add_to_friends(user_id, friend_id):
    conn = connect_db()
    cursor = conn.cursor()
    username = get_username(user_id)

    cursor.execute(f'INSERT INTO user_{friend_id}_friends (id, name, added) VALUES (?, ?, ?)',
                   (user_id, username, 0,))
    
    conn.commit()
    conn.close()
    success('Request sent')

def confirm_friend(user_id, friend_id, added):
    conn = connect_db()
    cursor = conn.cursor()
    username = get_username(user_id)

    if added == 'y':
        cursor.execute(f'UPDATE user_{user_id}_friends SET added = 1 WHERE id = ?', (friend_id,))

        cursor.execute(f'INSERT INTO user_{friend_id}_friends (id, name, added) VALUES (?, ?, ?)',
                (user_id, username, 1,))
        
        conn.commit()
        conn.close()
        success('Request accepted')
    
    elif added =='n':
        cursor.execute(f'DELETE FROM user_{user_id}_friends WHERE id = ?', (friend_id,))

        conn.commit()
        conn.close()
        success('Request denied')
    


class User():

    def __init__(self, id):
        self.id = id
        self.username = get_username(id)

    def show_friends(self):
        friends_list = get_people(self.id, 1)
        for friend in friends_list:
            id, username = friend
            message(f'{id} - ', no_newline=True)
            print(username)
        message('Enter to return')
        getpass('')

        clear_terminal()
        
    
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


    def greet(self):
        success(f'Hello {self.username}!')

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
    print('messages')
    

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
