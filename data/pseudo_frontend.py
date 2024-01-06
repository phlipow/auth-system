import os

# Message colors
def error(msg, no_newline=False):
    end = '' if no_newline else '\n'
    print('\033[91m' + msg + '\033[0m', end=end)

def success(msg, no_newline=False):
    end = '' if no_newline else '\n'
    print('\033[92m' + msg + '\033[0m', end=end)

def message(msg, no_newline=False):
    end = '' if no_newline else '\n'
    print('\033[94m' + msg + '\033[0m', end=end)

def you(name, msg):
    print('\033[35m' + name + ':' + '\033[0m', msg)

def him(name, msg):
    print('\033[95m' + name + ':' + '\033[0m', msg)

# Clear terminal
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')
