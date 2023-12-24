import os

# message colors
def error(msg, no_newline=False):
    end = '' if no_newline else '\n'
    print('\033[91m' + msg + '\033[0m', end=end)

def success(msg, no_newline=False):
    end = '' if no_newline else '\n'
    print('\033[92m' + msg + '\033[0m', end=end)

def message(msg, no_newline=False):
    end = '' if no_newline else '\n'
    print('\033[94m' + msg + '\033[0m', end=end)

#clear terminal
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# return back
class BackError(Exception):
    def __init__(self, level):
        self.level = level
        super().__init__(level)