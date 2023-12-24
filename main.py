from data.auth_system import auth
from data.user_actions import logged

while True:
    logged(auth())