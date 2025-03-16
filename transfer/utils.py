import secrets
import string

def generate_code(length=6):
    alphabet = string.ascii_letters + string.digits
    code = ''.join(secrets.choice(alphabet) for i in range(length))
    return code