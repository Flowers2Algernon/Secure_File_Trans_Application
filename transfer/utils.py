import secrets
import string
import hashlib
from datetime import datetime,timedelta
from django.conf import settings

def generate_code(length=6):
    alphabet = string.ascii_letters + string.digits
    code = ''.join(secrets.choice(alphabet) for i in range(length))
    return code

def hash_access_code(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()  # Corrected to call .hexdigest() on the hash object

def verify_access_code(entered_code, hashed_code):
    return hashlib.sha256(entered_code.encode('utf-8')).hexdigest()
    # get hash code for the user entered code not compare now.

def get_code_expire_time():
    return datetime.now() + timedelta(minutes=settings.ACCESS_CODE_EXPIRE_MINUTES)
    # get the expire time for the code