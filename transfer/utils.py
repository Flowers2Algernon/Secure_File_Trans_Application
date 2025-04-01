import secrets
import string
import hashlib
from datetime import timedelta
from django.conf import settings
from django.utils import timezone

def generate_code(length=6):
    alphabet = string.ascii_letters + string.digits
    code = ''.join(secrets.choice(alphabet) for i in range(length))
    return code

def hash_access_code(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()  # Corrected to call .hexdigest() on the hash object

def verify_access_code(stored_hash, entered_hash):
    """Verify if the entered access code hash matches the stored hash."""
    return stored_hash == entered_hash

def get_code_expire_time():
    return timezone.now() + timedelta(minutes=settings.ACCESS_CODE_EXPIRE_MINUTES)