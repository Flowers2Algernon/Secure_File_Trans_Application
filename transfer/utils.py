import secrets
import string
import hashlib
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
import random

def generate_code():
    """Generate a random 6-digit numeric access code."""
    return ''.join(random.choices('0123456789', k=6))

def hash_access_code(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()  # Corrected to call .hexdigest() on the hash object

def verify_access_code(stored_hash, entered_hash):
    """Verify if the entered access code hash matches the stored hash."""
    return stored_hash == entered_hash

def get_code_expire_time():
    return timezone.now() + timedelta(minutes=settings.ACCESS_CODE_EXPIRE_MINUTES)