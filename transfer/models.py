import uuid

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, User  # noqa: F401


class KeyPair(models.Model):
    """Model to store RSA key pairs for users"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True
    )
    public_key = models.TextField()  # Store PEM encoded public key
    private_key_salt = models.BinaryField(
        null=True, blank=True
    )  # Salt for private key encryption
    encrypted_private_key = models.BinaryField(
        null=True, blank=True
    )  # Encrypted private key
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"KeyPair {self.id}"


class EncrptedFile(models.Model):
    file_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True
    )
    original_filename = models.CharField(max_length=100)
    uploaded_file = models.FileField(upload_to="uploaded_files/")
    file_size = models.IntegerField(default=0)
    download_count = models.IntegerField(default=0)

    # Encryption fields
    encrypted_aes_key = models.BinaryField(null=True, blank=True)
    iv = models.BinaryField(null=True, blank=True)
    auth_tag = models.BinaryField(
        null=True, blank=True
    )  # Add this if you're using AES-GCM
    encryption_algorithm = models.CharField(
        max_length=20, default="AES-256-GCM", null=True, blank=True
    )
    file_hash = models.CharField(max_length=64, null=True, blank=True)
    recipient_public_key = models.TextField(null=True, blank=True)

    code_hash = models.CharField(max_length=64)
    code_expire = models.DateTimeField()
    uploaded_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.file_id)


class FileLog(models.Model):
    encrptedFile = models.ForeignKey(
        EncrptedFile, on_delete=models.CASCADE, related_name="logs", db_column="file_id"
    )
    download_time = models.IntegerField(default=0)
    download_final_datetime = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Log for {self.encrptedFile.file_id}"


class FileRequest(models.Model):
    """Model for secure file requests"""

    request_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requester_email = models.EmailField()
    requester_name = models.CharField(max_length=100)
    request_message = models.TextField(blank=True)
    public_key = models.TextField()  # Requester's public key
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_fulfilled = models.BooleanField(default=False)

    def __str__(self):
        return f"Request from {self.requester_email}"


class UserProfile(AbstractUser):

    def __str__(self):
        return str(self.username)
