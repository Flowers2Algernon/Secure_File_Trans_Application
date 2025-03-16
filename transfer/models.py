from django.db import models
from django.contrib.auth.models import User

class FileShare(models.Model):
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    code = models.CharField(max_length=255, unique=True)
    is_downloaded = models.BooleanField(default=False)
    def __str__(self):
        return f"File share with code: {self.code}"