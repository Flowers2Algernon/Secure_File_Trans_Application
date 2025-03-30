from django.db import models
import uuid


class EncrptedFile(models.Model):
    # TODO: current don't implement encrption
    file_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    original_filename = models.FileField(max_length=255)
    # The FileField itself stores the path to the file in the database table (as a VARCHAR or TEXT type column). It does not store the file content directly in the database.
    uploaded_file = models.FileField(
        upload_to='uploaded_files/')  # store the unencrypted file for now TODO: after encrption implement, change this model.
    # The size of file
    file_size = models.IntegerField(default=0)
    code_hash = models.CharField(max_length=64)  # store the hash of the 6-digit code
    code_expire = models.DateTimeField()  # store the expire time of the code
    uploaded_date = models.DateTimeField(auto_now_add=True)  # store the time when the file is uploaded

    def __str__(self):
        return str(self.file_id)


class FileLog(models.Model):
    encrptedFile = models.ForeignKey(EncrptedFile, on_delete=models.CASCADE, related_name='logs', db_column='file_id')
    download_time = models.IntegerField(default=0)
    download_final_datetime = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return str(self.file_id)
