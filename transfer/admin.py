from django.contrib import admin

from transfer.models import EncrptedFile, FileLog

# Register your models here.
admin.site.register(EncrptedFile)
admin.site.register(FileLog)