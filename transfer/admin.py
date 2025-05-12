from django.contrib import admin
from transfer.models import EncrptedFile, FileLog, KeyPair, FileRequest


# Register your models here.
@admin.register(EncrptedFile)
class EncrptedFileAdmin(admin.ModelAdmin):
    list_display = (
        "file_id",
        "original_filename",
        "file_size",
        "uploaded_date",
        "code_expire",
    )
    search_fields = ("original_filename", "file_id")
    readonly_fields = ("file_id", "uploaded_date")


@admin.register(FileLog)
class FileLogAdmin(admin.ModelAdmin):
    list_display = (
        "encrptedFile",
        "download_time",
        "download_final_datetime",
        "ip_address",
    )
    list_filter = ("download_final_datetime",)


@admin.register(KeyPair)
class KeyPairAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "created_at")
    readonly_fields = ("id", "created_at")


@admin.register(FileRequest)
class FileRequestAdmin(admin.ModelAdmin):
    list_display = (
        "request_id",
        "requester_email",
        "requester_name",
        "created_at",
        "expires_at",
        "is_fulfilled",
    )
    list_filter = ("is_fulfilled", "created_at")
    search_fields = ("requester_email", "requester_name")
    readonly_fields = ("request_id", "created_at")
