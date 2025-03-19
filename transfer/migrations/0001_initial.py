# Generated by Django 5.1.7 on 2025-03-19 13:03

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="EncrptedFile",
            fields=[
                (
                    "file_id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                ("uploaded_file", models.FileField(upload_to="uploaded_files/")),
                ("code_hash", models.CharField(max_length=64)),
                ("code_expire", models.DateTimeField()),
                ("uploaded_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
