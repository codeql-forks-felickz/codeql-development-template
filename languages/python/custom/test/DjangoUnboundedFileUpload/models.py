from django.db import models


def validate_file_size(value):
    if value.size > 10 * 1024 * 1024:
        raise ValueError("File is too large")


def validate_file_extension(value):
    pass


class Profile(models.Model):
    avatar = models.ImageField(upload_to="avatars/")  # $ Alert[py/django-unbounded-file-upload]
    document = models.FileField(upload_to="documents/")  # $ Alert[py/django-unbounded-file-upload]
    capped_avatar = models.ImageField(
        upload_to="avatars/",
        validators=[validate_file_size],
    )
    extension_only = models.FileField(
        upload_to="documents/",
        validators=[validate_file_extension],
    )  # $ Alert[py/django-unbounded-file-upload]
