from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.CharField(max_length=255)
    reset_token = models.CharField(max_length=7, default="")
    reset_token_expiration = models.DateTimeField(default=timezone.now)
    dob = models.CharField(max_length=8, default="00/00/00")
    ssn = models.CharField(max_length=11, default="000-00-0000")


class Project(models.Model):
    title = models.CharField(max_length=50)
    description = models.TextField()
