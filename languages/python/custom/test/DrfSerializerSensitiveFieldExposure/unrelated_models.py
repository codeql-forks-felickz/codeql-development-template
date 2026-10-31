from django.db import models


class UserProfile(models.Model):
    display_name = models.CharField(max_length=50)
