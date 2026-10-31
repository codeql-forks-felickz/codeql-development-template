from django.db import models


class UserData(models.Model):
    credit_card = models.CharField(max_length=16)
    ssn = models.CharField(max_length=9)
    api_key = models.CharField(max_length=32)


class AuthLogin(models.Model):
    password = models.CharField(max_length=128)


class Profile(models.Model):
    display_name = models.CharField(max_length=128)


def store_sensitive_data(request):
    credit_card = request.POST.get("credit_card")  # $ Source
    ssn = request.POST.get("ssn")  # $ Source
    api_key = request.POST.get("api_key")  # $ Source
    UserData.objects.create(credit_card=credit_card, ssn=ssn, api_key=api_key)  # $ Alert


def store_password(request):
    password = request.POST["pass"]  # $ Source
    AuthLogin.objects.create(password=password)  # $ Alert


def store_non_sensitive_data(request):
    display_name = request.POST.get("display_name")
    Profile.objects.create(display_name=display_name)


def store_hashed_password(request):
    password = request.POST.get("password")
    AuthLogin.objects.create(password=generate_password_hash(password))


def generate_password_hash(password):
    return password
