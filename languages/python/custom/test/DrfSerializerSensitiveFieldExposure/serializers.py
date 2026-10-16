from django.contrib.auth.models import User
from rest_framework import serializers

from .models import Project, UserProfile


class UserProfileSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("uuid", "image", "reset_token", "reset_token_expiration", "dob", "ssn", "user")  # $ Alert
        lookup_field = "uuid"


class UserProfileAllSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = "__all__"  # $ Alert


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "password"]  # $ Alert


class BaseSerializer(serializers.ModelSerializer):
    pass


class DerivedUserSerializer(BaseSerializer):
    class Meta:
        model = User
        fields = ["username", "password"]  # $ Alert


# --- Safe cases ---


class SafeUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "password"]
        extra_kwargs = {"password": {"write_only": True}}


class SafeDeclaredUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("username", "password")


class SafeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("image", "user", "reset_token_expiration")


class SafeProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = "__all__"


class NotASerializer:
    class Meta:
        fields = ("ssn", "password")
