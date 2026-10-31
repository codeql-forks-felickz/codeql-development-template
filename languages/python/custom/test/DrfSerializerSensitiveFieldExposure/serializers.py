from django.contrib.auth.models import User
from rest_framework import serializers

from . import models as model_module
from .models import Project, UserProfile, UserProfile as AliasedUserProfile
from .unrelated_models import UserProfile as UnrelatedUserProfile


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


class AttributeReferenceProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = model_module.UserProfile
        fields = "__all__"  # $ Alert


class AliasedProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AliasedUserProfile
        fields = "__all__"  # $ Alert


class UnrelatedProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnrelatedUserProfile
        fields = "__all__"


class ExcludeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ("image",)  # $ Alert


class ExcludeSensitiveProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ("reset_token", "dob", "ssn")


class ExplicitExtraKwargsSerializer(serializers.ModelSerializer):
    password = serializers.CharField()

    class Meta:
        model = User
        fields = ["password"]  # $ Alert
        extra_kwargs = {"password": {"write_only": True}}


class LegacyWriteOnlyFieldsSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["password"]  # $ Alert
        write_only_fields = ("password",)


class WriteOnlyBaseSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)


class InheritedWriteOnlySerializer(WriteOnlyBaseSerializer):
    class Meta:
        model = User
        fields = ["password"]


class RedeclaredPasswordSerializer(WriteOnlyBaseSerializer):
    password = serializers.CharField()

    class Meta:
        model = User
        fields = ["password"]  # $ Alert
        extra_kwargs = {"password": {"write_only": True}}


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
