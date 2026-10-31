from django.contrib.auth.views import logout_then_login
from django.urls import path

urlpatterns = [
    path("logout/", logout_then_login),  # $ Alert
]


def read_only_view(request):
    return None


urlpatterns += [path("read-only/", read_only_view)]
