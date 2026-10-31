from django.shortcuts import render
from django.urls import path


def ssti_view_blog(request, blog_id):  # $ Source
    return render(request, f"Lab_2021/A3_Injection/Blogs/{blog_id}.html")  # $ Alert


def fixed_template(request, blog_id):
    return render(request, "Lab_2021/A3_Injection/Blogs/index.html")


urlpatterns = [
    path("blog/<str:blog_id>/", ssti_view_blog),
    path("fixed/<str:blog_id>/", fixed_template),
]
