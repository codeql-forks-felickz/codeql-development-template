from django.db import models


class Project(models.Model):
    title = models.CharField(max_length=50)


class Task(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    title = models.CharField(max_length=50)
    completed = models.BooleanField(default=False)


class Note(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    text = models.CharField(max_length=200)
