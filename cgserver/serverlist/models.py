import datetime

from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

# Create your models here.

class Client(models.Model):
    client_id = models.CharField(max_length=64, db_index=True, unique=True, default=None)
    client_secret = models.CharField(max_length=64, default=None)
    display_name = models.CharField(max_length=64, blank=True, default='')
    manager = models.CharField(max_length=64, blank=True, default='')
    info = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return 'Client<{:s}>'.format(self.client_id)


class ClientReport(models.Model):
    client = models.ForeignKey(Client, default=None, on_delete=models.CASCADE)
    ip = models.CharField(max_length=64, db_index=True, default=None)
    version = models.CharField(max_length=64, db_index=True, default=None)
    report = models.TextField(default=None)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)


class AccessLog(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, null=True, on_delete=models.CASCADE)
    ip = models.CharField(max_length=64, db_index=True, default=None)
    target = models.CharField(max_length=64, db_index=True, default=None)
    param = models.CharField(max_length=64, blank=True, default='')
    info = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)


class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    can_access = models.BooleanField(default=False)
    staff_number = models.IntegerField(unique=True, blank=True, null=True,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(999),
        ],
    )
    shadow_password = models.CharField(max_length=255, blank=True)
    nt_password_hash = models.CharField(max_length=64, blank=True)
    password_updated_at = models.DateTimeField(default=datetime.datetime(2018, 1, 1))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return 'Employee<{:s}>'.format(self.user.username)


class GithubUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    github_id = models.IntegerField(unique=True, default=None)
    github_email = models.CharField(max_length=64, db_index=True, default=None)
    github_login = models.CharField(max_length=64, db_index=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class UnknownReport(models.Model):
    client_id = models.CharField(max_length=64, db_index=True, default=None)
    client_secret = models.CharField(max_length=64, default=None)
    ip = models.CharField(max_length=64, db_index=True, default=None)
    version = models.CharField(max_length=64, db_index=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return 'UnknownReport<{:s}>'.format(self.client_id)
