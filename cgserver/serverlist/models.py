import datetime
import os
import uuid

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
    dns_success = models.NullBooleanField(null=True, default=None)
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


class FtpPerm(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    path = models.CharField(max_length=255, db_index=True, blank=True, default=None)
    isdir = models.BooleanField(db_index=True, default=None)
    permission = models.CharField(max_length=64, db_index=True, default=None, choices=((p, p) for p in ['none', 'read', 'write', 'admin']))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'path']

    @staticmethod
    def issimplepath(path):
        if path == '':
            return True
        if '\\' in path:
            return False
        basedir = os.path.realpath(os.path.join('/does-not-exist', str(uuid.uuid4())))
        realpath = os.path.realpath(os.path.join(basedir, path))
        return realpath[:len(basedir) + 1] == basedir + os.sep and realpath[len(basedir) + 1:].replace(os.sep, '/') == path

    def save(self, *args, **kwargs):
        if not FtpPerm.issimplepath(self.path):
            raise ValueError('not a simple path')
        super().save(*args, **kwargs)


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
