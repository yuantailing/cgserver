import uuid

from django.contrib.auth.models import User
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


class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    can_access = models.BooleanField(default=False)
    vpn_username = models.CharField(max_length=64, unique=True, db_index=True, default=uuid.uuid4)
    comment = models.CharField(max_length=64, blank=True, default='')
