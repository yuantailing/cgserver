from django import forms
from django.contrib.auth.models import User


class ResetPasswordForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput())
