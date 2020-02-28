from django import forms


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Username',
            },
        ),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Password',
            },
        ),
    )


class ResetPasswordForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Username',
            },
        ),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Password',
            },
        ),
    )


class FtpForm(forms.Form):
    action = forms.CharField()
    id = forms.IntegerField(required=False)
    username = forms.CharField(required=False)
    path = forms.CharField(required=False)
    isdir = forms.BooleanField(required=False)
    permission = forms.CharField(required=False)
