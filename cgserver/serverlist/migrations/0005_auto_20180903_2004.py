# Generated by Django 2.0.8 on 2018-09-03 12:04

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('serverlist', '0004_accesslog'),
    ]

    operations = [
        migrations.CreateModel(
            name='GithubUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('github_id', models.IntegerField(default=None, unique=True)),
                ('github_email', models.CharField(db_index=True, default=None, max_length=64)),
                ('github_login', models.CharField(db_index=True, default=None, max_length=64)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RemoveField(
            model_name='employee',
            name='comment',
        ),
        migrations.RemoveField(
            model_name='employee',
            name='vpn_username',
        ),
    ]
