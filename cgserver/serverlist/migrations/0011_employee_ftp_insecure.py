# Generated by Django 2.0.13 on 2019-06-30 12:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('serverlist', '0010_auto_20190630_1717'),
    ]

    operations = [
        migrations.AddField(
            model_name='employee',
            name='ftp_insecure',
            field=models.BooleanField(db_index=True, default=False),
        ),
    ]
