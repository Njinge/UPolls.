# Generated by Django 5.2.3 on 2025-07-05 13:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="vote",
            name="signature",
            field=models.TextField(blank=True, null=True),
        ),
    ]
