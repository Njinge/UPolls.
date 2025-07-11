# Generated by Django 5.2.1 on 2025-07-03 15:55

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="Election",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=200)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "highlights",
                    models.TextField(
                        blank=True,
                        help_text="Election highlights or information for voters",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Matricule",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("matricule", models.CharField(max_length=50, unique=True)),
                ("is_used", models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name="PoliticalParty",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=100, unique=True)),
                ("description", models.TextField(blank=True)),
                (
                    "vision",
                    models.TextField(
                        blank=True, help_text="Party's vision and mission statement"
                    ),
                ),
                (
                    "logo",
                    models.ImageField(blank=True, null=True, upload_to="party_logos/"),
                ),
                (
                    "color",
                    models.CharField(
                        default="#008080",
                        help_text="Party color in hex format",
                        max_length=7,
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("username", models.CharField(max_length=150, unique=True)),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("matricule", models.CharField(max_length=50, unique=True)),
                (
                    "role",
                    models.CharField(
                        choices=[("VOTER", "Voter"), ("ADMIN", "Admin")],
                        default="VOTER",
                        max_length=10,
                    ),
                ),
                ("has_voted", models.BooleanField(default=False)),
                ("is_2fa_verified", models.BooleanField(default=False)),
                ("two_fa_code", models.CharField(blank=True, max_length=6, null=True)),
                ("two_fa_code_created_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False)),
                (
                    "date_joined",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("VOTE", "Vote Cast"),
                            ("LOGIN", "User Login"),
                            ("LOGOUT", "User Logout"),
                            ("2FA", "2FA Verification"),
                            ("ADMIN_ACTION", "Admin Action"),
                            ("EXPORT_RESULTS", "Export Results"),
                            ("UPLOAD_CSV", "Upload Matricule CSV"),
                            ("OTHER", "Other"),
                        ],
                        max_length=32,
                    ),
                ),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                (
                    "details",
                    models.TextField(blank=True, help_text="Extra details or JSON"),
                ),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Candidate",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                (
                    "post",
                    models.CharField(
                        choices=[
                            ("PRESIDENT", "President"),
                            ("VICE_PRESIDENT", "Vice President"),
                            ("SECRETARY_GENERAL", "Secretary General"),
                            ("TREASURER", "Treasurer"),
                            ("PUBLIC_RELATIONS", "Public Relations Officer"),
                            ("SPORTS_SECRETARY", "Sports Secretary"),
                            ("ACADEMIC_AFFAIRS", "Academic Affairs Secretary"),
                            ("WELFARE_SECRETARY", "Welfare Secretary"),
                            ("OTHER", "Other"),
                        ],
                        max_length=100,
                    ),
                ),
                (
                    "bio",
                    models.TextField(
                        blank=True, help_text="Candidate's biography and qualifications"
                    ),
                ),
                (
                    "photo",
                    models.ImageField(
                        blank=True, null=True, upload_to="candidate_photos/"
                    ),
                ),
                (
                    "manifesto",
                    models.TextField(
                        blank=True, help_text="Candidate's manifesto and promises"
                    ),
                ),
                (
                    "election",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="core.election"
                    ),
                ),
                (
                    "party",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="core.politicalparty",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Vote",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                (
                    "election",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="core.election"
                    ),
                ),
                (
                    "party",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="core.politicalparty",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "unique_together": {("user", "election")},
            },
        ),
    ]
