from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from .managers import UserManager
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.contrib.auth import get_user_model
import json

class User(AbstractBaseUser, PermissionsMixin):
    VOTER = 'VOTER'
    ADMIN = 'ADMIN'
    ROLE_CHOICES = [
        (VOTER, 'Voter'),
        (ADMIN, 'Admin'),
    ]

    name = models.CharField(max_length=255)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    matricule = models.CharField(max_length=50, unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default=VOTER)
    has_voted = models.BooleanField(default=False)
    is_2fa_verified = models.BooleanField(default=False)
    two_fa_code = models.CharField(max_length=6, blank=True, null=True)
    two_fa_code_created_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'name', 'matricule']

    objects = UserManager()

    def __str__(self):
        return f"{self.username} ({self.role})"

class Matricule(models.Model):
    matricule = models.CharField(max_length=50, unique=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return self.matricule

class PoliticalParty(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    vision = models.TextField(blank=True, help_text="Party's vision and mission statement")
    logo = models.ImageField(upload_to='party_logos/', blank=True, null=True)
    color = models.CharField(max_length=7, default='#008080', help_text="Party color in hex format")
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class Election(models.Model):
    name = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    highlights = models.TextField(blank=True, help_text="Election highlights or information for voters")

    def __str__(self):
        return self.name

class Candidate(models.Model):
    POSITION_CHOICES = [
        ('PRESIDENT', 'President'),
        ('VICE_PRESIDENT', 'Vice President'),
        ('SECRETARY_GENERAL', 'Secretary General'),
        ('TREASURER', 'Treasurer'),
        ('PUBLIC_RELATIONS', 'Public Relations Officer'),
        ('SPORTS_SECRETARY', 'Sports Secretary'),
        ('ACADEMIC_AFFAIRS', 'Academic Affairs Secretary'),
        ('WELFARE_SECRETARY', 'Welfare Secretary'),
        ('OTHER', 'Other'),
    ]
    
    election = models.ForeignKey(Election, on_delete=models.CASCADE)
    party = models.ForeignKey('PoliticalParty', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    post = models.CharField(max_length=100, choices=POSITION_CHOICES)
    bio = models.TextField(blank=True, help_text="Candidate's biography and qualifications")
    photo = models.ImageField(upload_to='candidate_photos/', blank=True, null=True)
    manifesto = models.TextField(blank=True, help_text="Candidate's manifesto and promises")

    def __str__(self):
        return f"{self.name} ({self.get_post_display()})"

class Vote(models.Model):
    election = models.ForeignKey(Election, on_delete=models.CASCADE)
    party = models.ForeignKey('PoliticalParty', on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    signature = models.TextField(blank=True, null=True)
    receipt = models.CharField(max_length=128, unique=True, blank=True, null=True)  # Voter gets this as proof
    public_key = models.TextField(blank=True, null=True)  # Voter's public key for verification

    def __str__(self):
        party = self.party.name if self.party else "No party"
        election = self.election.name if self.election else "No election"
        return f"Vote for {party} in {election} (receipt: {self.receipt})"

# --- AuditLog model for security logging ---
class AuditLog(models.Model):
    ACTION_CHOICES = [
        ("VOTE", "Vote Cast"),
        ("LOGIN", "User Login"),
        ("LOGOUT", "User Logout"),
        ("2FA", "2FA Verification"),
        ("ADMIN_ACTION", "Admin Action"),
        ("EXPORT_RESULTS", "Export Results"),
        ("UPLOAD_CSV", "Upload Matricule CSV"),
        ("OTHER", "Other"),
    ]
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.TextField(blank=True, help_text="Extra details or JSON")
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        user = self.user.username if self.user else "System/Anon"
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {user} - {self.get_action_display()}"
