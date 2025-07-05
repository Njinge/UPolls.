from django.contrib import admin
from django.http import HttpResponseRedirect
from django.urls import path
from django.shortcuts import render
from django.contrib import messages
import csv
from io import StringIO
from .models import PoliticalParty, Election, Candidate, Vote, Matricule, AuditLog
import json
import socket
from django.utils import timezone
from .views import verify_vote_signature

# Register your models here.

# --- Admin Audit Log Mixin ---
class AdminAuditLogMixin:
    def log_addition(self, request, obj, message):
        super().log_addition(request, obj, message)
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            details=json.dumps({
                'event': 'Admin Add',
                'object': str(obj),
                'model': obj.__class__.__name__,
                'message': message,
                'timestamp': timezone.now().isoformat()
            })
        )
    def log_change(self, request, obj, message):
        super().log_change(request, obj, message)
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            details=json.dumps({
                'event': 'Admin Change',
                'object': str(obj),
                'model': obj.__class__.__name__,
                'message': message,
                'timestamp': timezone.now().isoformat()
            })
        )
    def log_deletion(self, request, obj, object_repr):
        super().log_deletion(request, obj, object_repr)
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            details=json.dumps({
                'event': 'Admin Delete',
                'object': object_repr,
                'model': obj.__class__.__name__,
                'timestamp': timezone.now().isoformat()
            })
        )

@admin.register(Matricule)
class MatriculeAdmin(AdminAuditLogMixin, admin.ModelAdmin):
    list_display = ('matricule', 'is_used')
    list_filter = ('is_used',)
    search_fields = ('matricule',)
    actions = ['mark_as_unused', 'mark_as_used']
    
    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_upload_link'] = True
        return super().changelist_view(request, extra_context)
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('upload-csv/', self.admin_site.admin_view(self.upload_csv_view), name='core_matricule_upload_csv'),
        ]
        return custom_urls + urls
    
    def upload_csv_view(self, request):
        if request.method == 'POST':
            csv_file = request.FILES.get('csv_file')
            if csv_file:
                try:
                    # Read CSV content
                    content = csv_file.read().decode('utf-8')
                    csv_data = csv.reader(StringIO(content))
                    
                    # Skip header if present
                    next(csv_data, None)
                    
                    # Process each row
                    created_count = 0
                    for row in csv_data:
                        if row and row[0].strip():  # Check if row has data
                            matricule = row[0].strip()
                            # Only create if it doesn't exist
                            if not Matricule.objects.filter(matricule=matricule).exists():
                                Matricule.objects.create(matricule=matricule)
                                created_count += 1
                    
                    # --- Audit log for CSV upload ---
                    AuditLog.objects.create(
                        user=request.user if request.user.is_authenticated else None,
                        action='UPLOAD_CSV',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        details=json.dumps({
                            'event': 'Matricule CSV Upload',
                            'created_count': created_count
                        })
                    )
                    messages.success(request, f'Successfully uploaded {created_count} new matricules.')
                    return HttpResponseRedirect('../')
                    
                except Exception as e:
                    messages.error(request, f'Error uploading CSV: {str(e)}')
            else:
                messages.error(request, 'Please select a CSV file.')
        
        context = {
            'title': 'Upload Matricules CSV',
            'opts': self.model._meta,
        }
        return render(request, 'admin/core/matricule/upload_csv.html', context)
    
    def mark_as_unused(self, request, queryset):
        count = queryset.count()
        queryset.update(is_used=False)
        # --- Audit log for mark as unused ---
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR'),
            details=json.dumps({
                'event': 'Mark Matricules as Unused',
                'count': count,
                'matricules': list(queryset.values_list('matricule', flat=True))
            })
        )
        self.message_user(request, f'{count} matricules marked as unused.')
    mark_as_unused.short_description = "Mark selected matricules as unused"
    
    def mark_as_used(self, request, queryset):
        count = queryset.count()
        queryset.update(is_used=True)
        # --- Audit log for mark as used ---
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR'),
            details=json.dumps({
                'event': 'Mark Matricules as Used',
                'count': count,
                'matricules': list(queryset.values_list('matricule', flat=True))
            })
        )
        self.message_user(request, f'{count} matricules marked as used.')
    mark_as_used.short_description = "Mark selected matricules as used"

@admin.register(PoliticalParty)
class PoliticalPartyAdmin(AdminAuditLogMixin, admin.ModelAdmin):
    list_display = ('name', 'color', 'has_vision')
    list_filter = ('color',)
    search_fields = ('name', 'description', 'vision')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'logo')
        }),
        ('Branding', {
            'fields': ('color',),
            'description': 'Choose a color to represent this party in the UI'
        }),
        ('Vision & Mission', {
            'fields': ('vision',),
            'description': 'Party\'s vision and mission statement'
        }),
    )
    actions = ['delete_selected', 'deactivate_party']
    
    def has_vision(self, obj):
        return bool(obj.vision)
    has_vision.boolean = True
    has_vision.short_description = 'Has Vision'

    def deactivate_party(self, request, queryset):
        count = queryset.count()
        queryset.update(is_active=False)
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            details=json.dumps({
                'event': 'Deactivate PoliticalParty',
                'count': count,
                'parties': list(queryset.values_list('name', flat=True)),
                'timestamp': timezone.now().isoformat()
            })
        )
        self.message_user(request, f'{count} party(ies) deactivated.')
    deactivate_party.short_description = "Deactivate selected parties"

@admin.register(Election)
class ElectionAdmin(AdminAuditLogMixin, admin.ModelAdmin):
    list_display = ('name', 'is_active', 'created_at', 'candidate_count')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name',)
    actions = ['activate_election', 'deactivate_election', 'delete_selected']
    
    def candidate_count(self, obj):
        return obj.candidate_set.count()
    candidate_count.short_description = 'Candidates'
    
    def activate_election(self, request, queryset):
        # Deactivate all other elections first
        Election.objects.all().update(is_active=False)
        # Activate selected elections
        queryset.update(is_active=True)
        # --- Audit log for election activation ---
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR'),
            details=json.dumps({
                'event': 'Activate Election',
                'elections': list(queryset.values_list('name', flat=True))
            })
        )
        self.message_user(request, f'{queryset.count()} election(s) activated.')
    activate_election.short_description = "Activate selected elections"
    
    def deactivate_election(self, request, queryset):
        queryset.update(is_active=False)
        # --- Audit log for election deactivation ---
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR'),
            details=json.dumps({
                'event': 'Deactivate Election',
                'elections': list(queryset.values_list('name', flat=True))
            })
        )
        self.message_user(request, f'{queryset.count()} election(s) deactivated.')
    deactivate_election.short_description = "Deactivate selected elections"

    def delete_selected(self, request, queryset):
        count = queryset.count()
        names = list(queryset.values_list('name', flat=True))
        queryset.delete()
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action='ADMIN_ACTION',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            details=json.dumps({
                'event': 'Delete Election',
                'count': count,
                'elections': names,
                'timestamp': timezone.now().isoformat()
            })
        )
        self.message_user(request, f'{count} election(s) deleted.')
    delete_selected.short_description = "Delete selected elections"

@admin.register(Candidate)
class CandidateAdmin(AdminAuditLogMixin, admin.ModelAdmin):
    list_display = ('name', 'get_post_display', 'party', 'election', 'has_photo')
    list_filter = ('election', 'party', 'post')
    search_fields = ('name', 'bio', 'manifesto')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'election', 'party', 'post')
        }),
        ('Media', {
            'fields': ('photo',),
            'description': 'Upload a professional photo of the candidate'
        }),
        ('Details', {
            'fields': ('bio', 'manifesto'),
            'description': 'Candidate biography and manifesto'
        }),
    )
    
    def has_photo(self, obj):
        return bool(obj.photo)
    has_photo.boolean = True
    has_photo.short_description = 'Has Photo'
    
    def get_post_display(self, obj):
        return obj.get_post_display()
    get_post_display.short_description = 'Position'

@admin.register(Vote)
class VoteAdmin(AdminAuditLogMixin, admin.ModelAdmin):
    """
    Votes are anonymized in the admin: user is not shown or searchable.
    Only election, party, timestamp, signature, receipt, and public_key are visible. Votes are read-only.
    """
    list_display = ('election', 'party', 'timestamp', 'signature', 'receipt', 'public_key')
    list_filter = ('election', 'party', 'timestamp')
    search_fields = ('party__name', 'receipt', 'public_key')
    readonly_fields = ('election', 'party', 'timestamp', 'signature', 'receipt', 'public_key')
    actions = ['verify_vote_signatures']

    def verify_vote_signatures(self, request, queryset):
        verified = 0
        failed = 0
        for vote in queryset:
            # Reconstruct the vote data string as used in signing
            # (user is no longer available, so use receipt or public_key as needed)
            vote_data = f"{vote.election.id}:{vote.party.id}:{vote.timestamp.isoformat()}"
            if vote.signature and verify_vote_signature(vote_data, vote.signature):
                verified += 1
            else:
                failed += 1
        self.message_user(request, f"Signature verification: {verified} valid, {failed} invalid.")
    verify_vote_signatures.short_description = "Verify Ed25519 signatures of selected votes"

    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False

# --- AuditLog admin registration ---
@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'ip_address', 'short_details')
    list_filter = ('action', 'user', 'ip_address', 'timestamp')
    search_fields = ('user__username', 'action', 'details', 'ip_address')
    readonly_fields = [f.name for f in AuditLog._meta.fields]
    ordering = ('-timestamp',)

    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False
    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser
    def short_details(self, obj):
        d = obj.details
        if len(d) > 60:
            return d[:60] + '...'
        return d
    short_details.short_description = 'Details'
