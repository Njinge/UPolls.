from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .forms import UserRegistrationForm, UserLoginForm
from .models import Matricule, User, Election, Candidate, Vote, PoliticalParty, AuditLog
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.core.mail import send_mail
import random
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import HttpRequest
import json
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
import secrets
import base64
from nacl.signing import SigningKey
import os
from django.views.decorators.csrf import csrf_exempt

# Create your views here.

def home(request):
    return render(request, 'core/home.html')

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            matricule_value = form.cleaned_data['matricule']
            try:
                matricule_obj = Matricule.objects.get(matricule__iexact=matricule_value.strip(), is_used=False)
            except Matricule.DoesNotExist:
                form.add_error('matricule', 'This matricule is not valid or has already been used.')
            else:
                user = form.save(commit=False)
                user.set_password(form.cleaned_data['password'])
                user.save()
                matricule_obj.is_used = True
                matricule_obj.save()
                # --- Audit log for registration ---
                log_audit(request, 'ADMIN_ACTION', {
                    'event': 'User Registration',
                    'username': user.username,
                    'email': user.email,
                    'matricule': user.matricule
                })
                messages.success(request, 'Registration successful! Please log in.')
                return redirect('login')
    else:
        form = UserRegistrationForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
    form = UserLoginForm(request.POST or None)
    error = None
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 10
    now = timezone.now()
    # Check for lockout
    lockout_until = request.session.get('login_lockout_until')
    if lockout_until:
        lockout_until_dt = timezone.datetime.fromisoformat(lockout_until)
        if now < lockout_until_dt:
            error = f'Too many failed login attempts. Try again at {lockout_until_dt.strftime("%H:%M:%S")}.'
            log_audit(request, 'LOGIN', {
                'event': 'Login Lockout',
                'lockout_until': lockout_until,
                'ip': request.META.get('REMOTE_ADDR')
            })
            messages.error(request, error)
            return render(request, 'core/login.html', {'form': form})
        else:
            # Lockout expired, clear it
            request.session.pop('login_lockout_until', None)
            request.session['login_attempts'] = 0
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Check if user has a valid matricule and Gmail
            if user.email.endswith('@gmail.com') and user.matricule and user.is_active:
                # Reset login attempts on success
                request.session['login_attempts'] = 0
                # Generate 2FA code
                code = f"{secrets.randbelow(900000) + 100000}"
                user.two_fa_code = code
                user.two_fa_code_created_at = timezone.now()
                user.is_2fa_verified = False
                user.save()
                # Send code to Gmail
                send_mail(
                    'Your UPolls 2FA Code',
                    f'Your 2FA code is: {code}',
                    'no-reply@upolls.com',
                    [user.email],
                    fail_silently=False,
                )
                request.session['2fa_user_id'] = user.id
                # --- Audit log for login (pre-2FA) ---
                log_audit(request, 'LOGIN', {
                    'event': 'Login Attempt',
                    'username': user.username,
                    'email': user.email
                })
                return redirect('verify_2fa')
            else:
                error = 'You must have a valid matricule and Gmail address.'
        else:
            # Increment login attempts
            attempts = request.session.get('login_attempts', 0) + 1
            request.session['login_attempts'] = attempts
            if attempts >= MAX_LOGIN_ATTEMPTS:
                lockout_until = (now + timezone.timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                request.session['login_lockout_until'] = lockout_until
                error = f'Too many failed login attempts. Try again at {(now + timezone.timedelta(minutes=LOCKOUT_MINUTES)).strftime("%H:%M:%S")}.'
                log_audit(request, 'LOGIN', {
                    'event': 'Login Lockout',
                    'username': username,
                    'ip': request.META.get('REMOTE_ADDR'),
                    'lockout_until': lockout_until,
                    'attempts': attempts
                })
            else:
                error = 'Invalid username or password.'
                # --- Audit log for failed login ---
                log_audit(request, 'LOGIN', {
                    'event': 'Failed Login',
                    'username': username,
                    'attempts': attempts
                })
    else:
        # Reset attempts on GET
        request.session['login_attempts'] = 0
    if error:
        messages.error(request, error)
    return render(request, 'core/login.html', {'form': form})

def verify_2fa(request):
    error = None
    MAX_ATTEMPTS = 5
    CODE_EXPIRY_MINUTES = 5
    if request.method == 'POST':
        code = request.POST.get('code')
        user_id = request.session.get('2fa_user_id')
        # Track attempts in session
        attempts = request.session.get('2fa_attempts', 0) + 1
        request.session['2fa_attempts'] = attempts
        if attempts > MAX_ATTEMPTS:
            error = 'Too many failed attempts. Please log in again.'
            log_audit(request, '2FA', {
                'event': '2FA Lockout',
                'user_id': user_id,
                'code_entered': code,
                'attempts': attempts
            })
            # Clear session and force re-login
            request.session.pop('2fa_user_id', None)
            request.session.pop('2fa_attempts', None)
            return redirect('login')
        if user_id:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                user = None
            # Check code expiry
            now = timezone.now()
            expired = False
            if user and user.two_fa_code_created_at:
                delta = now - user.two_fa_code_created_at
                if delta.total_seconds() > CODE_EXPIRY_MINUTES * 60:
                    expired = True
            if user and user.two_fa_code == code and not expired:
                user.is_2fa_verified = True
                user.two_fa_code = ''
                user.save()
                auth_login(request, user)
                request.session.pop('2fa_user_id', None)
                request.session.pop('2fa_attempts', None)
                # --- Audit log for successful 2FA ---
                log_audit(request, '2FA', {
                    'event': '2FA Success',
                    'username': user.username,
                    'email': user.email
                })
                return redirect('dashboard')
            else:
                if expired:
                    error = '2FA code expired. Please log in again.'
                    log_audit(request, '2FA', {
                        'event': '2FA Expired',
                        'user_id': user_id,
                        'code_entered': code,
                        'attempts': attempts
                    })
                    request.session.pop('2fa_user_id', None)
                    request.session.pop('2fa_attempts', None)
                    return redirect('login')
                else:
                    error = 'Invalid or expired 2FA code.'
                    # --- Audit log for failed 2FA ---
                    log_audit(request, '2FA', {
                        'event': '2FA Failure',
                        'user_id': user_id,
                        'code_entered': code,
                        'attempts': attempts
                    })
        else:
            error = 'Session expired. Please login again.'
    else:
        # Reset attempts on GET
        request.session['2fa_attempts'] = 0
    return render(request, 'core/verify_2fa.html', {'error': error})

def logout_view(request):
    # --- Audit log for logout ---
    log_audit(request, 'LOGOUT', {'event': 'User Logout'})
    auth_logout(request)
    return redirect('home')

@login_required
def dashboard(request):
    active_election = Election.objects.filter(is_active=True).first()
    election_over = active_election is None
    parties = PoliticalParty.objects.all() if active_election else []
    # For each party, get the president and vice president (if any)
    party_heads = {}
    if active_election:
        for party in parties:
            president = Candidate.objects.filter(election=active_election, party=party, post='PRESIDENT').first()
            vice_president = Candidate.objects.filter(election=active_election, party=party, post='VICE_PRESIDENT').first()
            party_heads[party.id] = {
                'president': president,
                'vice_president': vice_president
            }
    return render(request, 'core/dashboard.html', {
        'election_over': election_over,
        'parties': parties,
        'party_heads': party_heads,
        'active_election': active_election
    })

@login_required
def discover_parties(request):
    active_election = Election.objects.filter(is_active=True).first()
    if not active_election:
        messages.error(request, 'No active election found.')
        return redirect('dashboard')
    parties = PoliticalParty.objects.all()
    party_presidents = {}
    for party in parties:
        president = Candidate.objects.filter(election=active_election, party=party, post='PRESIDENT').first()
        party_presidents[party.id] = president
    return render(request, 'core/discover_parties.html', {
        'parties': parties,
        'party_presidents': party_presidents,
        'election': active_election
    })

@login_required
def party_detail(request, party_id):
    active_election = Election.objects.filter(is_active=True).first()
    if not active_election:
        messages.error(request, 'No active election found.')
        return redirect('dashboard')
    party = get_object_or_404(PoliticalParty, id=party_id)
    # Group all candidates by position
    candidates = Candidate.objects.filter(election=active_election, party=party)
    candidates_by_position = {}
    for candidate in candidates:
        pos = candidate.get_post_display()
        if pos not in candidates_by_position:
            candidates_by_position[pos] = []
        candidates_by_position[pos].append(candidate)
    return render(request, 'core/party_detail.html', {
        'party': party,
        'candidates_by_position': candidates_by_position,
        'election': active_election
    })

# --- Audit logging helper ---
def log_audit(request: HttpRequest, action: str, details=None):
    ip = request.META.get('REMOTE_ADDR')
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    details_dict = details or {}
    details_dict['user_agent'] = user_agent
    AuditLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        ip_address=ip,
        details=json.dumps(details_dict)
    )

@login_required
def vote(request):
    if request.user.has_voted:
        return render(request, 'core/already_voted.html')
    active_election = Election.objects.filter(is_active=True).first()
    if not active_election:
        return render(request, 'core/no_elections.html')
    parties = PoliticalParty.objects.all()
    party_presidents = {}
    for party in parties:
        president = Candidate.objects.filter(election=active_election, party=party, post='PRESIDENT').first()
        party_presidents[party.id] = president
    if request.method == 'POST':
        party_id = request.POST.get('party')
        public_key = request.POST.get('public_key')
        signature = request.POST.get('signature')
        timestamp = request.POST.get('timestamp')
        if not party_id or not public_key or not signature or not timestamp:
            messages.error(request, 'Please select a party and allow the cryptographic process to complete.')
        else:
            party = get_object_or_404(PoliticalParty, id=party_id)
            if request.user.has_voted:
                return render(request, 'core/already_voted.html')
            # Use the timestamp from the form for signature verification
            vote_data = f"{active_election.id}:{party.id}:{timestamp}"
            # Optionally, verify the signature here before saving
            receipt = secrets.token_urlsafe(16)
            Vote.objects.create(
                election=active_election,
                party=party,
                signature=signature,
                receipt=receipt,
                public_key=public_key,
                timestamp=timestamp
            )
            request.user.has_voted = True
            request.user.save()
            log_audit(request, 'VOTE', {
                'election': active_election.name,
                'party': party.name,
                'party_id': party.id
            })
            messages.success(request, f'Your vote has been recorded successfully! Your receipt: {receipt}')
            return render(request, 'core/vote_receipt.html', {'receipt': receipt})
    return render(request, 'core/vote.html', {
        'parties': parties,
        'active_election': active_election,
        'party_presidents': party_presidents,
    })

@login_required
def results(request):
    if not request.user.has_voted:
        messages.error(request, 'To view results, you must cast your vote first.')
        return redirect('vote')
    
    election = Election.objects.filter(is_active=True).first()
    election_over = election is None
    
    if not election:
        messages.error(request, 'No active election found.')
        return render(request, 'core/results.html', {'election_over': True})
    
    # Get total voters (users who have matricules)
    total_voters = User.objects.filter(role='VOTER').count()
    total_votes = Vote.objects.filter(election=election).count()
    voter_turnout = (total_votes / total_voters * 100) if total_voters > 0 else 0
    
    # Get results by candidate
    candidates = Candidate.objects.filter(election=election).select_related('party')
    results_data = []
    
    for candidate in candidates:
        vote_count = Vote.objects.filter(election=election, party=candidate.party).count()
        percentage = (vote_count / total_votes * 100) if total_votes > 0 else 0
        results_data.append({
            'candidate': candidate,
            'vote_count': vote_count,
            'percentage': percentage,
        })
    
    # Sort by vote count (descending)
    results_data.sort(key=lambda x: x['vote_count'], reverse=True)
    
    # Get party-level results for pie chart
    parties = PoliticalParty.objects.all()
    party_results = []
    chart_labels = []
    chart_data = []
    chart_colors = []
    
    for party in parties:
        vote_count = Vote.objects.filter(election=election, party=party).count()
        percentage = (vote_count / total_votes * 100) if total_votes > 0 else 0
        party_results.append({
            'party': party,
            'vote_count': vote_count,
            'percentage': percentage,
        })
        chart_labels.append(party.name)
        chart_data.append(vote_count)
        chart_colors.append(party.color or '#008080')
    
    # Group results by position
    results_by_position = {}
    for result in results_data:
        position = result['candidate'].get_post_display()
        if position not in results_by_position:
            results_by_position[position] = []
        results_by_position[position].append(result)
    
    return render(request, 'core/results.html', {
        'election': election,
        'results': results_data,
        'party_results': party_results,
        'results_by_position': results_by_position,
        'total_votes': total_votes,
        'total_voters': total_voters,
        'voter_turnout': voter_turnout,
        'election_over': election_over,
        'chart_labels': chart_labels,
        'chart_data': chart_data,
        'chart_colors': chart_colors,
    })

@login_required
def download_results_pdf(request):
    """Download election results as PDF (admin only)"""
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to download results.')
        return redirect('results')
    
    election = Election.objects.filter(is_active=True).first()
    if not election:
        messages.error(request, 'No active election found.')
        return redirect('results')
    
    # Get the same data as results view
    total_voters = User.objects.filter(role='VOTER').count()
    total_votes = Vote.objects.filter(election=election).count()
    voter_turnout = (total_votes / total_voters * 100) if total_voters > 0 else 0
    
    candidates = Candidate.objects.filter(election=election).select_related('party')
    results_data = []
    
    for candidate in candidates:
        vote_count = Vote.objects.filter(election=election, party=candidate.party).count()
        percentage = (vote_count / total_votes * 100) if total_votes > 0 else 0
        results_data.append({
            'candidate': candidate,
            'vote_count': vote_count,
            'percentage': percentage,
        })
    
    results_data.sort(key=lambda x: x['vote_count'], reverse=True)
    
    # Group by position
    results_by_position = {}
    for result in results_data:
        position = result['candidate'].get_post_display()
        if position not in results_by_position:
            results_by_position[position] = []
        results_by_position[position].append(result)
    
    # Create PDF response
    from django.http import HttpResponse
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from io import BytesIO
    import datetime
    
    # Create the HttpResponse object with PDF headers
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="election_results_{election.name}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
    
    # Create the PDF object
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,  # Center
        textColor=colors.HexColor('#008080')
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#008080')
    )
    
    # Title
    elements.append(Paragraph(f"Election Results - {election.name}", title_style))
    elements.append(Spacer(1, 20))
    
    # Summary
    summary_data = [
        ['Total Votes Cast', str(total_votes)],
        ['Total Registered Voters', str(total_voters)],
        ['Voter Turnout', f"{voter_turnout:.1f}%"],
        ['Report Generated', datetime.datetime.now().strftime("%B %d, %Y at %I:%M %p")]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#008080')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
    ]))
    
    elements.append(Paragraph("Election Summary", heading_style))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Results by position
    for position, position_results in results_by_position.items():
        elements.append(Paragraph(f"Results for {position}", heading_style))
        
        # Table headers
        table_data = [['Rank', 'Candidate', 'Party', 'Votes', 'Percentage']]
        
        # Add results
        for i, result in enumerate(position_results, 1):
            table_data.append([
                str(i),
                result['candidate'].name,
                result['candidate'].party.name,
                str(result['vote_count']),
                f"{result['percentage']:.1f}%"
            ])
        
        # Create table
        results_table = Table(table_data, colWidths=[0.5*inch, 2*inch, 1.5*inch, 0.8*inch, 1*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#008080')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),  # Candidate names left-aligned
            ('ALIGN', (2, 1), (2, -1), 'LEFT'),  # Party names left-aligned
        ]))
        
        elements.append(results_table)
        elements.append(Spacer(1, 15))
    
    # Build PDF
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    response.write(pdf)
    
    # Log the PDF download
    AuditLog.objects.create(
        user=request.user,
        action='EXPORT_RESULTS',
        ip_address=request.META.get('REMOTE_ADDR'),
        details=json.dumps({
            'event': 'PDF Results Download',
            'election': election.name,
            'total_votes': total_votes
        })
    )
    
    return response

class AuditedPasswordChangeView(PasswordChangeView):
    success_url = reverse_lazy('dashboard')
    template_name = 'core/password_change_form.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        # Audit log for password change
        log_audit(self.request, 'ADMIN_ACTION', {
            'event': 'Password Change',
            'username': self.request.user.username,
        })
        return response

def about_us(request):
    return render(request, 'core/about.html')

def faqs(request):
    return render(request, 'core/faqs.html')

def help_center(request):
    return render(request, 'core/help_center.html')

def guides(request):
    return render(request, 'core/guides.html')

def privacy_policy(request):
    return render(request, 'core/privacy_policy.html')

def terms_of_use(request):
    return render(request, 'core/terms_of_use.html')

def election_info(request):
    election = Election.objects.filter(is_active=True).first()
    return render(request, 'core/election_info.html', {'election': election})

def sign_vote_data(vote_data: str) -> str:
    private_key = os.environ['VOTE_SIGN_PRIVATE_KEY']
    signing_key = SigningKey(base64.b64decode(private_key))
    signed = signing_key.sign(vote_data.encode())
    return base64.b64encode(signed.signature).decode()

# Add Ed25519 signature verification
def verify_vote_signature(vote_data: str, signature: str) -> bool:
    from nacl.signing import VerifyKey
    public_key = os.environ['VOTE_SIGN_PUBLIC_KEY']
    verify_key = VerifyKey(base64.b64decode(public_key))
    try:
        verify_key.verify(vote_data.encode(), base64.b64decode(signature))
        return True
    except Exception:
        return False

@csrf_exempt
def verify_vote(request):
    result = None
    if request.method == 'POST':
        receipt = request.POST.get('receipt')
        public_key = request.POST.get('public_key')
        if not receipt or not public_key:
            result = 'Please provide both your receipt and public key.'
        else:
            vote = Vote.objects.filter(receipt=receipt, public_key=public_key).first()
            if not vote:
                result = 'No vote found for the provided receipt and public key.'
            else:
                # Reconstruct the vote data string as used in signing
                vote_data = f"{vote.election.id}:{vote.party.id}:{vote.timestamp.isoformat()}"
                if verify_vote_signature(vote_data, vote.signature):
                    result = 'Your vote is present and the signature is valid!'
                else:
                    result = 'Vote found, but the signature is invalid.'
    return render(request, 'core/verify_vote.html', {'result': result})
