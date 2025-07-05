from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from .models import User, Candidate

class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, validators=[validate_password])
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['name', 'username', 'email', 'matricule', 'password']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email or not email.endswith('@gmail.com'):
            raise ValidationError('Please use a valid Gmail address.')
        if User.objects.filter(email=email).exists():
            raise ValidationError('A user with this email already exists.')
        return email

    def clean_matricule(self):
        matricule = self.cleaned_data.get('matricule')
        if User.objects.filter(matricule=matricule).exists():
            raise ValidationError('This matricule has already been used.')
        # Matricule list validation will be handled in the view
        return matricule

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match.')
        return cleaned_data

class UserLoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

class VoteForm(forms.Form):
    candidate = forms.ModelChoiceField(
        queryset=None,
        empty_label="Select a candidate",
        widget=forms.RadioSelect
    )
    
    def __init__(self, *args, **kwargs):
        election = kwargs.pop('election', None)
        super().__init__(*args, **kwargs)
        if election:
            self.fields['candidate'].queryset = Candidate.objects.filter(election=election) 