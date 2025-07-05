from django.urls import path
from . import views
from .views import AuditedPasswordChangeView

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('discover-parties/', views.discover_parties, name='discover_parties'),
    path('party/<int:party_id>/', views.party_detail, name='party_detail'),
    path('vote/', views.vote, name='vote'),
    path('results/', views.results, name='results'),
    path('password-change/', AuditedPasswordChangeView.as_view(), name='password_change'),
    path('about/', views.about_us, name='about_us'),
    path('faqs/', views.faqs, name='faqs'),
    path('help-center/', views.help_center, name='help_center'),
    path('guides/', views.guides, name='guides'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('terms-of-use/', views.terms_of_use, name='terms_of_use'),
    path('election-info/', views.election_info, name='election_info'),
    path('download-results-pdf/', views.download_results_pdf, name='download_results_pdf'),
] 