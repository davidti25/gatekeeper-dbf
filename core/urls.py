"""
Configuração Central de URLs para o projeto GateKeeper-DBF.
"""

from allauth.account import views as allauth_views
from allauth.account.decorators import secure_admin_login
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

# Fase 3.1: Fortalecimento do login do Admin com MFA e rate limiting (CIS 6.5)
admin.site.login = secure_admin_login(admin.site.login)

urlpatterns = [
    # Autenticação Centralizada, MFA e Rate Limiting (allauth - Fase 3)
    path("login/", allauth_views.LoginView.as_view(), name="login"),
    path("logout/", allauth_views.LogoutView.as_view(), name="logout"),
    path("accounts/", include("allauth.urls")),
    # Painel Administrativo de Segurança (Rota configurável - Fase 2.4)
    path(settings.ADMIN_URL, admin.site.urls),
    # Módulo de Governança e Identidades
    path("", include("apps.governance.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
