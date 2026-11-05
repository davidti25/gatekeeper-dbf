"""
Configuração Central de URLs para o projeto GateKeeper-DBF.
"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Autenticação Centralizada (Fase 0 - Emergência)
    path(
        'login/',
        auth_views.LoginView.as_view(
            template_name='registration/login.html',
            redirect_authenticated_user=True
        ),
        name='login'
    ),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    # Painel Administrativo de Segurança
    path('admin/', admin.site.urls),

    # Módulo de Governança e Identidades
    path('', include('apps.governance.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
