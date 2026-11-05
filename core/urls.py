"""
Configuração Central de URLs para o projeto GateKeeper-DBF.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Painel Administrativo de Segurança
    path('admin/', admin.site.urls),

    # Módulo de Governança e Identidades
    path('', include('apps.governance.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
