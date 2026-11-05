"""
Rotas de URL para o aplicativo de Governança de Acessos & IAM (GateKeeper-DBF).
"""

from django.urls import path

from . import views

urlpatterns = [
    # Dashboard Executivo
    path("", views.DashboardView.as_view(), name="dashboard"),
    # Gestão de Colaboradores
    path("colaboradores/", views.ColaboradorListView.as_view(), name="colaborador_list"),
    path("colaboradores/<int:pk>/", views.ColaboradorDetailView.as_view(), name="colaborador_detail"),
    path("colaboradores/<int:pk>/iniciar-offboarding/", views.iniciar_offboarding_view, name="iniciar_offboarding"),
    # Inventário de Sistemas
    path("sistemas/", views.SistemaListView.as_view(), name="sistema_list"),
    # Matriz RBAC
    path("matriz-acessos/", views.MatrizAcessoListView.as_view(), name="matriz_acesso"),
    # Central de Offboarding
    path("offboarding/", views.OffboardingListView.as_view(), name="offboarding_list"),
    path("offboarding/<int:pk>/", views.OffboardingDetailView.as_view(), name="offboarding_detail"),
    path(
        "offboarding/<int:pk>/revogar/<int:item_id>/",
        views.revogar_item_offboarding_view,
        name="revogar_item_offboarding",
    ),
    path("offboarding/<int:pk>/relatorio/", views.OffboardingRelatorioView.as_view(), name="offboarding_relatorio"),
]
