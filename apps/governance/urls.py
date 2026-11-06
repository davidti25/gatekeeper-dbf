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
    # Fase 15: Revisão Periódica de Acessos
    path("campanhas/", views.CampanhaListView.as_view(), name="campanha_list"),
    path("campanhas/abrir/", views.abrir_campanha_view, name="abrir_campanha"),
    path("campanhas/<int:pk>/painel/", views.CampanhaPainelView.as_view(), name="campanha_painel"),
    path("campanhas/<int:pk>/encerrar/", views.encerrar_campanha_view, name="encerrar_campanha"),
    path("campanhas/<int:pk>/relatorio/", views.CampanhaRelatorioView.as_view(), name="campanha_relatorio"),
    path(
        "campanhas/<int:pk>/revogar/<int:item_id>/",
        views.executar_revogacao_revisao_view,
        name="executar_revogacao_revisao",
    ),
    path("revisoes/", views.MinhasRevisoesView.as_view(), name="minhas_revisoes"),
    path("revisoes/<int:item_id>/decidir/", views.decidir_revisao_view, name="decidir_revisao"),
    path("revisoes/lote/", views.decidir_revisao_lote_view, name="decidir_revisao_lote"),
]
