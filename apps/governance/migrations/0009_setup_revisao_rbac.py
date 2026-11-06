from django.apps import apps as global_apps
from django.contrib.auth.management import create_permissions
from django.db import migrations


def setup_revisao_rbac(apps, schema_editor):
    app_config = global_apps.get_app_config("governance")
    create_permissions(app_config, verbosity=0)

    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")

    revisao_perms = list(
        Permission.objects.filter(
            content_type__app_label="governance",
            codename__in=[
                "revisar_acesso",
                "abrir_campanha_revisao",
                "view_campanharevisao",
                "view_itemrevisao",
            ],
        )
    )
    perms_by_code = {p.codename: p for p in revisao_perms}

    # 1. Grupo Revisor (Gestores e donos de sistemas)
    revisor_group, _ = Group.objects.get_or_create(name="Revisor")
    revisor_perms = [
        perms_by_code[c]
        for c in ["revisar_acesso", "view_campanharevisao", "view_itemrevisao"]
        if c in perms_by_code
    ]
    revisor_group.permissions.add(*revisor_perms)

    # 2. Grupo Gestor SecOps (Abrir campanhas, auditar e visão completa)
    gestor_group = Group.objects.filter(name="Gestor SecOps").first()
    if gestor_group:
        gestor_perms = [
            perms_by_code[c]
            for c in ["abrir_campanha_revisao", "view_campanharevisao", "view_itemrevisao"]
            if c in perms_by_code
        ]
        gestor_group.permissions.add(*gestor_perms)

    # 3. Grupo Auditor (Somente leitura e relatórios)
    auditor_group = Group.objects.filter(name="Auditor").first()
    if auditor_group:
        auditor_perms = [
            perms_by_code[c]
            for c in ["view_campanharevisao", "view_itemrevisao"]
            if c in perms_by_code
        ]
        auditor_group.permissions.add(*auditor_perms)


def remove_revisao_rbac(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Group.objects.filter(name="Revisor").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("governance", "0008_colaborador_usuario_historicalcolaborador_usuario_and_more"),
    ]

    operations = [
        migrations.RunPython(setup_revisao_rbac, reverse_code=remove_revisao_rbac),
    ]
