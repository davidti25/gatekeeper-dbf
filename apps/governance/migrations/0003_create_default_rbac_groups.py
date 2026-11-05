from django.db import migrations
from django.contrib.auth.management import create_permissions
from django.apps import apps as global_apps


def create_rbac_groups(apps, schema_editor):
    # Garante que as permissões dos modelos foram criadas antes de vincular aos grupos
    app_config = global_apps.get_app_config('governance')
    create_permissions(app_config, verbosity=0)

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    governance_models = [
        'colaborador',
        'departamento',
        'localidade',
        'cargo',
        'sistema',
        'perfilacesso',
        'vinculoacesso',
        'processooffboarding',
        'itemchecklistoffboarding',
    ]

    # Permissões de visualização (Leitura / Auditoria)
    view_perms = list(Permission.objects.filter(
        content_type__app_label='governance',
        content_type__model__in=governance_models,
        codename__startswith='view_'
    ))

    # 1. Grupo Auditor (Somente leitura e emissão de relatórios)
    auditor_group, _ = Group.objects.get_or_create(name='Auditor')
    auditor_group.permissions.set(view_perms)

    # 2. Grupo Analista TI (Auditor + iniciar offboarding + revogar itens do checklist)
    analista_group, _ = Group.objects.get_or_create(name='Analista TI')
    analista_perms = list(view_perms)
    exec_perms = list(Permission.objects.filter(
        content_type__app_label='governance',
        codename__in=[
            'iniciar_offboarding',
            'revogar_item_offboarding',
            'change_processooffboarding',
            'change_itemchecklistoffboarding',
            'change_vinculoacesso',
            'change_colaborador',
        ]
    ))
    analista_perms.extend(exec_perms)
    analista_group.permissions.set(analista_perms)

    # 3. Grupo Gestor SecOps (Todas as permissões do app governance)
    gestor_group, _ = Group.objects.get_or_create(name='Gestor SecOps')
    all_governance_perms = list(Permission.objects.filter(
        content_type__app_label='governance'
    ))
    gestor_group.permissions.set(all_governance_perms)


def remove_rbac_groups(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name__in=['Auditor', 'Analista TI', 'Gestor SecOps']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('governance', '0002_alter_processooffboarding_options'),
    ]

    operations = [
        migrations.RunPython(create_rbac_groups, reverse_code=remove_rbac_groups),
    ]
