from django.db import migrations


def remove_change_permissions(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    try:
        analista_group = Group.objects.get(name='Analista TI')
        perms_to_remove = Permission.objects.filter(
            content_type__app_label='governance',
            codename__in=[
                'change_processooffboarding',
                'change_itemchecklistoffboarding',
            ]
        )
        analista_group.permissions.remove(*perms_to_remove)
    except Group.DoesNotExist:
        pass


def restore_change_permissions(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    try:
        analista_group = Group.objects.get(name='Analista TI')
        perms_to_add = Permission.objects.filter(
            content_type__app_label='governance',
            codename__in=[
                'change_processooffboarding',
                'change_itemchecklistoffboarding',
            ]
        )
        analista_group.permissions.add(*perms_to_add)
    except Group.DoesNotExist:
        pass


class Migration(migrations.Migration):

    dependencies = [
        ('governance', '0005_alter_itemchecklistoffboarding_options'),
    ]

    operations = [
        migrations.RunPython(remove_change_permissions, reverse_code=restore_change_permissions),
    ]
