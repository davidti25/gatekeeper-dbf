"""
Cria a tabela do cache em banco (CACHES padrão `dbcache://gatekeeper_cache`).

Sem ela o rate limit do login (allauth) e a marcação de códigos TOTP já usados falham com
"no such table". Rodar aqui garante que `migrate` sozinho deixa o sistema funcional em
qualquer ambiente (local, CI, deploy manual), não só no compose. Para cache Redis é no-op.
"""

from django.core.management import call_command
from django.db import migrations


def criar_tabela_cache(apps, schema_editor):
    call_command("createcachetable", database=schema_editor.connection.alias, verbosity=0)


class Migration(migrations.Migration):
    dependencies = [
        ("governance", "0006_remove_change_perms_from_analista_ti"),
    ]

    operations = [
        migrations.RunPython(criar_tabela_cache, reverse_code=migrations.RunPython.noop),
    ]
