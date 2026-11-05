"""
Comando para provisionamento rápido de conta master (estilo root) para desenvolvimento.

Protegido para execução exclusiva em ambiente local (DEBUG=True).
Uso:
    python manage.py create_root
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.conf import settings

User = get_user_model()


class Command(BaseCommand):
    help = "Cria ou redefine o usuário master 'root' para desenvolvimento local."

    def handle(self, *args, **options):
        if not settings.DEBUG:
            self.stderr.write(self.style.ERROR("❌ ERRO DE SEGURANÇA: Este comando é restrito ao ambiente de desenvolvimento (DEBUG=True)."))
            return

        username = "root"
        password = "RootDev2026!"
        email = "root@gatekeeper.local"

        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email,
                "is_staff": True,
                "is_superuser": True,
            }
        )
        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()

        gestor_group = Group.objects.filter(name="Gestor SecOps").first()
        if gestor_group:
            user.groups.add(gestor_group)

        action = "criado" if created else "redefinido"
        self.stdout.write(self.style.SUCCESS(f"✅ Usuário master '{username}' {action} com sucesso!"))
        self.stdout.write(f"   • Usuário: {username}")
        self.stdout.write(f"   • Senha:   {password}")
        self.stdout.write("   • Acesso:  Superuser (bypass total de permissões / estilo root)")

