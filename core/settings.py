"""
Django settings for GateKeeper-DBF project.

Configurações blindadas segundo recomendações OWASP e CIS Controls.
Variáveis sensíveis carregadas via django-environ (.env).
"""

from pathlib import Path
import environ
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Inicialização do gerenciador de variáveis de ambiente
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ['127.0.0.1', 'localhost']),
    SESSION_COOKIE_SECURE=(bool, False),
    CSRF_COOKIE_SECURE=(bool, False),
    SECURE_SSL_REDIRECT=(bool, False),
)

# Carrega o arquivo .env se existir
env_file = BASE_DIR / '.env'
if env_file.is_file():
    environ.Env.read_env(env_file)

# Chave secreta da aplicação (NUNCA expor em repositórios)
SECRET_KEY = env('SECRET_KEY')

# Modo de depuração (False por padrão em produção)
DEBUG = env('DEBUG')

ALLOWED_HOSTS = env('ALLOWED_HOSTS')
if 'testserver' not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append('testserver')

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Auditoria de Alterações e Snapshots de Versão (CIS 5.5 / LGPD)
    'simple_history',

    # Módulos Internos do GateKeeper-DBF
    'apps.governance',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Middleware para capturar o usuário que realizou a alteração no histórico
    'simple_history.middleware.HistoryRequestMiddleware',
]

# Autenticação & Redirecionamentos (Secure by Default)
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': env.db('DATABASE_URL', default=f'sqlite:///{BASE_DIR / "db.sqlite3"}')
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # Hardening de complexidade (CIS Controls / NIST)
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization & Localização (PT-BR)
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'pt-br'

TIME_ZONE = 'America/Bahia'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images) & Mídia
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ==============================================================================
# Hardening de Segurança (OWASP Top 10 & CIS Controls)
# ==============================================================================

# Proteção contra Clickjacking
X_FRAME_OPTIONS = 'DENY'

# Proteção contra MIME-Sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# Proteção XSS legada do navegador
SECURE_BROWSER_XSS_FILTER = True

# Segurança de Cookies de Sessão e CSRF
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = env('SESSION_COOKIE_SECURE')
CSRF_COOKIE_SECURE = env('CSRF_COOKIE_SECURE')

# Redirecionamento HTTPS
SECURE_SSL_REDIRECT = env('SECURE_SSL_REDIRECT')
