"""
Django settings for myproject project.
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# MongoDB ayarları - En üstte tanımlayalım
MONGODB_SETTINGS = {
    'URI': 'mongodb://localhost:27017',
    'NAME': 'trafik_kaza'
}

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-ybfnkx((#002uel-ey-cat6i8=4y@)9l4-jr!qv+pwycey7wd_'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'myapp',
    'django_bootstrap5',
    'crispy_forms',
    'crispy_bootstrap5',
] 

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'myapp.context_processors.user_data',
            ],
        },
    },
]

# Static dosyalar için
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
] 

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Authentication kısmını kaldır veya yorum satırına al
# AUTHENTICATION_BACKENDS = [
#     'django.contrib.auth.backends.ModelBackend',
# ]

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# CSRF ayarları
CSRF_COOKIE_SECURE = False  # Development için False yapıyoruz
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_TRUSTED_ORIGINS = ['http://localhost:8000', 'http://127.0.0.1:8000']

# Cookie ayarları
CSRF_COOKIE_NAME = 'ttka_csrftoken'

# Database ayarları
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

# Middleware listesi
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Message framework ayarları
MESSAGE_STORAGE = 'django.contrib.messages.storage.cookie.CookieStorage' 

# Crispy Forms ayarı
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK = "bootstrap5" 

# Authentication settings
LOGIN_URL = 'giris'  # login view'inizin name'i
LOGIN_REDIRECT_URL = 'index'  # Başarılı girişten sonra yönlendirilecek sayfa
LOGOUT_REDIRECT_URL = 'index'  # Çıkış yapıldıktan sonra yönlendirilecek sayfa 

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
} 