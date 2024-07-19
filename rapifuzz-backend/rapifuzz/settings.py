"""
Django settings for rapifuzz project.
"""

import os
#  for python version 311
import tomllib
#  for python version below 311
import toml
from datetime import timedelta

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR,'templates/')
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.db.backends.mysql',
    "drf_standardized_errors",
    'user_auth',
    'discovery',
    'fuzzer',
    'individual',#for single api
    'rest_framework',
    'drf_yasg',
    'corsheaders',
    'license',
    'rest_framework_simplejwt' ,
    'rest_framework_simplejwt.token_blacklist',
    'reports'

]


SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=72),
    'REFRESH_TOKEN_LIFETIME': timedelta(hours=96),
    'ROTATE_REFRESH_TOKENS': True,
    'USER_ID_FIELD': 'uu_id',
    'BLACKLIST_AFTER_ROTATION': True,
    'ISSUER':'RAPIFuzz',
    'USER_ID_CLAIM':'id',
}

PASSWORD_HASHERS = ['fuzzer.components.authbackend.CustomPasswordHasher',]

SWAGGER_SETTINGS = {
   'USE_SESSION_AUTH': False,
   'SECURITY_DEFINITIONS': {
      'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
      }
   }
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'fuzzer.components.loggingmiddleware.LogRestMiddleware',
    'license.middleware.BaseMiddleware',
    'fuzzer.components.headersmiddleware.SecurityHeaders',
    'fuzzer.components.authtoken.TokenBlacklistMiddleware',
]

ROOT_URLCONF = 'rapifuzz.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [TEMPLATE_DIR,],
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


WSGI_APPLICATION = 'rapifuzz.wsgi.application'

# Database
DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_PORT = os.environ.get('DB_PORT')
LICENSE_KEY = os.environ.get('LICENSE_KEY')
RSA_KEY = os.environ.get('RSA_KEY', "<RSAKeyValue><Modulus>yJdndsoHiNEmQ+PUprbipZrOIHlHK1OVe3xCqgDYm744q4JKZ3S4Z3iauoyWDKjIAtpuwLyDSoxRoMTF6SFVf7byr4MIK2TiyEwKL1qSbFklCC0/y9IyUcushh3GKc2vgoZuh2Iw3OvqQP6x16ZuIM+nl/vet7B242HQ6BAQerGOab+03lVBIqgEADfGS2/uH/H6iBZ3E+plF5Oy2X+aC/MMIzXVIj80ZYnnNIJXWmPkoDoYbI0xTQ4gje2+bQ/6CNb9PthPJiyI7EKT99ubmW+1T3OyRH3yik6stnGDJTwDngVPgmEymBPAoQsCiusGWO6KA5y2hvX8qNkmmuPFCw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>")
PRODUCT_KEY = os.environ.get('PRODUCT_KEY',"13969")
AUTH = os.environ.get("AUTH","WyIxMTQ1ODgzIiwiRjhaT3M2bUJyeUVIV1Zsa2F6STVucFppQTg5L0pCZFM5SW5NTmtlaCJd")
LICENSE_HOST = os.environ.get('LICENSE_HOST')
if os.environ.get("ENVIRONMENT") == "development" or os.environ.get("ENVIRONMENT") == "qa":
    LICENSE_KILLSWITCH = True
else:
    LICENSE_KILLSWITCH = False    
"""
vendor_code and feature_id are global parameter which will be set in environment varialble.
"""
VENDOR_CODE = os.environ.get("VENDOR_CODE",  b"AzIceaqfA1hX5wS+M8cGnYh5ceevUnOZIzJBbXFD6dgf3tBkb9cvUF/Tkd/iKu2fsg9wAysYKw7RMAsVvIp4KcXle/v1RaXrLVnNBJ2H2DmrbUMOZbQUFXe698qmJsqNpLXRA367xpZ54i8kC5DTXwDhfxWTOZrBrh5sRKHcoVLumztIQjgWh37AzmSd1bLOfUGI0xjAL9zJWO3fRaeB0NS2KlmoKaVT5Y04zZEc06waU2r6AU2Dc4uipJqJmObqKM+tfNKAS0rZr5IudRiC7pUwnmtaHRe5fgSI8M7yvypvm+13Wm4Gwd4VnYiZvSxf8ImN3ZOG9wEzfyMIlH2+rKPUVHI+igsqla0Wd9m7ZUR9vFotj1uYV0OzG7hX0+huN2E/IdgLDjbiapj1e2fKHrMmGFaIvI6xzzJIQJF9GiRZ7+0jNFLKSyzX/K3JAyFrIPObfwM+y+zAgE1sWcZ1YnuBhICyRHBhaJDKIZL8MywrEfB2yF+R3k9wFG1oN48gSLyfrfEKuB/qgNp+BeTruWUk0AwRE9XVMUuRbjpxa4YA67SKunFEgFGgUfHBeHJTivvUl0u4Dki1UKAT973P+nXy2O0u239If/kRpNUVhMg8kpk7s8i6Arp7l/705/bLCx4kN5hHHSXIqkiG9tHdeNV8VYo5+72hgaCx3/uVoVLmtvxbOIvo120uTJbuLVTvT8KtsOlb3DxwUrwLzaEMoAQAFk6Q9bNipHxfkRQER4kR7IYTMzSoW5mxh3H9O8Ge5BqVeYMEW36q9wnOYfxOLNw6yQMf8f9sJN4KhZty02xm707S7VEfJJ1KNq7b5pP/3RjE0IKtB2gE6vAPRvRLzEohu0m7q1aUp8wAvSiqjZy7FLaTtLEApXYvLvz6PEJdj4TegCZugj7c8bIOEqLXmloZ6EgVnjQ7/ttys7VFITB3mazzFiyQuKf4J6+b/a/Y")#Feature ID duration represent the expiry date time feature and product represent execution
FEATURE_ID = os.environ.get("FEATURE_ID", {"enterprise": 2023, "project": 2024, "individual-api": 3024})

DATABASES = {
   'default': {
      'ENGINE': 'dj_db_conn_pool.backends.mysql',
      'HOST': DB_HOST,
      'NAME': DB_NAME,
      'USER': DB_USER,
      'PASSWORD': DB_PASSWORD,
      'PORT': DB_PORT,
      'CONN_MAX_AGE': 1800,
      'POOL_OPTIONS' : {
            'POOL_SIZE': 20,
            'MAX_OVERFLOW': -1,
            'RECYCLE': 24 * 60 * 60,
        },
      'OPTIONS': {
            'charset': 'utf8mb4',  # This is the important line
            "init_command": "SET GLOBAL max_allowed_packet = 64*1024*1024",
        },
  }
}

# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


DRF_STANDARDIZED_ERRORS = {
                            "ENABLE_IN_DEBUG_FOR_UNHANDLED_EXCEPTIONS": True,
                            "EXCEPTION_HANDLER_CLASS": "exception_handling.exception_formatter.CustomExceptionHandler",
                            "EXCEPTION_FORMATTER_CLASS": "exception_handling.exception_formatter.CustomExceptionFormatter",
                            }


REST_FRAMEWORK = {
    'DEFAULT_FILTER_BACKENDS': ['django_filters.rest_framework.DjangoFilterBackend'],
    'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework_simplejwt.authentication.JWTAuthentication',],
    'DATETIME_FORMAT': "%d-%b-%Y %H:%M:%S",
    "EXCEPTION_HANDLER": "drf_standardized_errors.handler.exception_handler"
}


CORS_ALLOW_ALL_ORIGINS  = True

# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = '/static/'
MEDIA_URL = '/media/'

#SMTP settings
EMAIL_BACKEND  = 'django.core.mail.backends.smtp.EmailBackend'

#Custom User Backend
AUTH_USER_MODEL = "user_auth.User"
AUTHENTICATION_BACKENDS = [
                            "fuzzer.components.authbackend.CustomUserModelBackend",
                            "django.contrib.auth.backends.ModelBackend",
                           ]

# Creating a superuser  
DJANGO_SUPERUSER_USERNAME = os.environ.get('DJANGO_SUPERUSER_USERNAME')
DJANGO_SUPERUSER_EMAIL = os.environ.get('DJANGO_SUPERUSER_EMAIL')
DJANGO_SUPERUSER_PASSWORD = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
DJANGO_SUPERUSER_IS_ACTIVE = os.environ.get('DJANGO_SUPERUSER_IS_ACTIVE')
DJANGO_SUPERUSER_EMAIL_VERIFIED = os.environ.get('DJANGO_SUPERUSER_EMAIL_VERIFIED')
DJANGO_SUPERUSER_SECRET_KEY = os.environ.get('DJANGO_SUPERUSER_SECRET')
DJANGO_SUPERUSER_NAME = "admin"
DJANGO_SUPERUSER_ROLE = "ROLE_ADMIN"


DATA_UPLOAD_MAX_MEMORY_SIZE = 1024*1024*1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 200*1024*1024*1024

# LOGGING CONFIGURATION USING TOML FILE
LOGGING_CONFIG_DIR =  os.getcwd() +"/config.toml"
if DEBUG:
    LOGGING_CONFIG_DIR = os.getcwd()+"/text_log.toml"
# for python version 311
with open(LOGGING_CONFIG_DIR, "rb") as f:
    CUSTOM_LOG_CONFIG = tomllib.load(f)

# for python version below 311
# CUSTOM_LOG_CONFIG =toml.load(LOGGING_CONFIG_DIR)

LOGGING=CUSTOM_LOG_CONFIG

# Using cache for caching testing thread objects.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "CacheTable",
    }
}
