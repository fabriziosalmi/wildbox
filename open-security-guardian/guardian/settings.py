"""
Django settings for Open Security Guardian

The Guardian: Proactive Vulnerability Management Platform
"""

import os
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Security settings for production
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_REDIRECT_EXEMPT = []
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# =============================================================================
# APPLICATION DEFINITION
# =============================================================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'django_filters',
    'corsheaders',
    'drf_spectacular',
    'django_celery_beat',
    'django_celery_results',
    
    # Guardian apps - ordered by dependency
    'apps.core',            # Core functionality (base classes, utilities)
    'apps.assets',          # Asset management (foundational)
    'apps.vulnerabilities', # Vulnerability management (depends on assets)
    'apps.scanners',        # Scanner integration (creates vulnerabilities)
    'apps.remediation',     # Remediation workflows (depends on vulnerabilities)
    'apps.integrations',    # External system integrations
    'apps.compliance',      # Compliance and reporting (depends on vulnerabilities)
    'apps.reporting',       # Analytics and dashboards
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'apps.core.middleware.APIKeyMiddleware',
    'apps.core.middleware.RequestLoggingMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'guardian.urls'

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

WSGI_APPLICATION = 'guardian.wsgi.application'
ASGI_APPLICATION = 'guardian.asgi.application'

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

DATABASES = {
    'default': dj_database_url.parse(
        os.getenv('DATABASE_URL', 'postgresql://guardian:guardian@localhost:5432/guardian')
    )
}

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# =============================================================================
# PASSWORD VALIDATION
# =============================================================================

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

# =============================================================================
# INTERNATIONALIZATION
# =============================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# =============================================================================
# STATIC FILES
# =============================================================================

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# WhiteNoise configuration
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# =============================================================================
# DEFAULT PRIMARY KEY FIELD TYPE
# =============================================================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# DJANGO REST FRAMEWORK CONFIGURATION
# =============================================================================

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'apps.core.authentication.APIKeyAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': os.getenv('API_RATE_LIMIT', '100/hour'),
        'user': os.getenv('API_RATE_LIMIT', '1000/hour')
    },
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# =============================================================================
# API DOCUMENTATION CONFIGURATION
# =============================================================================

SPECTACULAR_SETTINGS = {
    'TITLE': 'Open Security Guardian API',
    'DESCRIPTION': 'Proactive Vulnerability Management Platform',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'CONTACT': {
        'name': 'Wildbox Security',
        'email': 'security@wildbox.dev',
    },
    'LICENSE': {
        'name': 'MIT License',
    },
    'TAGS': [
        {'name': 'Assets', 'description': 'Asset inventory management'},
        {'name': 'Vulnerabilities', 'description': 'Vulnerability tracking and management'},
        {'name': 'Scanners', 'description': 'Vulnerability scanner integrations'},
        {'name': 'Remediation', 'description': 'Remediation workflow management'},
        {'name': 'Compliance', 'description': 'Compliance framework support'},
        {'name': 'Reports', 'description': 'Reporting and analytics'},
    ],
}

# =============================================================================
# CORS CONFIGURATION
# =============================================================================

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:80",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1",
]

CORS_ALLOW_CREDENTIALS = True

# Allow custom headers for API authentication
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'x-api-key',  # Critical for Guardian API authentication
    'api-key',
]

# =============================================================================
# CELERY CONFIGURATION
# =============================================================================

CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')
CELERY_TIMEZONE = os.getenv('CELERY_TIMEZONE', 'UTC')
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000

# Celery Beat (scheduled tasks)
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'json': {
            '()': 'apps.core.logging.JSONFormatter',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json' if LOG_FORMAT == 'json' else 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': LOG_LEVEL,
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'guardian': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
    },
}

# =============================================================================
# WILDBOX INTEGRATION SETTINGS
# =============================================================================

WILDBOX_SETTINGS = {
    'API_URL': os.getenv('WILDBOX_API_URL', 'http://localhost:8000'),
    'API_KEY': os.getenv('WILDBOX_API_KEY', ''),
    'DATA_URL': os.getenv('WILDBOX_DATA_URL', 'http://localhost:8001'),
    'DATA_API_KEY': os.getenv('WILDBOX_DATA_API_KEY', ''),
}

# =============================================================================
# SCANNER INTEGRATION SETTINGS
# =============================================================================

SCANNER_SETTINGS = {
    'NESSUS': {
        'ENABLED': os.getenv('NESSUS_ENABLED', 'false').lower() == 'true',
        'URL': os.getenv('NESSUS_URL', ''),
        'USERNAME': os.getenv('NESSUS_USERNAME', ''),
        'PASSWORD': os.getenv('NESSUS_PASSWORD', ''),
        'VERIFY_SSL': os.getenv('NESSUS_VERIFY_SSL', 'true').lower() == 'true',
    },
    'QUALYS': {
        'ENABLED': os.getenv('QUALYS_ENABLED', 'false').lower() == 'true',
        'URL': os.getenv('QUALYS_URL', ''),
        'USERNAME': os.getenv('QUALYS_USERNAME', ''),
        'PASSWORD': os.getenv('QUALYS_PASSWORD', ''),
    },
    'OPENVAS': {
        'ENABLED': os.getenv('OPENVAS_ENABLED', 'false').lower() == 'true',
        'URL': os.getenv('OPENVAS_URL', ''),
        'USERNAME': os.getenv('OPENVAS_USERNAME', ''),
        'PASSWORD': os.getenv('OPENVAS_PASSWORD', ''),
    },
    'RAPID7': {
        'ENABLED': os.getenv('RAPID7_ENABLED', 'false').lower() == 'true',
        'URL': os.getenv('RAPID7_URL', ''),
        'API_KEY': os.getenv('RAPID7_API_KEY', ''),
    },
}

# =============================================================================
# TICKETING INTEGRATION SETTINGS
# =============================================================================

TICKETING_SETTINGS = {
    'JIRA': {
        'ENABLED': os.getenv('JIRA_ENABLED', 'false').lower() == 'true',
        'URL': os.getenv('JIRA_URL', ''),
        'USERNAME': os.getenv('JIRA_USERNAME', ''),
        'API_TOKEN': os.getenv('JIRA_API_TOKEN', ''),
        'PROJECT_KEY': os.getenv('JIRA_PROJECT_KEY', 'SEC'),
    },
    'SERVICENOW': {
        'ENABLED': os.getenv('SERVICENOW_ENABLED', 'false').lower() == 'true',
        'URL': os.getenv('SERVICENOW_URL', ''),
        'USERNAME': os.getenv('SERVICENOW_USERNAME', ''),
        'PASSWORD': os.getenv('SERVICENOW_PASSWORD', ''),
    },
}

# =============================================================================
# NOTIFICATION SETTINGS
# =============================================================================

# Email settings
EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.getenv('EMAIL_HOST', '')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'true').lower() == 'true'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'guardian@wildbox.dev')

# Notification settings
NOTIFICATION_SETTINGS = {
    'SLACK': {
        'ENABLED': os.getenv('SLACK_ENABLED', 'false').lower() == 'true',
        'WEBHOOK_URL': os.getenv('SLACK_WEBHOOK_URL', ''),
        'CHANNEL': os.getenv('SLACK_CHANNEL', '#security-alerts'),
    },
    'TEAMS': {
        'ENABLED': os.getenv('TEAMS_ENABLED', 'false').lower() == 'true',
        'WEBHOOK_URL': os.getenv('TEAMS_WEBHOOK_URL', ''),
    },
}

# =============================================================================
# COMPLIANCE FRAMEWORK SETTINGS
# =============================================================================

COMPLIANCE_SETTINGS = {
    'DEFAULT_FRAMEWORKS': os.getenv('DEFAULT_COMPLIANCE_FRAMEWORKS', 
                                  'PCI_DSS,SOX,HIPAA,ISO27001,NIST_CSF').split(','),
}

# =============================================================================
# RISK CALCULATION SETTINGS
# =============================================================================

RISK_CALCULATION_SETTINGS = {
    'METHOD': os.getenv('RISK_CALCULATION_METHOD', 'advanced'),
    'WEIGHTS': {
        'THREAT_INTEL': float(os.getenv('THREAT_INTEL_WEIGHT', '0.3')),
        'ASSET_CRITICALITY': float(os.getenv('ASSET_CRITICALITY_WEIGHT', '0.4')),
        'CVSS': float(os.getenv('CVSS_WEIGHT', '0.3')),
        'EXPLOITABILITY': float(os.getenv('EXPLOITABILITY_WEIGHT', '0.2')),
    },
}

# =============================================================================
# PERFORMANCE SETTINGS
# =============================================================================

PERFORMANCE_SETTINGS = {
    'MAX_CONCURRENT_SCANS': int(os.getenv('MAX_CONCURRENT_SCANS', '5')),
    'SCAN_TIMEOUT_SECONDS': int(os.getenv('SCAN_TIMEOUT_SECONDS', '3600')),
    'BULK_OPERATIONS_BATCH_SIZE': int(os.getenv('BULK_OPERATIONS_BATCH_SIZE', '1000')),
    'CACHE_TIMEOUT_SECONDS': int(os.getenv('CACHE_TIMEOUT_SECONDS', '3600')),
}

# Database connection pooling
DATABASES['default']['CONN_MAX_AGE'] = int(os.getenv('DATABASE_CONN_MAX_AGE', '300'))

# =============================================================================
# MONITORING SETTINGS
# =============================================================================

# Sentry integration
SENTRY_DSN = os.getenv('SENTRY_DSN')
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(auto_enabling=True),
            CeleryIntegration(monitor_beat_tasks=True),
        ],
        environment=os.getenv('SENTRY_ENVIRONMENT', 'development'),
        traces_sample_rate=0.1,
        send_default_pii=False,
    )

# Prometheus metrics
PROMETHEUS_ENABLED = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'

# =============================================================================
# DEVELOPMENT SETTINGS
# =============================================================================

if DEBUG:
    # Additional apps for development
    INSTALLED_APPS += [
        'django_extensions',
    ]
    
    # Debug toolbar
    try:
        import debug_toolbar
        INSTALLED_APPS.append('debug_toolbar')
        MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
        INTERNAL_IPS = ['127.0.0.1', 'localhost']
    except ImportError:
        pass
