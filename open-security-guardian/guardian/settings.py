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
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Security settings for production
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000
    # The health route is exempt from the HTTPS redirect. It is probed over
    # plain HTTP by things that are not the gateway -- the container
    # healthcheck (curl inside the container) and the integration suite on
    # 127.0.0.1:8013 -- and neither has TLS to follow the redirect to. With no
    # exemption every probe got a 301: `curl -f` counts a 301 as success, so
    # the container reported healthy with the database down, and the suite's
    # probe followed it to https://localhost:8013, found no TLS there, and
    # skipped the guardian tests as "not reachable" on every run (#532).
    # Patterns match the path without its leading slash; "health" is covered
    # too so the APPEND_SLASH redirect to health/ stays on plain HTTP.
    # The response carries only up/down status per dependency.
    #
    # The membership notice is exempt for the same reason: identity calls it
    # on the internal network, over plain HTTP, to say that a member left a
    # team (#676). Redirected, every such notice would be answered 301 to a
    # port with no TLS and lost, as the gateway's cache purge once was
    # (#475). This one route only: it is not reachable through the gateway,
    # which proxies /api/v1/ only, and it refuses a request without the
    # gateway-internal secret.
    SECURE_REDIRECT_EXEMPT = [
        r"^health/?$",
        r"^internal/team-memberships/revoke/$",
    ]
    SECURE_SSL_REDIRECT = True
    # Without this, SECURE_SSL_REDIRECT loops. TLS terminates at the gateway,
    # which proxies to guardian over plain HTTP, so Django sees an insecure
    # request and 301s to https -- to the same URL, which arrives over HTTP
    # again. Every request through the gateway became a redirect loop the moment
    # ENVIRONMENT was production. The gateway sets X-Forwarded-Proto (see
    # nginx/includes/proxy_params.conf) and is the only thing that can reach
    # this service, so the header is trustworthy here.
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SECURE = True
    CSRF_COOKIE_HTTPONLY = True
    CSRF_COOKIE_SAMESITE = 'Lax'

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
    'apps.core.gateway_middleware.GatewayAuthMiddleware',  # New: Gateway authentication
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

_database_url = os.getenv('DATABASE_URL')
if not _database_url:
    raise ValueError("DATABASE_URL environment variable must be set")
DATABASES = {
    'default': dj_database_url.parse(_database_url)
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

# WhiteNoise configuration.
# STATICFILES_STORAGE was removed in Django 5.1 and is silently ignored there:
# static files would fall back to the plain StaticFilesStorage, without the
# compressed, hashed copies WhiteNoise serves. STORAGES (Django >= 4.2) is the
# replacement; "default" has to be spelled out because setting STORAGES
# replaces Django's default for both aliases.
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
    },
}

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

# Requests one user may make per period, as DRF reads a rate, or None for
# 'off'. Parsed here, so a malformed GUARDIAN_RATE_LIMIT_USER stops guardian
# at start-up instead of answering 500 to every request (#645).
from guardian.rate_limit import user_rate  # noqa: E402

USER_RATE_LIMIT = user_rate()

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # Gateway-injected identity (no CSRF — there is no browser session).
        # SessionAuthentication was removed: it enforced CSRF and rejected
        # every gateway-authenticated write with "CSRF Failed".
        'apps.core.authentication.GatewayHeaderAuthentication',
        # Nothing else. APIKeyAuthentication accepted guardian's own key
        # rows beside the gateway (#629); identity's personal API keys,
        # validated by the gateway, are the way in for scripts.
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    # JSON. DRF's browsable API is for development only (#724): it is an
    # HTML form on every route, and in the image it answered 500 to any
    # request that asked for text/html ("Missing staticfiles manifest
    # entry": its pages link static files, the storage below wants the
    # manifest collectstatic writes, and the image never runs it). With
    # DEBUG the storage serves the files as they are and the pages work.
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ] + (
        ['rest_framework.renderers.BrowsableAPIRenderer'] if DEBUG else []
    ),
    # next/previous as relative references under the gateway's path, not
    # absolute URLs on the Host the gateway presents guardian (#643).
    'DEFAULT_PAGINATION_CLASS': 'apps.core.pagination.GatewayPageNumberPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    # One throttle, per user as the gateway names the user, at
    # GUARDIAN_RATE_LIMIT_USER (1000/hour unless set; 'off' removes it). No
    # throttle for anonymous callers: under /api/ there are none, and the
    # one it had refused the health check (#645; apps/core/throttling.py).
    'DEFAULT_THROTTLE_CLASSES': (
        ['apps.core.throttling.GatewayUserRateThrottle'] if USER_RATE_LIMIT else []
    ),
    'DEFAULT_THROTTLE_RATES': {
        'user': USER_RATE_LIMIT,
    },
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# =============================================================================
# API DOCUMENTATION CONFIGURATION
# =============================================================================

SPECTACULAR_SETTINGS = {
    'TITLE': 'Open Security Guardian API',
    'DESCRIPTION': 'Proactive Vulnerability Management Platform',
    'VERSION': '0.1.6',
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

# Store each task's name, worker and delivery queue with its result, so that
# GET /api/v1/tasks/{id}/ can report which queue a task was delivered on
# (#545). The result backend also keeps the task's arguments then; they are
# the ones already on the broker, in the same Redis, and expire with the
# result (one day). The endpoint returns the state and the queue only.
CELERY_RESULT_EXTENDED = True

# Celery Beat (scheduled tasks). guardian-beat runs the scheduler below; it
# writes CELERY_BEAT_SCHEDULE into django-celery-beat's PeriodicTask rows when
# it starts. Every entry, its default and its environment override are in
# guardian/schedule.py (#545).
from guardian.schedule import build_beat_schedule  # noqa: E402

# django-celery-beat's DatabaseScheduler, plus the heartbeat file the
# container health check reads (guardian/beat.py).
CELERY_BEAT_SCHEDULER = 'guardian.beat:HeartbeatDatabaseScheduler'
CELERY_BEAT_SCHEDULE = build_beat_schedule()

# How long a firing alert rule waits before notifying again while it keeps
# firing; None: never, only when it starts firing and when it recovers
# (#549). GUARDIAN_ALERT_RENOTIFY_INTERVAL, seconds or 'off', default one
# day; see guardian/schedule.py.
from guardian.schedule import alert_renotify_interval  # noqa: E402

ALERT_RENOTIFY_INTERVAL = alert_renotify_interval()

# How long a user stays a member of a team for guardian without acting in
# it (#676): GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS, 1 to 365, default 30;
# see guardian/schedule.py.
from guardian.schedule import team_membership_max_age  # noqa: E402

TEAM_MEMBERSHIP_MAX_AGE = team_membership_max_age()

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

# E-mail: by SMTP, or not at all (#705). EMAIL_BACKEND is not read: it
# defaulted to the console backend, which printed every notification to the
# log and reported it sent. EMAIL_HOST empty means no mail server, and a
# notification is then recorded as not sent, with that reason
# (apps.core.notifications). With a host, DEFAULT_FROM_EMAIL is required.
# Every value is checked here, at start-up: see guardian/mailconf.py.
from guardian.mailconf import (  # noqa: E402
    mail_settings,
    public_base_url,
    team_contacts_settings,
)

_mail = mail_settings()
EMAIL_BACKEND = _mail['EMAIL_BACKEND']
EMAIL_HOST = _mail['EMAIL_HOST']
EMAIL_PORT = _mail['EMAIL_PORT']
EMAIL_USE_TLS = _mail['EMAIL_USE_TLS']
EMAIL_USE_SSL = _mail['EMAIL_USE_SSL']
EMAIL_HOST_USER = _mail['EMAIL_HOST_USER']
EMAIL_HOST_PASSWORD = _mail['EMAIL_HOST_PASSWORD']
EMAIL_TIMEOUT = _mail['EMAIL_TIMEOUT']
DEFAULT_FROM_EMAIL = _mail['DEFAULT_FROM_EMAIL']

# The address users open the dashboard at (GUARDIAN_BASE_URL): what a link
# in an e-mail starts with. The SLA and assignment e-mails linked
# <BASE_URL>/vulnerabilities/<id>/, a page the dashboard does not have, and
# a relative path when this was unset (#705). A link is now built only for a
# page the dashboard serves, and only when this is set
# (apps.core.notifications.dashboard_link).
BASE_URL = public_base_url()

# Where guardian asks identity who may be e-mailed about a team, and the
# secret it presents (#705): GUARDIAN_TEAM_CONTACTS_URL, default identity's
# name on the Compose network, and GUARDIAN_CONTACTS_SECRET. guardian keeps
# no e-mail address: it mirrors identity's users by id. Without the secret
# it asks nothing, and e-mails only the addresses a team typed into an
# alert rule or a report schedule.
TEAM_CONTACTS_URL, TEAM_CONTACTS_SECRET = team_contacts_settings()

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
