"""
Utility functions for Open Security Guardian
"""

import logging
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import timezone
import uuid

logger = logging.getLogger(__name__)


def send_notification(subject, template, context, notification_type='general', recipients=None):
    """
    Send notification via configured channels
    
    Args:
        subject: Email subject
        template: Template path for notification content
        context: Template context data
        notification_type: Type of notification (general, alert, report, etc.)
        recipients: List of email recipients (optional)
    
    Returns:
        bool: True if notification sent successfully
    """
    try:
        # Render email content
        html_content = render_to_string(template, context)
        
        # Get recipients
        if not recipients:
            recipients = getattr(settings, 'DEFAULT_NOTIFICATION_RECIPIENTS', [])
        
        if not recipients:
            logger.warning(f"No recipients configured for notification: {subject}")
            return False
            
        # Send email
        send_mail(
            subject=subject,
            message=html_content,
            html_message=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )
        
        logger.info(f"Notification sent: {subject} to {len(recipients)} recipients")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send notification '{subject}': {str(e)}")
        return False


def generate_api_key():
    """
    Generate a secure API key
    """
    return f"gsk_{uuid.uuid4().hex}"


def validate_ip_address(ip):
    """
    Validate IP address format
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_hostname(hostname):
    """
    Validate hostname format
    """
    import re
    
    if len(hostname) > 253:
        return False
    
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    
    allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    return all(allowed.match(x) for x in hostname.split("."))


def sanitize_input(data):
    """
    Sanitize input data to prevent injection attacks
    """
    if isinstance(data, str):
        # Basic HTML/script tag removal
        import re
        data = re.sub(r'<[^>]*>', '', data)
        data = data.replace('<', '&lt;').replace('>', '&gt;')
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    
    return data


def calculate_risk_score(vulnerability):
    """
    Calculate risk score for vulnerability
    
    Args:
        vulnerability: Vulnerability instance
        
    Returns:
        float: Risk score between 0-10
    """
    # Base score from CVSS
    base_score = getattr(vulnerability, 'cvss_score', 5.0)
    
    # Asset criticality multiplier
    asset_multiplier = 1.0
    if hasattr(vulnerability, 'asset') and vulnerability.asset:
        if vulnerability.asset.criticality == 'critical':
            asset_multiplier = 1.5
        elif vulnerability.asset.criticality == 'high':
            asset_multiplier = 1.3
        elif vulnerability.asset.criticality == 'medium':
            asset_multiplier = 1.1
    
    # Environment multiplier
    env_multiplier = 1.0
    if hasattr(vulnerability, 'asset') and vulnerability.asset:
        if vulnerability.asset.environment == 'production':
            env_multiplier = 1.4
        elif vulnerability.asset.environment == 'staging':
            env_multiplier = 1.2
    
    # Exploitability factor
    exploit_multiplier = 1.0
    if hasattr(vulnerability, 'exploitability'):
        if vulnerability.exploitability == 'high':
            exploit_multiplier = 1.3
        elif vulnerability.exploitability == 'medium':
            exploit_multiplier = 1.1
    
    # Calculate final score
    risk_score = base_score * asset_multiplier * env_multiplier * exploit_multiplier
    
    # Cap at 10.0
    return min(risk_score, 10.0)


def get_severity_from_score(score):
    """
    Get severity level from numeric score
    
    Args:
        score: Numeric score (0-10)
        
    Returns:
        str: Severity level
    """
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    else:
        return 'low'


def format_duration(duration):
    """
    Format duration for human-readable display
    
    Args:
        duration: timedelta object
        
    Returns:
        str: Formatted duration string
    """
    if not duration:
        return "N/A"
    
    total_seconds = int(duration.total_seconds())
    
    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes}m {seconds}s"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        return f"{days}d {hours}h"


def format_file_size(size_bytes):
    """
    Format file size for human-readable display
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        str: Formatted size string
    """
    if not size_bytes:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    
    return f"{size_bytes:.1f} PB"


def get_client_ip(request):
    """
    Get client IP address from request
    
    Args:
        request: Django request object
        
    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_safe_url(url, allowed_hosts=None):
    """
    Check if URL is safe for redirects
    
    Args:
        url: URL to check
        allowed_hosts: List of allowed host names
        
    Returns:
        bool: True if URL is safe
    """
    from urllib.parse import urlparse
    
    if not url:
        return False
    
    try:
        parsed = urlparse(url)
        
        # Allow relative URLs
        if not parsed.netloc:
            return True
        
        # Check against allowed hosts
        if allowed_hosts and parsed.netloc not in allowed_hosts:
            return False
        
        # Block dangerous schemes
        if parsed.scheme not in ('http', 'https'):
            return False
        
        return True
        
    except Exception:
        return False


def mask_sensitive_data(data, fields=None):
    """
    Mask sensitive data in dictionaries/objects
    
    Args:
        data: Data to mask
        fields: List of field names to mask
        
    Returns:
        dict: Data with sensitive fields masked
    """
    if not fields:
        fields = ['password', 'token', 'key', 'secret', 'api_key']
    
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if any(field in key.lower() for field in fields):
                masked[key] = '*' * 8
            elif isinstance(value, (dict, list)):
                masked[key] = mask_sensitive_data(value, fields)
            else:
                masked[key] = value
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_data(item, fields) for item in data]
    
    return data


class RateLimiter:
    """
    Simple rate limiter utility
    """
    
    def __init__(self, max_requests=100, window_seconds=3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    def is_allowed(self, identifier):
        """
        Check if request is allowed for identifier
        
        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            
        Returns:
            bool: True if request is allowed
        """
        now = timezone.now().timestamp()
        
        # Clean old entries
        self.requests = {
            k: v for k, v in self.requests.items() 
            if now - v['first_request'] < self.window_seconds
        }
        
        if identifier not in self.requests:
            self.requests[identifier] = {
                'count': 1,
                'first_request': now
            }
            return True
        
        request_data = self.requests[identifier]
        
        if now - request_data['first_request'] >= self.window_seconds:
            # Reset window
            self.requests[identifier] = {
                'count': 1,
                'first_request': now
            }
            return True
        
        if request_data['count'] >= self.max_requests:
            return False
        
        request_data['count'] += 1
        return True
