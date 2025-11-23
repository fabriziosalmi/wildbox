"""
Celery worker for asynchronous CSPM scans
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import traceback

from celery import Celery
from celery.signals import worker_ready, worker_shutting_down
import boto3
from google.auth import default as gcp_default
from azure.identity import DefaultAzureCredential

from .config import settings
from .checks.runner import check_runner
from .checks.framework import CloudProvider, ScanReport
from . import schemas

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format=settings.log_format
)
logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "csmp-worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.worker"]
)

# Configure Celery
celery_app.conf.update(
    task_serializer=settings.celery_task_serializer,
    accept_content=settings.celery_accept_content,
    result_serializer=settings.celery_result_serializer,
    timezone=settings.celery_timezone,
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.scan_timeout_seconds,
    task_soft_time_limit=settings.scan_timeout_seconds - 60,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=100,
)


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Called when worker is ready to receive tasks."""
    logger.info("CSPM Worker is ready to process scans")


@worker_shutting_down.connect
def worker_shutting_down_handler(sender=None, **kwargs):
    """Called when worker is shutting down."""
    logger.info("CSPM Worker is shutting down")


class CloudSessionManager:
    """Manages cloud provider session creation and authentication."""
    
    @staticmethod
    def create_aws_session(credentials: Dict[str, Any]) -> boto3.Session:
        """Create AWS session from credentials."""
        auth_method = credentials.get("auth_method", "access_key")
        
        if auth_method == "access_key":
            return boto3.Session(
                aws_access_key_id=credentials["access_key_id"],
                aws_secret_access_key=credentials["secret_access_key"],
                region_name=credentials.get("region", "us-east-1")
            )
        elif auth_method == "assume_role":
            # Create session with base credentials
            base_session = boto3.Session(
                aws_access_key_id=credentials["access_key_id"],
                aws_secret_access_key=credentials["secret_access_key"]
            )
            
            # Assume role
            sts_client = base_session.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=credentials["role_arn"],
                RoleSessionName=f"wildbox-cspm-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            )
            
            assumed_credentials = assumed_role['Credentials']
            return boto3.Session(
                aws_access_key_id=assumed_credentials['AccessKeyId'],
                aws_secret_access_key=assumed_credentials['SecretAccessKey'],
                aws_session_token=assumed_credentials['SessionToken'],
                region_name=credentials.get("region", "us-east-1")
            )
        else:
            raise ValueError(f"Unsupported AWS auth method: {auth_method}")
    
    @staticmethod
    def create_gcp_session(credentials: Dict[str, Any]):
        """Create GCP session from credentials."""
        # This would be implemented based on GCP SDK requirements
        # For now, placeholder implementation
        raise NotImplementedError("GCP session creation not yet implemented")
    
    @staticmethod
    def create_azure_session(credentials: Dict[str, Any]):
        """Create Azure session from credentials."""
        # This would be implemented based on Azure SDK requirements
        # For now, placeholder implementation
        raise NotImplementedError("Azure session creation not yet implemented")


@celery_app.task(bind=True, name="run_cspm_scan")
def run_cspm_scan_task(
    self,
    scan_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a CSPM scan asynchronously.
    
    Args:
        scan_config: Dictionary containing scan configuration:
            - provider: Cloud provider ('aws', 'gcp', 'azure')
            - credentials: Provider-specific credentials
            - account_id: Cloud account identifier
            - account_name: Optional friendly name
            - regions: Optional list of regions to scan
            - check_ids: Optional list of specific checks to run
            - metadata: Additional metadata for the scan
    
    Returns:
        Dictionary containing scan results and metadata
    """
    scan_id = self.request.id
    provider_str = scan_config["provider"]
    
    logger.info(f"Starting CSPM scan {scan_id} for {provider_str}")
    
    try:
        # Validate provider
        try:
            provider = CloudProvider(provider_str)
        except ValueError:
            raise ValueError(f"Unsupported cloud provider: {provider_str}")
        
        # Create cloud session
        session = _create_cloud_session(provider, scan_config["credentials"])
        
        # Extract scan parameters
        account_id = scan_config["account_id"]
        account_name = scan_config.get("account_name")
        regions = scan_config.get("regions")
        check_ids = scan_config.get("check_ids")
        
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={
                "status": "initializing",
                "provider": provider_str,
                "account_id": account_id,
                "started_at": datetime.utcnow().isoformat()
            }
        )
        
        # Run the scan using asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            report = loop.run_until_complete(
                check_runner.run_scan(
                    provider=provider,
                    session=session,
                    account_id=account_id,
                    account_name=account_name,
                    regions=regions,
                    check_ids=check_ids
                )
            )
        finally:
            loop.close()
        
        # Convert report to dict for serialization
        report_dict = report.model_dump()
        
        # Update task state
        self.update_state(
            state="SUCCESS",
            meta={
                "status": "completed",
                "provider": provider_str,
                "account_id": account_id,
                "scan_id": scan_id,
                "completed_at": datetime.utcnow().isoformat(),
                "total_checks": report.total_checks,
                "failed_checks": report.failed_checks,
                "compliance_score": report.compliance_score
            }
        )
        
        logger.info(
            f"CSMP scan {scan_id} completed: "
            f"{report.passed_checks} passed, {report.failed_checks} failed"
        )
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "report": report_dict,
            "metadata": scan_config.get("metadata", {})
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        error_msg = str(e)
        error_traceback = traceback.format_exc()
        
        logger.error(f"CSMP scan {scan_id} failed: {error_msg}")
        logger.debug(f"Traceback: {error_traceback}")
        
        # Update task state
        self.update_state(
            state="FAILURE",
            meta={
                "status": "failed",
                "provider": provider_str,
                "account_id": scan_config.get("account_id", "unknown"),
                "error": error_msg,
                "error_traceback": error_traceback,
                "failed_at": datetime.utcnow().isoformat()
            }
        )
        
        # Re-raise to mark task as failed
        raise


def _create_cloud_session(provider: CloudProvider, credentials: Dict[str, Any]):
    """Create a cloud provider session based on provider and credentials."""
    if provider == CloudProvider.AWS:
        return CloudSessionManager.create_aws_session(credentials)
    elif provider == CloudProvider.GCP:
        return CloudSessionManager.create_gcp_session(credentials)
    elif provider == CloudProvider.AZURE:
        return CloudSessionManager.create_azure_session(credentials)
    else:
        raise ValueError(f"Unsupported provider: {provider}")


@celery_app.task(name="get_available_checks")
def get_available_checks_task(provider: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get available security checks.
    
    Args:
        provider: Optional provider filter
        
    Returns:
        List of available checks metadata
    """
    try:
        provider_enum = CloudProvider(provider) if provider else None
        return check_runner.get_available_checks(provider_enum)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get available checks: {e}")
        raise


@celery_app.task(name="health_check")
def health_check_task() -> Dict[str, Any]:
    """Health check task for monitoring worker status."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "worker_id": f"{celery_app.control.inspect().stats()}",
        "available_providers": [p.value for p in CloudProvider]
    }


# Periodic tasks (if using celery-beat)
celery_app.conf.beat_schedule = {
    "health-check": {
        "task": "health_check",
        "schedule": 300.0,  # Every 5 minutes
    },
}


if __name__ == "__main__":
    # For running worker directly
    celery_app.start()
