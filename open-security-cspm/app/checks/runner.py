"""
Check runner for executing security scans
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Type
from datetime import datetime
import importlib
import inspect
import pkgutil

from .framework import (
    BaseCheck, ScanReport, CheckResult, CloudProvider, 
    CheckStatus, check_registry
)
from ..config import settings


logger = logging.getLogger(__name__)


class CheckRunner:
    """Runner for executing security checks against cloud resources."""
    
    def __init__(self):
        self.loaded_checks: Dict[CloudProvider, List[BaseCheck]] = {}
        self._load_all_checks()
    
    def _load_all_checks(self):
        """Dynamically load all security checks from provider modules."""
        providers = ["aws", "gcp", "azure"]
        
        for provider in providers:
            try:
                self._load_provider_checks(provider)
            except Exception as e:
                logger.error(f"Failed to load checks for provider {provider}: {e}")
    
    def _load_provider_checks(self, provider: str):
        """Load all checks for a specific provider."""
        try:
            # Import the provider module
            provider_module = importlib.import_module(f"app.checks.{provider}")
            
            # Get all check classes from the module and its submodules
            check_classes = self._find_check_classes(provider_module, provider)
            
            # Instantiate and register checks
            provider_enum = CloudProvider(provider)
            self.loaded_checks[provider_enum] = []
            
            for check_class in check_classes:
                try:
                    check_instance = check_class()
                    check_registry.register(check_instance)
                    self.loaded_checks[provider_enum].append(check_instance)
                    logger.info(f"Loaded check: {check_instance.metadata.check_id}")
                except Exception as e:
                    logger.error(f"Failed to instantiate check {check_class.__name__}: {e}")
                    
        except ImportError as e:
            logger.warning(f"Provider module {provider} not found: {e}")
    
    def _find_check_classes(self, module, provider: str) -> List[Type[BaseCheck]]:
        """Find all BaseCheck subclasses in a module and its submodules."""
        check_classes = []
        
        # Check the current module
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BaseCheck) and 
                obj != BaseCheck and 
                hasattr(obj, 'get_metadata')):
                check_classes.append(obj)
        
        # Check submodules
        if hasattr(module, '__path__'):
            for importer, modname, ispkg in pkgutil.iter_modules(module.__path__):
                try:
                    submodule = importlib.import_module(f"app.checks.{provider}.{modname}")
                    check_classes.extend(self._find_check_classes(submodule, provider))
                except Exception as e:
                    logger.error(f"Failed to load submodule {modname}: {e}")
        
        return check_classes
    
    async def run_scan(
        self,
        provider: CloudProvider,
        session: Any,
        account_id: str,
        account_name: Optional[str] = None,
        regions: Optional[List[str]] = None,
        check_ids: Optional[List[str]] = None
    ) -> ScanReport:
        """
        Run a complete security scan for a cloud account.
        
        Args:
            provider: Cloud provider to scan
            session: Authenticated session/client for the provider
            account_id: Cloud account identifier
            account_name: Optional friendly name for the account
            regions: List of regions to scan (uses defaults if None)
            check_ids: Optional list of specific check IDs to run
            
        Returns:
            Complete scan report
        """
        logger.info(f"Starting CSPM scan for {provider} account {account_id}")
        
        # Initialize scan report
        scan_regions = regions or settings.default_scan_regions.get(provider.value, [])
        report = ScanReport(
            provider=provider,
            account_id=account_id,
            account_name=account_name,
            regions=scan_regions
        )
        
        try:
            # Get checks to run
            checks_to_run = self._filter_checks(provider, check_ids)
            
            if not checks_to_run:
                logger.warning(f"No checks found for provider {provider}")
                report.status = "completed"
                report.completed_at = datetime.utcnow()
                return report
            
            logger.info(f"Running {len(checks_to_run)} checks across {len(scan_regions)} regions")
            
            # Run checks
            await self._execute_checks(checks_to_run, session, scan_regions, report)
            
            # Finalize report
            report.finalize()
            
            logger.info(
                f"Scan completed: {report.passed_checks} passed, "
                f"{report.failed_checks} failed, {report.error_checks} errors"
            )
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            report.status = "failed"
            report.completed_at = datetime.utcnow()
            raise
        
        return report
    
    def _filter_checks(
        self, 
        provider: CloudProvider, 
        check_ids: Optional[List[str]] = None
    ) -> List[BaseCheck]:
        """Filter checks based on provider and optional check IDs."""
        provider_checks = self.loaded_checks.get(provider, [])
        
        if not check_ids:
            return [check for check in provider_checks if check.metadata.enabled]
        
        return [
            check for check in provider_checks 
            if check.metadata.check_id in check_ids and check.metadata.enabled
        ]
    
    async def _execute_checks(
        self,
        checks: List[BaseCheck],
        session: Any,
        regions: List[str],
        report: ScanReport
    ):
        """Execute all checks with concurrency control."""
        semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        
        async def run_check_with_semaphore(check: BaseCheck, region: Optional[str]):
            async with semaphore:
                return await self._run_single_check(check, session, region, report)
        
        # Create tasks for all check/region combinations
        tasks = []
        for check in checks:
            if regions:
                # Multi-region providers
                for region in regions:
                    tasks.append(run_check_with_semaphore(check, region))
            else:
                # Global/single-region providers
                tasks.append(run_check_with_semaphore(check, None))
        
        # Execute all tasks
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_single_check(
        self,
        check: BaseCheck,
        session: Any,
        region: Optional[str],
        report: ScanReport
    ):
        """Run a single security check and add results to the report."""
        check_id = check.metadata.check_id
        region_str = f" in {region}" if region else ""
        
        try:
            logger.debug(f"Running check {check_id}{region_str}")
            
            # Execute the check
            results = await check.execute(session, region)
            
            # Add results to report
            for result in results:
                report.add_result(result)
            
            logger.debug(f"Check {check_id}{region_str} completed with {len(results)} results")
            
        except Exception as e:
            # Create error result
            error_result = CheckResult(
                check_id=check_id,
                resource_id="unknown",
                resource_type="unknown",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Check execution failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
            report.add_result(error_result)
            
            logger.error(f"Check {check_id}{region_str} failed: {e}")
    
    def get_available_checks(
        self, 
        provider: Optional[CloudProvider] = None
    ) -> List[Dict[str, Any]]:
        """Get metadata for all available checks, optionally filtered by provider."""
        if provider:
            checks = self.loaded_checks.get(provider, [])
        else:
            checks = []
            for provider_checks in self.loaded_checks.values():
                checks.extend(provider_checks)
        
        return [
            {
                "check_id": check.metadata.check_id,
                "title": check.metadata.title,
                "description": check.metadata.description,
                "provider": check.metadata.provider.value,
                "service": check.metadata.service,
                "category": check.metadata.category,
                "severity": check.metadata.severity.value,
                "compliance_frameworks": check.metadata.compliance_frameworks,
                "enabled": check.metadata.enabled
            }
            for check in checks
        ]


# Global check runner instance
check_runner = CheckRunner()
