"""
Asset Management Background Tasks

Celery tasks for asset discovery, inventory updates, and maintenance.
"""

from celery import shared_task
from django.utils import timezone
from django.conf import settings
import logging
import requests
import socket
import ipaddress
from datetime import timedelta

from .models import Asset, AssetDiscoveryRule, AssetSoftware, AssetPort

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def discover_assets(self, network_range, scan_type='basic'):
    """
    Discover assets in a network range
    
    Args:
        network_range: Network range in CIDR notation (e.g., '192.168.1.0/24')
        scan_type: Type of scan ('basic', 'comprehensive')
    """
    try:
        logger.info(f"Starting asset discovery for {network_range}, scan type: {scan_type}")
        
        # Parse network range
        network = ipaddress.ip_network(network_range, strict=False)
        discovered_count = 0
        
        # Iterate through IP addresses in the network
        for ip in network.hosts():
            ip_str = str(ip)
            
            # Check if host is reachable
            if _ping_host(ip_str):
                asset, created = _discover_host(ip_str, scan_type)
                if created:
                    discovered_count += 1
                    logger.info(f"Discovered new asset: {asset.name} ({ip_str})")
        
        logger.info(f"Asset discovery completed. Discovered {discovered_count} new assets.")
        return {
            'status': 'completed',
            'network_range': network_range,
            'discovered_count': discovered_count
        }
        
    except Exception as exc:
        logger.error(f"Asset discovery failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True)
def execute_discovery_rule(self, rule_id):
    """
    Execute a specific asset discovery rule
    
    Args:
        rule_id: ID of the AssetDiscoveryRule to execute
    """
    try:
        rule = AssetDiscoveryRule.objects.get(id=rule_id)
        logger.info(f"Executing discovery rule: {rule.name}")
        
        if not rule.enabled:
            logger.warning(f"Discovery rule {rule.name} is disabled")
            return {'status': 'skipped', 'reason': 'rule_disabled'}
        
        # Update last_run timestamp
        rule.last_run = timezone.now()
        rule.save(update_fields=['last_run'])
        
        discovered_count = 0
        
        if rule.discovery_type == 'network_scan':
            discovered_count = _execute_network_scan(rule)
        elif rule.discovery_type == 'cloud_api':
            discovered_count = _execute_cloud_discovery(rule)
        elif rule.discovery_type == 'cmdb_import':
            discovered_count = _execute_cmdb_import(rule)
        
        logger.info(f"Discovery rule {rule.name} completed. Discovered {discovered_count} assets.")
        return {
            'status': 'completed',
            'rule_name': rule.name,
            'discovered_count': discovered_count
        }
        
    except AssetDiscoveryRule.DoesNotExist:
        logger.error(f"Discovery rule with ID {rule_id} not found")
        return {'status': 'error', 'reason': 'rule_not_found'}
    except Exception as exc:
        logger.error(f"Discovery rule execution failed: {str(exc)}")
        raise


@shared_task
def update_asset_inventory():
    """
    Periodic task to update asset inventory and cleanup old data
    """
    logger.info("Starting asset inventory update")
    
    # Mark assets as inactive if not seen for 30 days
    stale_threshold = timezone.now() - timedelta(days=30)
    stale_assets = Asset.objects.filter(
        last_seen__lt=stale_threshold,
        status='active'
    )
    
    stale_count = stale_assets.update(status='inactive')
    logger.info(f"Marked {stale_count} assets as inactive (not seen for 30 days)")
    
    # Clean up old software entries for decommissioned assets
    AssetSoftware.objects.filter(
        asset__status='decommissioned',
        last_verified__lt=stale_threshold
    ).delete()
    
    # Clean up old port entries for decommissioned assets
    AssetPort.objects.filter(
        asset__status='decommissioned',
        last_verified__lt=stale_threshold
    ).delete()
    
    logger.info("Asset inventory update completed")
    
    return {
        'status': 'completed',
        'stale_assets_marked': stale_count
    }


@shared_task
def scan_asset_ports(asset_id, port_range=None):
    """
    Scan ports on a specific asset
    
    Args:
        asset_id: UUID of the asset to scan
        port_range: Port range to scan (e.g., '1-1000' or None for common ports)
    """
    try:
        asset = Asset.objects.get(id=asset_id)
        logger.info(f"Starting port scan for asset: {asset.name} ({asset.ip_address})")
        
        if not asset.ip_address:
            logger.warning(f"Asset {asset.name} has no IP address for port scanning")
            return {'status': 'skipped', 'reason': 'no_ip_address'}
        
        # Define ports to scan
        if port_range:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = range(start, end + 1)
            else:
                ports = [int(port_range)]
        else:
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                    1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        
        open_ports_found = 0
        
        for port in ports:
            if _scan_port(asset.ip_address, port):
                # Port is open, create or update port record
                service_info = _detect_service(asset.ip_address, port)
                
                port_obj, created = AssetPort.objects.update_or_create(
                    asset=asset,
                    port_number=port,
                    protocol='tcp',
                    defaults={
                        'state': 'open',
                        'service': service_info.get('service', ''),
                        'service_version': service_info.get('version', ''),
                        'banner': service_info.get('banner', ''),
                        'discovered_by': 'guardian_port_scanner',
                        'last_verified': timezone.now()
                    }
                )
                
                if created:
                    open_ports_found += 1
                    logger.info(f"Found open port {port} on {asset.name}")
        
        # Update asset last_seen
        asset.last_seen = timezone.now()
        asset.save(update_fields=['last_seen'])
        
        logger.info(f"Port scan completed for {asset.name}. Found {open_ports_found} new open ports.")
        
        return {
            'status': 'completed',
            'asset_name': asset.name,
            'ports_scanned': len(ports),
            'new_open_ports': open_ports_found
        }
        
    except Asset.DoesNotExist:
        logger.error(f"Asset with ID {asset_id} not found")
        return {'status': 'error', 'reason': 'asset_not_found'}
    except Exception as exc:
        logger.error(f"Port scan failed for asset {asset_id}: {str(exc)}")
        raise


def _ping_host(ip_address, timeout=1):
    """Check if host is reachable via ping"""
    import subprocess
    import platform
    
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-W' if platform.system().lower() == 'windows' else '-w', str(timeout * 1000), ip_address]
    
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _discover_host(ip_address, scan_type):
    """Discover and create/update asset for a host"""
    # Check if asset already exists
    asset = Asset.objects.filter(ip_address=ip_address).first()
    created = False
    
    if not asset:
        # Try to resolve hostname
        hostname = _resolve_hostname(ip_address)
        
        # Create new asset
        asset = Asset.objects.create(
            name=hostname or f"host-{ip_address.replace('.', '-')}",
            ip_address=ip_address,
            hostname=hostname,
            asset_type='server',  # Default type
            status='active',
            discovered_by='guardian_network_discovery'
        )
        created = True
    else:
        # Update existing asset
        asset.last_seen = timezone.now()
        asset.save(update_fields=['last_seen'])
    
    # If comprehensive scan, also scan ports
    if scan_type == 'comprehensive':
        scan_asset_ports.delay(asset.id)
    
    return asset, created


def _resolve_hostname(ip_address):
    """Attempt to resolve hostname for IP address"""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def _scan_port(ip_address, port, timeout=1):
    """Check if a specific port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _detect_service(ip_address, port):
    """Attempt to detect service running on port"""
    service_info = {'service': '', 'version': '', 'banner': ''}
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip_address, port))
        
        # Try to grab banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['banner'] = banner[:500]  # Limit banner size
            
            # Basic service detection based on port and banner
            if port == 22:
                service_info['service'] = 'ssh'
            elif port == 80:
                service_info['service'] = 'http'
            elif port == 443:
                service_info['service'] = 'https'
            elif port == 25:
                service_info['service'] = 'smtp'
            elif port == 21:
                service_info['service'] = 'ftp'
            elif port == 3306:
                service_info['service'] = 'mysql'
            elif port == 5432:
                service_info['service'] = 'postgresql'
            
        except socket.timeout:
            pass
        
        sock.close()
        
    except Exception:
        pass
    
    return service_info


def _execute_network_scan(rule):
    """Execute network scan discovery rule"""
    networks = rule.target_specification.get('networks', [])
    scan_type = rule.target_specification.get('scan_type', 'basic')
    
    discovered_count = 0
    
    for network_range in networks:
        try:
            result = discover_assets.delay(network_range, scan_type)
            # In a real implementation, you might wait for the result or track it
            discovered_count += 1  # Placeholder
        except Exception as e:
            logger.error(f"Failed to scan network {network_range}: {str(e)}")
    
    return discovered_count


def _execute_cloud_discovery(rule):
    """Execute cloud API discovery rule"""
    provider = rule.target_specification.get('provider')
    
    if provider == 'aws':
        return _discover_aws_assets(rule)
    elif provider == 'azure':
        return _discover_azure_assets(rule)
    elif provider == 'gcp':
        return _discover_gcp_assets(rule)
    
    return 0


def _execute_cmdb_import(rule):
    """Execute CMDB import discovery rule"""
    cmdb_url = rule.target_specification.get('url')
    cmdb_query = rule.target_specification.get('query')
    
    # Implementation would depend on specific CMDB system
    logger.info(f"CMDB import from {cmdb_url} not yet implemented")
    return 0


def _discover_aws_assets(rule):
    """Discover AWS assets using boto3"""
    # Placeholder for AWS discovery implementation
    logger.info("AWS asset discovery not yet implemented")
    return 0


def _discover_azure_assets(rule):
    """Discover Azure assets using Azure SDK"""
    # Placeholder for Azure discovery implementation
    logger.info("Azure asset discovery not yet implemented")
    return 0


def _discover_gcp_assets(rule):
    """Discover GCP assets using Google Cloud SDK"""
    # Placeholder for GCP discovery implementation
    logger.info("GCP asset discovery not yet implemented")
    return 0
