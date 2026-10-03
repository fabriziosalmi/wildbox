"""
Asset Management Background Tasks

Celery tasks for asset discovery, inventory updates, and maintenance.
"""

from celery import shared_task
from django.utils import timezone
from django.conf import settings
import logging
import requests
import errno
import socket
import ipaddress
from datetime import timedelta

from apps.core.tenancy import normalize_team_id, scope_to_team

from .models import (
    IMPLEMENTED_DISCOVERY_TYPES,
    Asset,
    AssetDiscoveryRule,
    AssetPort,
    AssetSoftware,
)

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def discover_assets(self, network_range, scan_type='basic', team_id=None):
    """
    Discover assets in a network range

    Args:
        network_range: Network range in CIDR notation (e.g., '192.168.1.0/24')
        scan_type: Type of scan ('basic', 'comprehensive')
        team_id: The team the discovered assets belong to (#642): a host
            already known to that team is updated, a new one is created
            for it. Other teams' assets at the same address are left
            alone. None is the rows without a team (a legacy rule's).
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
            if _host_is_up(ip_str):
                asset, created = _discover_host(ip_str, scan_type, team_id)
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

        # The other types only log "not yet implemented" (or do nothing);
        # reporting them as completed said discovery had run (#548).
        if rule.discovery_type not in IMPLEMENTED_DISCOVERY_TYPES:
            logger.warning(
                f"Discovery rule {rule.name}: {rule.discovery_type} discovery "
                "is not implemented"
            )
            return {'status': 'skipped', 'reason': 'not_implemented'}

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


# Ports a host-discovery probe connects to (#548). This used to run the ping
# binary, which guardian's image does not contain: every probe raised
# FileNotFoundError and a network scan discovered nothing. ICMP would also
# need a raw socket, which the unprivileged guardian user does not have. A
# TCP connection either completes or is refused by a host that is up; only a
# host that is down or drops every probe stays silent. This is what nmap
# does for host discovery without privileges.
HOST_PROBE_PORTS = (80, 443, 22, 3389)


def _host_is_up(ip_address, timeout=1):
    """True if the host completes or refuses a TCP connection on a probe port."""
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        logger.warning(f"Invalid IP address format: {ip_address}")
        return False

    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    for port in HOST_PROBE_PORTS:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((str(address), port))
        except OSError:
            continue
        if result in (0, errno.ECONNREFUSED):
            return True
    return False


def _discover_host(ip_address, scan_type, team_id=None):
    """Discover and create/update the team's asset for a host"""
    # Check if the team already has an asset at this address (#642)
    asset = scope_to_team(Asset.objects.filter(ip_address=ip_address), team_id).first()
    created = False
    
    if not asset:
        # Try to resolve hostname
        hostname = _resolve_hostname(ip_address)
        
        # Create new asset
        asset = Asset.objects.create(
            team_id=normalize_team_id(team_id),
            name=hostname or f"host-{ip_address.replace('.', '-')}",
            ip_address=ip_address,
            # hostname is NOT NULL: a host without a reverse DNS name made
            # the whole discovery fail and retry.
            hostname=hostname or '',
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
            result = discover_assets.delay(
                network_range,
                scan_type,
                team_id=str(rule.team_id) if rule.team_id else None,
            )
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
