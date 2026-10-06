"""
Asset Management Background Tasks

Celery tasks for asset discovery, inventory updates, and maintenance.
"""

from celery import shared_task
from django.utils import timezone
from django.conf import settings
import logging
import errno
import socket
import ipaddress
from datetime import timedelta

from apps.core.tenancy import normalize_team_id, scope_to_team

from .networks import (
    MAX_RULE_NETWORKS,
    NetworkRefused,
    check_address,
    check_port_range,
    scan_network,
)
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
    # What the API refuses, refused here too: a rule stored before the check
    # may name a range of any size (#724) or an internal one, and the ranges
    # the operator allows may have changed since this was queued (#748). Not
    # retried: it would be the same.
    try:
        network = scan_network(network_range)
    except NetworkRefused as refused:
        logger.warning(f"Asset discovery of {network_range!r} refused: {refused}")
        return {
            'status': 'refused',
            'network_range': network_range,
            'reason': str(refused),
        }

    try:
        logger.info(f"Starting asset discovery for {network_range}, scan type: {scan_type}")
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

        # network_scan is the one implemented type (the guard above). It
        # queues one discover_assets task per network and does not wait for
        # them, so what this task knows is how many scans it queued, not how
        # many assets they will find: it used to report the first as the
        # second ("Discovered N assets", 'discovered_count') (#644).
        networks_queued, skipped = _execute_network_scan(rule)

        # And which networks it did not queue, and why. A rule whose networks
        # were all refused (stored before the target check, or before the
        # operator narrowed the list) ended 'completed' with nothing queued,
        # and the reason was in this worker's log only (#775).
        outcome = {
            'status': 'completed' if networks_queued else 'skipped',
            'networks_queued': networks_queued,
            'networks_skipped_count': len(skipped),
            # A rule stored before the API bounded the list may name any
            # number of networks; what is kept and returned is bounded.
            'networks_skipped': skipped[:MAX_RULE_NETWORKS],
        }
        if not networks_queued:
            outcome['reason'] = 'no_network_queued'

        # Where the rule's owner reads it: the task's result is the
        # operator's (the task route answers with a state and no result).
        rule.last_run_result = outcome
        rule.save(update_fields=['last_run_result'])

        logger.info(
            f"Discovery rule {rule.name} {outcome['status']}. Queued "
            f"{networks_queued} network scans, skipped {len(skipped)}."
        )
        return {'rule_name': rule.name, **outcome}

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
        port_range: Port range to scan (e.g., '1-1000' or None for common ports):
            one port or a range of at most MAX_SCAN_PORTS ports from 1 to
            65535 (apps.assets.networks.check_port_range). Anything else is
            refused, with the reason in the result, and nothing is dialed.
    """
    try:
        asset = Asset.objects.get(id=asset_id)
        logger.info(f"Starting port scan for asset: {asset.name} ({asset.ip_address})")
        
        if not asset.ip_address:
            logger.warning(f"Asset {asset.name} has no IP address for port scanning")
            return {'status': 'skipped', 'reason': 'no_ip_address'}

        # The address is checked here, where the scan runs, whoever queued
        # it: the scan action, the creation of an asset, a discovery, or a
        # task queued before the check existed (#748). An asset may sit at
        # an internal address; it is recorded, and not scanned.
        # What is dialed below is the address this check returned, not the
        # stored text read a second time (#775).
        address, refusal = check_address(asset.ip_address)
        if refusal is not None:
            logger.warning(f"Port scan of asset {asset.name} refused: {refusal}")
            return {'status': 'refused', 'reason': refusal}

        # Define ports to scan
        if port_range is None or port_range == '':
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                    1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        else:
            # Bounded before anything is dialed (#775). Not retried: it
            # would be the same.
            ports, refusal = check_port_range(port_range)
            if refusal is not None:
                logger.warning(f"Port scan of asset {asset.name} refused: {refusal}")
                return {'status': 'refused', 'reason': refusal}

        open_ports_found = 0
        # Attempts that ended for a reason that is not the port's: reason
        # -> how many. Logged once below, not once a port.
        failures = {}

        for port in ports:
            if _scan_port(address, port, failures=failures):
                # Port is open, create or update port record
                service_info = _detect_service(address, port)
                
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
        
        if failures:
            # The result below cannot say it (#787): these ports are counted
            # as scanned and are not known to be closed.
            logger.warning(
                f"Port scan of asset {asset.name}: {sum(failures.values())} of "
                f"{len(ports)} ports could not be tried ("
                + ", ".join(f"{reason} x{count}" for reason, count in sorted(failures.items()))
                + "); they are not known to be closed"
            )

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


def _host_name(ip_address):
    """The name of an asset discovered at an address no name resolves from.

    ``host-`` and the address with a hyphen for each separator, a name a
    host could have: ``host-93-184-215-14``. Only the dots were replaced, so
    an IPv6 host was named ``host-2606:2800:21f::1``, colons and all (#788).
    Nothing validates an asset's name or needs it unique (the team's asset
    at an address is found by the address), but it is shown, searched and
    exported as a host's name, and that is not one.

    An IPv6 address is written in full, eight groups of four digits: the
    short form would give ``host-2001-db8--1``, and for ``2001:db8::`` a name
    that ends in a hyphen. An IPv4 name is what it has always been, and no
    stored name is changed.
    """
    address = ipaddress.ip_address(ip_address)
    if address.version == 6:
        # From the number, not from a text of the address: how Python
        # writes one that carries an IPv4 address changed between releases.
        digits = f"{int(address):032x}"
        return "host-" + "-".join(digits[i:i + 4] for i in range(0, 32, 4))
    return f"host-{ip_address.replace('.', '-')}"


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
            name=hostname or _host_name(ip_address),
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


def _socket_family(address):
    """The socket family of ``address``, an ``ipaddress`` address.

    _scan_port and _detect_service opened AF_INET sockets whatever the
    address: connecting one to an IPv6 address fails before a packet leaves,
    so the scan of an IPv6 asset reported every port closed (#775).
    """
    return socket.AF_INET6 if address.version == 6 else socket.AF_INET


# What a connection to a port that is not open ends with: the host refuses
# it, or nothing answers within the timeout. connect_ex reports the socket's
# own timeout as EAGAIN/EWOULDBLOCK and the kernel's as ETIMEDOUT.
_PORT_NOT_OPEN = frozenset(
    {errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK}
)


def _scan_port(address, port, timeout=1, failures=None):
    """True if the port is open at ``address``, which check_address returned.

    False for a port that refuses the connection or does not answer it.

    False as well for an attempt that failed for a reason that says nothing
    about the port: no route to the host, a network that is down, no socket
    to be had. Those were read as "closed", by an ``except Exception`` that
    also read any error in this function as one. The result of a scan has
    no place for them yet (#787), so the reason is counted in ``failures``,
    by the name of its errno, for the task to log once.

    The socket is closed whatever happens: when the connection raised, it
    was left to the garbage collector (#788).
    """
    try:
        with socket.socket(_socket_family(address), socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((str(address), port))
    except Exception as exc:
        # What connect_ex raises instead of returning, or no socket at all.
        # Named by its errno or its class, never by its text. A resolver's
        # error carries a number of its own in errno, which is not one.
        resolver = isinstance(exc, (socket.gaierror, socket.herror))
        code = None if resolver else getattr(exc, 'errno', None)
        reason = errno.errorcode.get(code, type(exc).__name__)
    else:
        if code == 0:
            return True
        reason = errno.errorcode.get(code, f"errno {code}")
    if code not in _PORT_NOT_OPEN and failures is not None:
        failures[reason] = failures.get(reason, 0) + 1
    return False


def _detect_service(address, port):
    """Attempt to detect the service on a port of ``address`` (as _scan_port)"""
    service_info = {'service': '', 'version': '', 'banner': ''}

    try:
        # Closed whatever happens, as in _scan_port.
        with socket.socket(_socket_family(address), socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((str(address), port))

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

    except Exception:
        pass

    return service_info


# Why a network of a rule was not scanned when no check refused it: the
# broker did not take the task. A text of guardian's own, not the exception's,
# which may name the broker and its address.
NOT_QUEUED = "The scan of this network could not be queued."


def _execute_network_scan(rule):
    """Queue a network scan per network of the rule.

    Returns how many were queued, and the networks that were not: a list of
    ``{'network': ..., 'reason': ...}``, the reason being the message
    ``check_network`` writes for the caller.
    """
    networks = rule.target_specification.get('networks', [])
    scan_type = rule.target_specification.get('scan_type', 'basic')

    queued = 0
    skipped = []

    for network_range in networks:
        # As check_network shortens what it quotes: a stored value is not
        # always a string, nor a short one.
        named = str(network_range).strip()[:64]
        try:
            # Nothing is queued for a range the task would refuse.
            scan_network(network_range)
        except NetworkRefused as refused:
            logger.warning(
                f"Discovery rule {rule.name}: {network_range!r} not scanned: {refused}"
            )
            skipped.append({'network': named, 'reason': str(refused)})
            continue
        try:
            discover_assets.delay(
                network_range,
                scan_type,
                team_id=str(rule.team_id) if rule.team_id else None,
            )
            queued += 1
        except Exception as e:
            # The class, not the text: a broker's error names the broker
            # and its address, and may hold the URL it was given (#788).
            logger.error(
                f"Failed to queue the scan of network {named!r}: {type(e).__name__}"
            )
            skipped.append({'network': named, 'reason': NOT_QUEUED})

    return queued, skipped


# Cloud API (AWS, Azure, GCP) and CMDB discovery are not implemented. The
# functions that stood here for them logged "not yet implemented" and
# returned 0 discovered assets; execute_discovery_rule cannot reach a type
# outside IMPLEMENTED_DISCOVERY_TYPES (#548), so they were dead code and
# were removed (#644).
