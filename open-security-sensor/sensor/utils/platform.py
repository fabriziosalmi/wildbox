"""
Platform detection and information utilities
"""

import platform
import os
import sys
from typing import Dict, Any

def get_platform_info() -> Dict[str, Any]:
    """Get comprehensive platform information"""
    
    info = {
        'system': platform.system(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'architecture': platform.architecture(),
        'platform': platform.platform(),
        'python_version': sys.version,
        'python_executable': sys.executable
    }
    
    # Operating system specific information
    if platform.system() == 'Linux':
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_release[key] = value.strip('"')
                info['os_release'] = os_release
        except FileNotFoundError:
            pass
        
        # Kernel version
        info['kernel_version'] = platform.release()
        
    elif platform.system() == 'Windows':
        info['windows_version'] = platform.win32_ver()
        info['windows_edition'] = platform.win32_edition()
        
    elif platform.system() == 'Darwin':  # macOS
        info['mac_version'] = platform.mac_ver()
    
    # Environment information
    info['environment'] = {
        'user': os.environ.get('USER') or os.environ.get('USERNAME'),
        'home': os.environ.get('HOME') or os.environ.get('USERPROFILE'),
        'path': os.environ.get('PATH', '').split(os.pathsep)[:5]  # First 5 PATH entries
    }
    
    return info

def is_windows() -> bool:
    """Check if running on Windows"""
    return platform.system() == 'Windows'

def is_linux() -> bool:
    """Check if running on Linux"""
    return platform.system() == 'Linux'

def is_macos() -> bool:
    """Check if running on macOS"""
    return platform.system() == 'Darwin'

def get_default_paths() -> Dict[str, str]:
    """Get default paths for the current platform"""
    
    if is_windows():
        return {
            'config_dir': os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'SecuritySensor'),
            'data_dir': os.path.join(os.environ.get('APPDATA', ''), 'SecuritySensor'),
            'log_dir': os.path.join(os.environ.get('APPDATA', ''), 'SecuritySensor', 'logs'),
            'temp_dir': os.environ.get('TEMP', 'C:\\Windows\\Temp')
        }
    else:  # Unix-like (Linux, macOS)
        return {
            'config_dir': '/etc/security-sensor',
            'data_dir': '/var/lib/security-sensor',
            'log_dir': '/var/log/security-sensor',
            'temp_dir': '/tmp'
        }
