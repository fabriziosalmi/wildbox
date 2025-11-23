"""
Wordlist Management for API Discovery and Security Testing

This module provides utilities for loading and managing wordlists used in
security testing tools. It supports multiple wordlist types and provides
safe fallback mechanisms.
"""

from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

# Get wordlist directory (same directory as this file)
WORDLIST_DIR = Path(__file__).parent

# Minimal fallback paths if wordlist files are missing
# These are the absolute minimum paths needed for basic functionality
FALLBACK_PATHS = [
    "/api/v1",
    "/api/v2", 
    "/api",
    "/rest",
    "/graphql",
    "/users",
    "/login",
    "/auth",
    "/token",
    "/admin"
]


def load_wordlist(name: str = "api_common") -> List[str]:
    """
    Load wordlist from file with automatic fallback
    
    Args:
        name: Wordlist filename without extension (e.g., 'api_common', 'admin_paths')
        
    Returns:
        List of paths/endpoints to test
        
    Example:
        >>> paths = load_wordlist("api_common")
        >>> len(paths)
        200
    """
    wordlist_path = WORDLIST_DIR / f"{name}.txt"
    
    if not wordlist_path.exists():
        logger.warning(
            f"Wordlist '{name}.txt' not found at {wordlist_path}. "
            f"Using minimal fallback ({len(FALLBACK_PATHS)} paths). "
            f"Available wordlists: {', '.join(list_available_wordlists())}"
        )
        return FALLBACK_PATHS.copy()
    
    paths = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Basic validation: paths should start with /
                if not line.startswith('/'):
                    logger.warning(
                        f"Invalid path in {name}.txt line {line_num}: '{line}' "
                        f"(paths must start with '/')"
                    )
                    continue
                
                paths.append(line)
        
        logger.info(f"Loaded {len(paths)} paths from {name}.txt")
        return paths
        
    except Exception as e:
        logger.error(f"Failed to load wordlist '{name}': {e}")
        logger.info(f"Falling back to minimal wordlist ({len(FALLBACK_PATHS)} paths)")
        return FALLBACK_PATHS.copy()


def list_available_wordlists() -> List[str]:
    """
    Return names of available wordlists (without .txt extension)
    
    Returns:
        List of wordlist names that can be used with load_wordlist()
        
    Example:
        >>> wordlists = list_available_wordlists()
        >>> 'api_common' in wordlists
        True
    """
    try:
        return [
            f.stem for f in WORDLIST_DIR.glob("*.txt")
            if not f.name.startswith('.') and not f.name.startswith('__')
        ]
    except Exception as e:
        logger.error(f"Failed to list wordlists: {e}")
        return []


def get_wordlist_info(name: str = "api_common") -> Dict[str, any]:
    """
    Get metadata about a wordlist
    
    Args:
        name: Wordlist filename without extension
        
    Returns:
        Dictionary with wordlist metadata (path_count, file_size, exists)
        
    Example:
        >>> info = get_wordlist_info("api_common")
        >>> info['exists']
        True
    """
    wordlist_path = WORDLIST_DIR / f"{name}.txt"
    
    if not wordlist_path.exists():
        return {
            "name": name,
            "exists": False,
            "path_count": 0,
            "file_size": 0,
            "file_path": str(wordlist_path)
        }
    
    try:
        # Count non-empty, non-comment lines
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            path_count = sum(
                1 for line in f 
                if line.strip() and not line.strip().startswith('#')
            )
        
        file_size = wordlist_path.stat().st_size
        
        return {
            "name": name,
            "exists": True,
            "path_count": path_count,
            "file_size": file_size,
            "file_path": str(wordlist_path)
        }
    except Exception as e:
        logger.error(f"Failed to get wordlist info for '{name}': {e}")
        return {
            "name": name,
            "exists": False,
            "path_count": 0,
            "file_size": 0,
            "error": str(e)
        }


# Convenience function for backward compatibility
def get_common_api_paths() -> List[str]:
    """
    Get common API paths (wrapper around load_wordlist)
    
    Returns:
        List of common API endpoint paths
        
    Deprecated:
        Use load_wordlist("api_common") instead
    """
    return load_wordlist("api_common")


if __name__ == "__main__":
    # Quick test/demo of wordlist functionality
    print("=== Wildbox Wordlist Manager ===\n")
    
    print("Available wordlists:")
    for wl in list_available_wordlists():
        info = get_wordlist_info(wl)
        print(f"  - {wl}: {info['path_count']} paths ({info['file_size']} bytes)")
    
    print("\nLoading api_common wordlist:")
    paths = load_wordlist("api_common")
    print(f"  Loaded {len(paths)} paths")
    print(f"  First 10: {paths[:10]}")
