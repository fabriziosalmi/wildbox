"""Directory Brute Forcer Tool - Discovers hidden directories and files."""

import time
import asyncio
import aiohttp
from datetime import datetime
from typing import List
try:
    from .schemas import DirectoryBruteforcerInput, DirectoryBruteforcerOutput, DirectoryResult
except ImportError:
    from schemas import DirectoryBruteforcerInput, DirectoryBruteforcerOutput, DirectoryResult

# Directory and file wordlists
SMALL_WORDLIST = [
    "admin", "login", "dashboard", "config", "backup", "test", "dev", "api", "upload", "download",
    "images", "css", "js", "assets", "static", "media", "files", "docs", "help", "support",
    "robots.txt", "sitemap.xml", ".htaccess", "index.php", "wp-admin", "phpmyadmin"
]

MEDIUM_WORDLIST = SMALL_WORDLIST + [
    "administrator", "management", "panel", "control", "cpanel", "webmail", "mail", "email",
    "ftp", "ssh", "secure", "security", "private", "hidden", "secret", "confidential",
    "internal", "intranet", "extranet", "portal", "gateway", "proxy", "cache", "temp",
    "tmp", "log", "logs", "debug", "error", "errors", "status", "health", "monitor",
    "stats", "statistics", "analytics", "reports", "data", "database", "db", "sql",
    "mysql", "postgres", "oracle", "mongodb", "redis", "elastic", "search", "solr",
    "kibana", "grafana", "prometheus", "jenkins", "gitlab", "github", "bitbucket",
    "jira", "confluence", "wiki", "documentation", "manual", "guide", "tutorial"
]

LARGE_WORDLIST = MEDIUM_WORDLIST + [
    "application", "applications", "app", "apps", "service", "services", "resource",
    "resources", "component", "components", "module", "modules", "plugin", "plugins",
    "extension", "extensions", "addon", "addons", "widget", "widgets", "tool", "tools",
    "utility", "utilities", "script", "scripts", "library", "libraries", "framework",
    "frameworks", "template", "templates", "theme", "themes", "skin", "skins",
    "layout", "layouts", "design", "designs", "style", "styles", "stylesheet",
    "stylesheets", "font", "fonts", "icon", "icons", "image", "video", "audio",
    "document", "documents", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "tar", "gz", "7z", "bin", "exe", "dll", "so", "jar", "war",
    "class", "java", "python", "ruby", "perl", "php", "asp", "aspx", "jsp",
    "servlet", "cgi", "pl", "py", "rb", "sh", "bat", "cmd", "ps1", "vbs"
]

def get_wordlist(size: str) -> List[str]:
    """Get wordlist based on size preference."""
    if size == "small":
        return SMALL_WORDLIST
    elif size == "large":
        return LARGE_WORDLIST
    else:
        return MEDIUM_WORDLIST

async def test_path(session: aiohttp.ClientSession, base_url: str, path: str, timeout: int) -> DirectoryResult:
    """Test a single path."""
    url = f"{base_url.rstrip('/')}/{path}"
    start_time = time.time()
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
            response_time = time.time() - start_time
            content = await response.read()
            
            return DirectoryResult(
                path=path,
                status_code=response.status,
                size=len(content),
                response_time=response_time
            )
    except Exception:
        response_time = time.time() - start_time
        return DirectoryResult(
            path=path,
            status_code=0,
            size=0,
            response_time=response_time
        )

async def execute_tool(input_data: DirectoryBruteforcerInput) -> DirectoryBruteforcerOutput:
    """Execute the directory brute forcer tool."""
    start_time = datetime.now()
    
    wordlist = get_wordlist(input_data.wordlist_size)
    extensions = input_data.extensions or []
    
    # Create list of paths to test
    paths_to_test = []
    
    # Add directories
    paths_to_test.extend(wordlist)
    
    # Add files with extensions
    for word in wordlist:
        for ext in extensions:
            paths_to_test.append(f"{word}.{ext}")
    
    # Create HTTP session with connection limits
    connector = aiohttp.TCPConnector(limit=input_data.threads, limit_per_host=input_data.threads)
    timeout = aiohttp.ClientTimeout(total=input_data.timeout)
    
    results = []
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(input_data.threads)
        
        async def test_with_semaphore(path):
            async with semaphore:
                return await test_path(session, input_data.target_url, path, input_data.timeout)
        
        # Execute all tests
        tasks = [test_with_semaphore(path) for path in paths_to_test]
        results = await asyncio.gather(*tasks)
    
    # Filter successful results (status codes 200, 301, 302, 403, etc.)
    interesting_results = []
    for result in results:
        if result.status_code in [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 503]:
            interesting_results.append(result)
    
    # Sort results by status code and path
    interesting_results.sort(key=lambda x: (x.status_code, x.path))
    
    duration = (datetime.now() - start_time).total_seconds()
    
    return DirectoryBruteforcerOutput(
        target_url=input_data.target_url,
        timestamp=start_time,
        total_requests=len(paths_to_test),
        found_paths=len(interesting_results),
        results=interesting_results,
        duration=duration
    )

# Tool metadata
TOOL_INFO = {
    "name": "directory_bruteforcer",
    "display_name": "Directory Brute Forcer",
    "description": "Discovers hidden directories and files on web servers",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "web_reconnaissance"
}
