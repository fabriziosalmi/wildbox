"""Email Harvester Tool - Discovers email addresses associated with a domain."""

import re
import requests
import time
from datetime import datetime
from typing import List, Set, Dict
from urllib.parse import quote_plus, urljoin
try:
    from .schemas import EmailHarvesterInput, EmailHarvesterOutput, EmailSource
except ImportError:
    from schemas import EmailHarvesterInput, EmailHarvesterOutput, EmailSource

# Email regex pattern
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

class SearchEngine:
    """Base class for search engines."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def search(self, domain: str, max_results: int) -> List[EmailSource]:
        """Search for emails. To be implemented by subclasses."""
        raise NotImplementedError

class GoogleSearch(SearchEngine):
    """Google search engine implementation."""
    
    def search(self, domain: str, max_results: int) -> List[EmailSource]:
        emails = []
        queries = [
            f'"{domain}" email',
            f'site:{domain} "@{domain}"',
            f'"{domain}" contact email',
            f'inurl:{domain} email'
        ]
        
        for query in queries:
            try:
                url = f"https://www.google.com/search?q={quote_plus(query)}&num=50"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    found_emails = EMAIL_PATTERN.findall(response.text)
                    for email in found_emails:
                        if domain.lower() in email.lower():
                            emails.append(EmailSource(
                                email=email.lower(),
                                source="Google",
                                url=url
                            ))
                
                # Rate limiting
                time.sleep(1)
                
            except Exception:
                continue
        
        return emails[:max_results]

class BingSearch(SearchEngine):
    """Bing search engine implementation."""
    
    def search(self, domain: str, max_results: int) -> List[EmailSource]:
        emails = []
        queries = [
            f'{domain} email',
            f'site:{domain} email',
            f'"{domain}" contact'
        ]
        
        for query in queries:
            try:
                url = f"https://www.bing.com/search?q={quote_plus(query)}&count=50"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    found_emails = EMAIL_PATTERN.findall(response.text)
                    for email in found_emails:
                        if domain.lower() in email.lower():
                            emails.append(EmailSource(
                                email=email.lower(),
                                source="Bing",
                                url=url
                            ))
                
                # Rate limiting
                time.sleep(1)
                
            except Exception:
                continue
        
        return emails[:max_results]

class DuckDuckGoSearch(SearchEngine):
    """DuckDuckGo search engine implementation."""
    
    def search(self, domain: str, max_results: int) -> List[EmailSource]:
        emails = []
        queries = [
            f'{domain} email contact',
            f'site:{domain} "@{domain}"'
        ]
        
        for query in queries:
            try:
                url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    found_emails = EMAIL_PATTERN.findall(response.text)
                    for email in found_emails:
                        if domain.lower() in email.lower():
                            emails.append(EmailSource(
                                email=email.lower(),
                                source="DuckDuckGo",
                                url=url
                            ))
                
                # Rate limiting
                time.sleep(1)
                
            except Exception:
                continue
        
        return emails[:max_results]

class DirectDomainSearch:
    """Direct domain search for common email patterns."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search(self, domain: str) -> List[EmailSource]:
        emails = []
        
        # Common pages that might contain email addresses
        common_pages = [
            '',
            'contact',
            'contact.html',
            'contact.php',
            'about',
            'about.html',
            'about.php',
            'team',
            'staff',
            'support',
            'help'
        ]
        
        for page in common_pages:
            try:
                if page:
                    url = f"https://{domain}/{page}"
                else:
                    url = f"https://{domain}"
                
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    found_emails = EMAIL_PATTERN.findall(response.text)
                    for email in found_emails:
                        if domain.lower() in email.lower():
                            emails.append(EmailSource(
                                email=email.lower(),
                                source="Direct Domain",
                                url=url
                            ))
                
            except Exception:
                continue
        
        return emails

def execute_tool(input_data: EmailHarvesterInput) -> EmailHarvesterOutput:
    """Execute the email harvester tool."""
    timestamp = datetime.now()
    all_emails = []
    sources_searched = []
    
    # Initialize search engines
    search_engines = {
        'google': GoogleSearch(input_data.timeout),
        'bing': BingSearch(input_data.timeout),
        'duckduckgo': DuckDuckGoSearch(input_data.timeout)
    }
    
    # Search using specified search engines
    for engine_name in input_data.search_engines:
        if engine_name.lower() in search_engines:
            try:
                engine = search_engines[engine_name.lower()]
                emails = engine.search(input_data.domain, input_data.max_results)
                all_emails.extend(emails)
                sources_searched.append(engine_name.title())
            except Exception:
                continue
    
    # Direct domain search
    try:
        direct_search = DirectDomainSearch(input_data.timeout)
        direct_emails = direct_search.search(input_data.domain)
        all_emails.extend(direct_emails)
        sources_searched.append("Direct Domain")
    except Exception:
        pass
    
    # Remove duplicates while preserving source information
    unique_emails = {}
    for email_source in all_emails:
        email_addr = email_source.email
        if email_addr not in unique_emails:
            unique_emails[email_addr] = email_source
        # If we find the same email from a different source, we could merge sources
        # For now, we'll keep the first occurrence
    
    final_emails = list(unique_emails.values())
    
    # Calculate statistics
    statistics = {}
    for email_source in final_emails:
        source = email_source.source
        statistics[source] = statistics.get(source, 0) + 1
    
    return EmailHarvesterOutput(
        domain=input_data.domain,
        timestamp=timestamp,
        total_emails=len(final_emails),
        sources_searched=sources_searched,
        emails=final_emails,
        statistics=statistics
    )

# Tool metadata
TOOL_INFO = {
    "name": "email_harvester",
    "display_name": "Email Harvester",
    "description": "Discovers email addresses associated with a target domain",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "osint"
}
