#!/usr/bin/env python3

"""
Wildbox API Documentation Generator
Automatically generates static OpenAPI/Swagger documentation by spinning up
services with docker-compose and fetching their OpenAPI schemas.
"""

import os
import sys
import json
import time
import base64
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

# ANSI Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

# Configuration
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
DOCS_DIR = PROJECT_ROOT / 'docs' / 'api'
TEMP_DIR = Path('/tmp/wildbox-api-docs')

# Service configurations: (name, port, container_name)
SERVICES = [
    ('api', 8000, 'open-security-tools'),
    ('identity', 8001, 'open-security-identity'),
    ('data', 8002, 'open-security-data'),
    ('guardian', 8013, 'open-security-guardian'),
    ('responder', 8018, 'open-security-responder'),
    ('agents', 8006, 'open-security-agents'),
]


def print_step(step_num: int, message: str):
    """Print a step message"""
    print(f"\n{BLUE}Step {step_num}: {message}{NC}")


def print_success(message: str):
    """Print success message"""
    print(f"{GREEN}✓{NC} {message}")


def print_error(message: str):
    """Print error message"""
    print(f"{RED}✗{NC} {message}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{YELLOW}⚠{NC} {message}")


def run_command(cmd: List[str], cwd: Path = None, check: bool = True) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr"""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        print_error(f"Command timeout: {' '.join(cmd)}")
        return 1, '', 'Timeout'
    except Exception as e:
        if check:
            raise
        return 1, '', str(e)


def start_services() -> bool:
    """Start docker-compose services"""
    print_step(1, "Starting Docker Compose services")

    code, stdout, stderr = run_command(
        ['docker-compose', 'up', '-d'],
        cwd=PROJECT_ROOT,
        check=False
    )

    if code != 0:
        print_error(f"Failed to start services: {stderr}")
        return False

    print_success("Docker Compose services started")
    return True


def wait_for_service(host: str, port: int, service_name: str, max_retries: int = 30) -> bool:
    """Wait for a service to be ready"""
    url = f"http://{host}:{port}/health"

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code in [200, 404]:  # 404 is ok, means service is up
                print_success(f"{service_name} (port {port}) is ready")
                return True
        except requests.exceptions.RequestException:
            pass

        if attempt < max_retries - 1:
            print(f"  Waiting for {service_name}... ({attempt + 1}/{max_retries})")
            time.sleep(5)

    print_error(f"{service_name} (port {port}) did not start in time")
    return False


def wait_for_all_services() -> bool:
    """Wait for all services to be ready"""
    print_step(2, "Waiting for services to be ready")

    all_ready = True
    for service_name, port, container_name in SERVICES:
        if not wait_for_service('localhost', port, service_name):
            all_ready = False

    if not all_ready:
        return False

    print_success("All services are ready")
    return True


def fetch_openapi_schema(service_name: str, port: int) -> Dict:
    """Fetch OpenAPI schema from a service"""
    endpoints = [
        f"http://localhost:{port}/openapi.json",
        f"http://localhost:{port}/api/openapi.json",
        f"http://localhost:{port}/docs/openapi.json",
    ]

    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, timeout=10)
            if response.status_code == 200:
                schema = response.json()
                print_success(f"Fetched {service_name} OpenAPI schema from {endpoint}")
                return schema
        except Exception as e:
            continue

    print_error(f"Could not fetch OpenAPI schema for {service_name}")
    return None


def fetch_all_schemas() -> Dict[str, Dict]:
    """Fetch all OpenAPI schemas"""
    print_step(3, "Fetching OpenAPI schemas")

    schemas = {}
    for service_name, port, container_name in SERVICES:
        print(f"Fetching schema for {service_name}...")
        schema = fetch_openapi_schema(service_name, port)
        if schema:
            schemas[service_name] = schema

    if not schemas:
        print_warning("No schemas were fetched. Services may not have OpenAPI endpoints.")
        return schemas

    print_success(f"Fetched {len(schemas)} OpenAPI schema(s)")
    return schemas


def generate_html_from_schema(service_name: str, schema: Dict) -> str:
    """Generate HTML documentation from OpenAPI schema"""
    title = schema.get('info', {}).get('title', f"{service_name} API")
    description = schema.get('info', {}).get('description', f"{service_name} API Documentation")
    version = schema.get('info', {}).get('version', '1.0.0')

    # Encode schema as base64 for embedding
    schema_json = json.dumps(schema)
    schema_b64 = base64.b64encode(schema_json.encode()).decode()

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Wildbox API</title>
    <meta name="description" content="{description}">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='75' font-size='75'>🛡️</text></svg>">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f0f;
            color: #e5e7eb;
            line-height: 1.6;
        }}
        redoc {{
            display: block;
        }}
        [data-testid="footer"] {{
            background: #1a1a1a;
            border-top: 1px solid #333;
            padding: 2rem;
            text-align: center;
            color: #9ca3af;
            font-size: 0.9rem;
        }}
        /* ReDoc theming */
        ::part(sidebar) {{
            background: #1a1a1a;
        }}
    </style>
</head>
<body>
    <redoc spec-url="data:application/json;base64,{schema_b64}"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
    <script>
        // Add footer with generation timestamp
        window.addEventListener('load', () => {{
            const footer = document.createElement('div');
            footer.setAttribute('data-testid', 'footer');
            footer.innerHTML = '<p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} | {service_name} API v{version}</p>';
            document.body.appendChild(footer);
        }});
    </script>
</body>
</html>'''

    return html


def generate_documentation(schemas: Dict[str, Dict]) -> bool:
    """Generate static HTML documentation"""
    print_step(4, "Generating static HTML documentation")

    if not schemas:
        print_warning("No schemas available. Skipping documentation generation.")
        return True

    # Create docs directory if it doesn't exist
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    generated_count = 0
    for service_name, schema in schemas.items():
        try:
            html = generate_html_from_schema(service_name, schema)
            output_file = DOCS_DIR / f'{service_name}-api.html'

            with open(output_file, 'w') as f:
                f.write(html)

            print_success(f"Generated {output_file}")
            generated_count += 1
        except Exception as e:
            print_error(f"Failed to generate documentation for {service_name}: {e}")

    if generated_count == 0:
        print_error("Failed to generate any documentation")
        return False

    print_success(f"Generated {generated_count} HTML documentation file(s)")
    return True


def stop_services() -> bool:
    """Stop docker-compose services"""
    print(f"\n{YELLOW}Cleaning up and stopping services...{NC}")

    code, stdout, stderr = run_command(
        ['docker-compose', 'down', '--remove-orphans'],
        cwd=PROJECT_ROOT,
        check=False
    )

    if code == 0:
        print_success("Services stopped")
        return True
    else:
        print_warning(f"Failed to stop services: {stderr}")
        return False


def create_index_html() -> bool:
    """Create an index.html that links to all generated API docs"""
    print_step(5, "Creating API documentation index")

    index_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wildbox API Documentation</title>
    <meta name="description" content="Complete API documentation for Wildbox Security Platform">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f0f0f;
            color: #e5e7eb;
            line-height: 1.6;
            padding: 2rem;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            text-align: center;
            margin-bottom: 3rem;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            color: #9ca3af;
            font-size: 1.1rem;
        }
        .api-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        .api-card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 8px;
            padding: 2rem;
            transition: all 0.3s ease;
        }
        .api-card:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: #ef4444;
            transform: translateY(-2px);
        }
        .api-card h2 {
            color: #f87171;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }
        .api-card p {
            color: #d1d5db;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }
        .api-link {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        .api-link:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3);
        }
        .info-box {
            background: rgba(239, 68, 68, 0.05);
            border-left: 4px solid #ef4444;
            padding: 1.5rem;
            border-radius: 4px;
            margin-bottom: 2rem;
        }
        .info-box strong {
            color: #f87171;
        }
        .timestamp {
            text-align: center;
            color: #6b7280;
            font-size: 0.9rem;
            margin-top: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Wildbox API Documentation</h1>
            <p class="subtitle">Complete REST API reference for all security services</p>
        </header>

        <div class="info-box">
            <strong>ℹ️ Note:</strong> This documentation is auto-generated from live API services. Each service provides a complete OpenAPI specification with all endpoints, parameters, request/response examples, and error codes.
        </div>

        <div class="api-grid">
'''

    # Check which files were generated
    service_files = list(DOCS_DIR.glob('*-api.html'))

    if not service_files:
        print_warning("No API documentation files found")
        return False

    # Mapping of services to descriptions
    service_descriptions = {
        'api': 'Security Tools Platform - Core API for security tool execution and orchestration',
        'identity': 'Authentication & Authorization - User management, JWT tokens, and role-based access control',
        'data': 'Threat Intelligence & Data - Security data aggregation, IOCs, and threat feeds',
        'guardian': 'Integration Management - Security integrations, queue monitoring, and workflow orchestration',
        'responder': 'Incident Response - Playbook execution, remediation automation, and incident management',
        'agents': 'AI Security Agents - Machine learning-powered threat analysis and intelligence enrichment',
    }

    for service_file in sorted(service_files):
        service_name = service_file.stem.replace('-api', '')
        description = service_descriptions.get(service_name, f"{service_name} API Documentation")

        # Format service name nicely
        display_name = ' '.join(word.capitalize() for word in service_name.split('-'))

        index_html += f'''            <div class="api-card">
                <h2>{display_name}</h2>
                <p>{description}</p>
                <a href="./{service_file.name}" class="api-link">View Documentation →</a>
            </div>
'''

    index_html += '''        </div>

        <div class="timestamp">
            Generated: {timestamp}
        </div>
    </div>
</body>
</html>'''.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))

    # Write index file
    index_file = DOCS_DIR / 'swagger-index.html'
    with open(index_file, 'w') as f:
        f.write(index_html)

    print_success(f"Created {index_file}")
    return True


def main():
    """Main execution"""
    print(f"\n{BLUE}╔════════════════════════════════════════════╗{NC}")
    print(f"{BLUE}║   Wildbox API Documentation Generator    ║{NC}")
    print(f"{BLUE}╚════════════════════════════════════════════╝{NC}\n")

    try:
        # Step 1: Start services
        if not start_services():
            sys.exit(1)

        # Wait a bit for services to start
        time.sleep(5)

        # Step 2: Wait for services
        if not wait_for_all_services():
            sys.exit(1)

        # Step 3: Fetch schemas
        schemas = fetch_all_schemas()

        # Step 4: Generate documentation
        if not generate_documentation(schemas):
            sys.exit(1)

        # Step 5: Create index
        create_index_html()

        # Success message
        print(f"\n{GREEN}{'='*50}{NC}")
        print(f"{GREEN}API Documentation generation successful!{NC}")
        print(f"{GREEN}{'='*50}{NC}")
        print(f"\nGenerated files:")
        for html_file in sorted(DOCS_DIR.glob('*.html')):
            print(f"  {GREEN}✓{NC} {html_file.relative_to(PROJECT_ROOT)}")

        print(f"\n{BLUE}Documentation available at:{NC}")
        print(f"  {DOCS_DIR}/swagger-index.html")
        print(f"\n{YELLOW}To view the documentation:{NC}")
        print(f"  Open: {DOCS_DIR.relative_to(PROJECT_ROOT)}/swagger-index.html")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted by user{NC}")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        stop_services()


if __name__ == '__main__':
    main()
