#!/usr/bin/env python3
"""
Script to fix incorrect Google Cloud imports in CSPM checks
"""

import os
import re

# Mapping of directories to correct imports
import_mappings = {
    'bigquery': 'from google.cloud import bigquery',
    'cloudsql': 'from googleapiclient import discovery',
    'compute': 'from google.cloud import compute_v1',
    'dns': 'from google.cloud import dns',
    'functions': 'from google.cloud import functions_v1',
    'gke': 'from google.cloud import container_v1',
    'kms': 'from google.cloud import kms',
    'logging': 'from google.cloud import logging_v2',
    'monitoring': 'from google.cloud import monitoring_v3',
    'pubsub': 'from google.cloud import pubsub_v1',
    'secretmanager': 'from google.cloud import secretmanager',
    'storage': 'from google.cloud import storage',
    'cloudarmor': 'from google.cloud import compute_v1',
    'cloudshell': 'from google.cloud import compute_v1',  # Uses compute for shell instances
    'firestore': 'from google.cloud import firestore',
    'vpc': 'from google.cloud import compute_v1',
    'scheduler': 'from google.cloud import scheduler_v1',
    'scc': 'from google.cloud import securitycenter',
    'binaryauth': 'from google.cloud import binaryauthorization_v1',
    'memorystore': 'from google.cloud import redis_v1',
    'asset': 'from google.cloud import asset_v1',
    'service-usage': 'from google.cloud import serviceusage_v1',
    'dataflow': 'from google.cloud import dataflow_v1beta3'
}

def fix_file(filepath, service_dir):
    """Fix imports in a single file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Replace the incorrect import
    old_import = 'from google.cloud import compute_v1'
    if service_dir in import_mappings:
        new_import = import_mappings[service_dir]
        if old_import in content and old_import != new_import:
            content = content.replace(old_import, new_import)
            print(f"Fixed import in {filepath}: {new_import}")
            
            with open(filepath, 'w') as f:
                f.write(content)
            return True
    return False

def main():
    # Path to GCP checks
    gcp_checks_path = '/Users/fab/GitHub/wildbox/open-security-cspm/app/checks/gcp'
    
    if not os.path.exists(gcp_checks_path):
        print(f"Path not found: {gcp_checks_path}")
        return
    
    total_fixed = 0
    
    # Walk through all service directories
    for service_dir in os.listdir(gcp_checks_path):
        service_path = os.path.join(gcp_checks_path, service_dir)
        
        if not os.path.isdir(service_path):
            continue
            
        print(f"Checking service: {service_dir}")
        
        # Process all Python files in the service directory
        for filename in os.listdir(service_path):
            if filename.endswith('.py') and not filename.startswith('__'):
                filepath = os.path.join(service_path, filename)
                if fix_file(filepath, service_dir):
                    total_fixed += 1
    
    print(f"Total files fixed: {total_fixed}")

if __name__ == "__main__":
    main()
