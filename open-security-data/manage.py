#!/usr/bin/env python3
"""
Management script for Open Security Data platform
"""

import asyncio
import click
import logging
import sys
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.config import get_config
from app.models import Source, Base
from app.utils.database import engine, get_db_session, create_tables, drop_tables
from app.collectors.sources import (
    MalwareDomainListCollector, PhishTankCollector, FeodoTrackerCollector,
    ThreatFoxCollector, MalwareBazaarCollector
)

config = get_config()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default sources configuration
DEFAULT_SOURCES = [
    {
        "name": "Malware Domain List",
        "description": "Community-maintained list of malicious domains",
        "url": "http://www.malwaredomainlist.com/hostslist/hosts.txt",
        "source_type": "txt",
        "enabled": True,
        "collection_interval": 86400,  # Daily
        "config": {},
        "headers": {},
        "auth_config": {}
    },
    {
        "name": "PhishTank",
        "description": "Collaborative clearing house for phishing URLs",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "source_type": "json",
        "enabled": True,
        "collection_interval": 3600,  # Hourly
        "config": {},
        "headers": {},
        "auth_config": {}
    },
    {
        "name": "Feodo Tracker",
        "description": "Tracks botnet C&C servers",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "source_type": "json",
        "enabled": True,
        "collection_interval": 3600,  # Hourly
        "config": {},
        "headers": {},
        "auth_config": {}
    },
    {
        "name": "AbuseIPDB Blacklist",
        "description": "Database of abusive IP addresses",
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "source_type": "json",
        "enabled": False,  # Requires API key
        "collection_interval": 3600,
        "config": {
            "api_key": "your-api-key-here"
        },
        "headers": {
            "Accept": "application/json"
        },
        "auth_config": {
            "type": "api_key",
            "header": "Key",
            "key": "your-api-key-here"
        }
    },
    {
        "name": "URLVoid Reputation",
        "description": "URL reputation checking service",
        "url": "http://api.urlvoid.com/1000/",
        "source_type": "json",
        "enabled": False,  # Requires API key and domain list
        "collection_interval": 14400,  # Every 4 hours
        "config": {
            "api_key": "your-api-key-here",
            "domains": []  # List of domains to check
        },
        "headers": {},
        "auth_config": {}
    }
]

def init_database():
    """Initialize database tables"""
    try:
        logger.info("Creating database tables...")
        create_tables()
        logger.info("Database tables created successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        return False

def reset_database():
    """Reset database (drop and recreate tables)"""
    try:
        logger.info("Dropping existing database tables...")
        drop_tables()
        logger.info("Creating new database tables...")
        create_tables()
        logger.info("Database reset successfully")
        return True
    except Exception as e:
        logger.error(f"Error resetting database: {e}")
        return False

def add_default_sources():
    """Add default threat intelligence sources"""
    db = get_db_session()
    try:
        added_count = 0
        
        for source_config in DEFAULT_SOURCES:
            # Check if source already exists
            existing = db.query(Source).filter(Source.name == source_config["name"]).first()
            if existing:
                logger.info(f"Source '{source_config['name']}' already exists, skipping")
                continue
            
            # Create new source
            source = Source(
                name=source_config["name"],
                description=source_config["description"],
                url=source_config["url"],
                source_type=source_config["source_type"],
                enabled=source_config["enabled"],
                collection_interval=source_config["collection_interval"],
                config=source_config["config"],
                headers=source_config["headers"],
                auth_config=source_config["auth_config"],
                status="active",
                created_at=datetime.now(timezone.utc)
            )
            
            db.add(source)
            added_count += 1
            logger.info(f"Added source: {source_config['name']}")
        
        db.commit()
        logger.info(f"Added {added_count} new sources")
        return True
        
    except Exception as e:
        logger.error(f"Error adding default sources: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def list_sources():
    """List all configured sources"""
    db = get_db_session()
    try:
        sources = db.query(Source).order_by(Source.name).all()
        
        if not sources:
            print("No sources configured")
            return
        
        print(f"\nConfigured Sources ({len(sources)}):")
        print("=" * 80)
        
        for source in sources:
            status_icon = "✓" if source.enabled else "✗"
            print(f"{status_icon} {source.name}")
            print(f"   Type: {source.source_type}")
            print(f"   URL: {source.url}")
            print(f"   Status: {source.status}")
            print(f"   Interval: {source.collection_interval}s")
            if source.last_collection:
                print(f"   Last Collection: {source.last_collection}")
            if source.last_error:
                print(f"   Last Error: {source.last_error}")
            print()
            
    finally:
        db.close()

def enable_source(source_name: str):
    """Enable a source"""
    db = get_db_session()
    try:
        source = db.query(Source).filter(Source.name == source_name).first()
        if not source:
            logger.error(f"Source '{source_name}' not found")
            return False
        
        source.enabled = True
        source.status = "active"
        db.commit()
        logger.info(f"Enabled source: {source_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error enabling source: {e}")
        return False
    finally:
        db.close()

def disable_source(source_name: str):
    """Disable a source"""
    db = get_db_session()
    try:
        source = db.query(Source).filter(Source.name == source_name).first()
        if not source:
            logger.error(f"Source '{source_name}' not found")
            return False
        
        source.enabled = False
        source.status = "inactive"
        db.commit()
        logger.info(f"Disabled source: {source_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error disabling source: {e}")
        return False
    finally:
        db.close()

def test_collection(source_name: str):
    """Test collection from a specific source"""
    from app.collectors import CollectorRegistry
    
    db = get_db_session()
    try:
        source = db.query(Source).filter(Source.name == source_name).first()
        if not source:
            logger.error(f"Source '{source_name}' not found")
            return False
        
        logger.info(f"Testing collection from: {source_name}")
        
        async def run_test():
            collector = CollectorRegistry.get_collector(source)
            result = await collector.run_collection()
            
            print(f"\nCollection Test Results for '{source_name}':")
            print(f"Status: {result.status.value}")
            print(f"Items Collected: {result.items_collected}")
            print(f"Items New: {result.items_new}")
            print(f"Items Updated: {result.items_updated}")
            print(f"Items Failed: {result.items_failed}")
            print(f"Duration: {result.duration_seconds:.2f}s")
            
            if result.error_message:
                print(f"Error: {result.error_message}")
        
        asyncio.run(run_test())
        return True
        
    except Exception as e:
        logger.error(f"Error testing collection: {e}")
        return False
    finally:
        db.close()

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Open Security Data Management")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    subparsers.add_parser("init", help="Initialize database")
    
    # Reset command
    subparsers.add_parser("reset", help="Reset database (WARNING: destroys all data)")
    
    # Sources commands
    sources_parser = subparsers.add_parser("sources", help="Manage sources")
    sources_subparsers = sources_parser.add_subparsers(dest="sources_command")
    
    sources_subparsers.add_parser("add-defaults", help="Add default sources")
    sources_subparsers.add_parser("list", help="List all sources")
    
    enable_parser = sources_subparsers.add_parser("enable", help="Enable a source")
    enable_parser.add_argument("name", help="Source name")
    
    disable_parser = sources_subparsers.add_parser("disable", help="Disable a source")
    disable_parser.add_argument("name", help="Source name")
    
    test_parser = sources_subparsers.add_parser("test", help="Test collection from a source")
    test_parser.add_argument("name", help="Source name")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute commands
    if args.command == "init":
        if init_database():
            print("Database initialized successfully")
        else:
            print("Failed to initialize database")
            sys.exit(1)
    
    elif args.command == "reset":
        confirm = input("This will destroy all data. Are you sure? (yes/no): ")
        if confirm.lower() == "yes":
            if reset_database():
                print("Database reset successfully")
            else:
                print("Failed to reset database")
                sys.exit(1)
        else:
            print("Operation cancelled")
    
    elif args.command == "sources":
        if args.sources_command == "add-defaults":
            if add_default_sources():
                print("Default sources added successfully")
            else:
                print("Failed to add default sources")
                sys.exit(1)
        
        elif args.sources_command == "list":
            list_sources()
        
        elif args.sources_command == "enable":
            if enable_source(args.name):
                print(f"Source '{args.name}' enabled")
            else:
                print(f"Failed to enable source '{args.name}'")
                sys.exit(1)
        
        elif args.sources_command == "disable":
            if disable_source(args.name):
                print(f"Source '{args.name}' disabled")
            else:
                print(f"Failed to disable source '{args.name}'")
                sys.exit(1)
        
        elif args.sources_command == "test":
            if test_collection(args.name):
                print("Collection test completed")
            else:
                print("Collection test failed")
                sys.exit(1)
        
        else:
            sources_parser.print_help()

if __name__ == "__main__":
    main()
