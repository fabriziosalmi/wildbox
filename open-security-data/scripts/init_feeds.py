#!/usr/bin/env python3
"""
Initialize threat intelligence feed sources in the database

This script adds default threat intelligence feeds to the database.
Run this after database initialization to populate the sources table.
"""

import sys
import os
from datetime import datetime, timezone

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.database import get_db_session
from app.models import Source
from sqlalchemy.exc import IntegrityError

def init_feeds():
    """Initialize threat intelligence feeds"""

    feeds = [
        {
            "name": "ThreatFox",
            "description": "ThreatFox is a free platform for sharing indicators of compromise (IOCs) associated with malware. Operated by abuse.ch.",
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "source_type": "api",
            "config": {
                "query": "get_iocs",
                "days": 1,
                "collector_class": "ThreatFoxCollector"
            },
            "enabled": True,
            "collection_interval": 3600,  # 1 hour
            "status": "active"
        },
        {
            "name": "Feodo Tracker",
            "description": "Feodo Tracker is a project to track the Feodo/Emotet/Dridex botnet infrastructure. It provides a list of botnet C&C servers.",
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "source_type": "api",
            "config": {
                "collector_class": "FeodoTrackerCollector"
            },
            "enabled": True,
            "collection_interval": 3600,  # 1 hour
            "status": "active"
        },
        {
            "name": "MalwareBazaar",
            "description": "MalwareBazaar is a project to share malware samples with the infosec community. Operated by abuse.ch.",
            "url": "https://mb-api.abuse.ch/api/v1/",
            "source_type": "api",
            "config": {
                "query": "get_recent",
                "selector": "time",
                "collector_class": "MalwareBazaarCollector"
            },
            "enabled": True,
            "collection_interval": 7200,  # 2 hours
            "status": "idle"
        },
        {
            "name": "PhishTank",
            "description": "PhishTank is a collaborative clearing house for data and information about phishing on the Internet.",
            "url": "http://data.phishtank.com/data/online-valid.json",
            "source_type": "feed",
            "config": {
                "collector_class": "PhishTankCollector"
            },
            "enabled": True,
            "collection_interval": 3600,  # 1 hour
            "status": "idle"
        },
        {
            "name": "AbuseIPDB",
            "description": "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet.",
            "url": "https://api.abuseipdb.com/api/v2/blacklist",
            "source_type": "api",
            "config": {
                "api_key": "YOUR_API_KEY_HERE",
                "collector_class": "AbuseIPDBCollector"
            },
            "headers": {
                "Accept": "application/json"
            },
            "enabled": False,  # Disabled by default - requires API key
            "collection_interval": 86400,  # 24 hours
            "status": "inactive"
        },
        {
            "name": "Malware Domain List",
            "description": "The Malware Domain List is a non-commercial community project to track domains used by malware.",
            "url": "http://www.malwaredomainlist.com/hostslist/hosts.txt",
            "source_type": "feed",
            "config": {
                "collector_class": "MalwareDomainListCollector"
            },
            "enabled": False,  # Disabled by default - may be deprecated
            "collection_interval": 86400,  # 24 hours
            "status": "inactive"
        }
    ]

    db = get_db_session()
    added_count = 0
    updated_count = 0
    skipped_count = 0

    try:
        for feed_data in feeds:
            try:
                # Check if source already exists
                existing = db.query(Source).filter(Source.name == feed_data["name"]).first()

                if existing:
                    print(f"⚠️  Feed '{feed_data['name']}' already exists - skipping")
                    skipped_count += 1
                    continue

                # Create new source
                source = Source(**feed_data)
                db.add(source)
                db.commit()

                status_icon = "✅" if feed_data["enabled"] else "⏸️"
                print(f"{status_icon} Added feed: {feed_data['name']} ({feed_data['source_type']})")
                added_count += 1

            except IntegrityError as e:
                db.rollback()
                print(f"❌ Error adding feed '{feed_data['name']}': {e}")
                continue

        print(f"\n📊 Summary:")
        print(f"   - Added: {added_count}")
        print(f"   - Skipped (already exists): {skipped_count}")
        print(f"   - Total feeds in database: {db.query(Source).count()}")

        # Show active feeds
        active_feeds = db.query(Source).filter(Source.enabled == True).all()
        print(f"\n🟢 Active Feeds ({len(active_feeds)}):")
        for feed in active_feeds:
            print(f"   - {feed.name}")

        inactive_feeds = db.query(Source).filter(Source.enabled == False).all()
        if inactive_feeds:
            print(f"\n⚪ Inactive Feeds ({len(inactive_feeds)}):")
            for feed in inactive_feeds:
                print(f"   - {feed.name} (requires configuration)")

    except Exception as e:
        db.rollback()
        print(f"❌ Error initializing feeds: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    print("🚀 Initializing Threat Intelligence Feeds...\n")
    init_feeds()
    print("\n✅ Feed initialization complete!")
