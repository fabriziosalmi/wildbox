import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import json
import random

from schemas import SocialMediaOSINTRequest, SocialMediaOSINTResponse

logger = logging.getLogger(__name__)

TOOL_INFO = {
    "name": "Social Media OSINT Tool",
    "description": "Advanced social media intelligence gathering and analysis tool",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "osint",
    "tags": ["social-media", "osint", "intelligence", "reconnaissance"]
}


class PlatformSearcher:
    """Base class for platform-specific searching."""
    
    def __init__(self, platform_name: str):
        self.platform_name = platform_name
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        """Search for profile on this platform."""
        raise NotImplementedError


class TwitterSearcher(PlatformSearcher):
    def __init__(self):
        super().__init__("Twitter")
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.2)  # Simulate API delay
        
        # Simulate profile existence (70% chance)
        if random.random() > 0.3:
            profile = {
                "platform": "Twitter",
                "username": username,
                "profile_url": f"https://twitter.com/{username}",
                "display_name": f"{username.title()} User",
                "bio": "Simulated Twitter bio for OSINT demo",
                "followers_count": random.randint(10, 50000),
                "following_count": random.randint(50, 2000),
                "tweets_count": random.randint(100, 10000),
                "account_created": (datetime.now() - timedelta(days=random.randint(30, 2000))).isoformat(),
                "verified": random.random() > 0.9,
                "location": random.choice(["New York", "London", "San Francisco", None]),
                "profile_image": f"https://example.com/avatar_{username}.jpg"
            }
            
            if deep_search:
                profile.update({
                    "recent_tweets": [
                        {
                            "text": "Sample tweet for OSINT analysis",
                            "date": (datetime.now() - timedelta(days=1)).isoformat(),
                            "likes": random.randint(0, 100),
                            "retweets": random.randint(0, 50)
                        }
                    ],
                    "posting_patterns": {
                        "most_active_hour": random.randint(8, 22),
                        "avg_tweets_per_day": random.randint(1, 20),
                        "hashtags_used": ["#tech", "#security", "#osint"]
                    }
                })
            
            return profile
        return None


class InstagramSearcher(PlatformSearcher):
    def __init__(self):
        super().__init__("Instagram")
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.2)
        
        if random.random() > 0.4:
            profile = {
                "platform": "Instagram",
                "username": username,
                "profile_url": f"https://instagram.com/{username}",
                "display_name": f"{username.title()}",
                "bio": "📸 OSINT Demo Account",
                "followers_count": random.randint(50, 100000),
                "following_count": random.randint(100, 1000),
                "posts_count": random.randint(20, 2000),
                "is_private": random.random() > 0.6,
                "is_verified": random.random() > 0.95,
                "profile_image": f"https://example.com/insta_{username}.jpg"
            }
            
            if deep_search and not profile["is_private"]:
                profile.update({
                    "recent_posts": [
                        {
                            "image_url": "https://example.com/post1.jpg",
                            "caption": "Sample Instagram post",
                            "date": (datetime.now() - timedelta(days=2)).isoformat(),
                            "likes": random.randint(10, 1000),
                            "comments": random.randint(0, 100)
                        }
                    ],
                    "location_tags": ["New York, NY", "San Francisco, CA"],
                    "hashtags_used": ["#photography", "#travel", "#lifestyle"]
                })
            
            return profile
        return None


class LinkedInSearcher(PlatformSearcher):
    def __init__(self):
        super().__init__("LinkedIn")
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.3)
        
        if random.random() > 0.5:
            profile = {
                "platform": "LinkedIn",
                "username": username,
                "profile_url": f"https://linkedin.com/in/{username}",
                "display_name": f"{username.title()} Professional",
                "headline": "Security Professional | OSINT Researcher",
                "location": random.choice(["New York", "London", "San Francisco", "Remote"]),
                "industry": "Information Technology and Services",
                "connections": f"{random.randint(100, 500)}+ connections",
                "profile_image": f"https://example.com/linkedin_{username}.jpg"
            }
            
            if deep_search:
                profile.update({
                    "experience": [
                        {
                            "title": "Security Analyst",
                            "company": "Tech Corp",
                            "duration": "2020 - Present",
                            "location": "Remote"
                        }
                    ],
                    "education": [
                        {
                            "school": "Example University",
                            "degree": "Computer Science",
                            "years": "2016 - 2020"
                        }
                    ],
                    "skills": ["Cybersecurity", "OSINT", "Risk Assessment"],
                    "certifications": ["CISSP", "CEH"]
                })
            
            return profile
        return None


class GitHubSearcher(PlatformSearcher):
    def __init__(self):
        super().__init__("GitHub")
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.2)
        
        if random.random() > 0.4:
            profile = {
                "platform": "GitHub",
                "username": username,
                "profile_url": f"https://github.com/{username}",
                "display_name": username,
                "bio": "Security enthusiast and developer",
                "public_repos": random.randint(5, 200),
                "followers": random.randint(10, 1000),
                "following": random.randint(20, 500),
                "account_created": (datetime.now() - timedelta(days=random.randint(100, 2000))).isoformat(),
                "location": random.choice(["San Francisco", "New York", "London", None]),
                "company": random.choice(["@tech-corp", "@security-firm", None])
            }
            
            if deep_search:
                profile.update({
                    "top_repositories": [
                        {
                            "name": "security-tools",
                            "description": "Collection of security scripts",
                            "language": "Python",
                            "stars": random.randint(5, 100),
                            "last_updated": (datetime.now() - timedelta(days=10)).isoformat()
                        }
                    ],
                    "languages_used": ["Python", "JavaScript", "Go"],
                    "contribution_activity": {
                        "total_commits": random.randint(100, 2000),
                        "current_streak": random.randint(0, 100)
                    }
                })
            
            return profile
        return None


class RedditSearcher(PlatformSearcher):
    def __init__(self):
        super().__init__("Reddit")
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.2)
        
        if random.random() > 0.5:
            profile = {
                "platform": "Reddit",
                "username": username,
                "profile_url": f"https://reddit.com/user/{username}",
                "account_created": (datetime.now() - timedelta(days=random.randint(30, 1500))).isoformat(),
                "comment_karma": random.randint(100, 50000),
                "post_karma": random.randint(10, 10000),
                "is_premium": random.random() > 0.9
            }
            
            if deep_search:
                profile.update({
                    "active_subreddits": [
                        "r/cybersecurity", "r/netsec", "r/osint", 
                        "r/programming", "r/privacy"
                    ],
                    "recent_activity": [
                        {
                            "type": "comment",
                            "subreddit": "r/cybersecurity",
                            "content": "Great post about OSINT techniques!",
                            "score": random.randint(1, 50),
                            "date": (datetime.now() - timedelta(hours=6)).isoformat()
                        }
                    ],
                    "posting_patterns": {
                        "most_active_time": "Evening",
                        "avg_posts_per_week": random.randint(2, 20)
                    }
                })
            
            return profile
        return None


class FacebookSearcher(PlatformSearcher):
    def __init__(self):
        super().__init__("Facebook")
    
    async def search_profile(self, username: str, deep_search: bool = False) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.3)
        
        if random.random() > 0.6:
            profile = {
                "platform": "Facebook",
                "username": username,
                "profile_url": f"https://facebook.com/{username}",
                "display_name": f"{username.title()} User",
                "is_private": random.random() > 0.3,
                "profile_image": f"https://example.com/fb_{username}.jpg",
                "location": random.choice(["New York", "Los Angeles", "Chicago", None])
            }
            
            if deep_search and not profile["is_private"]:
                profile.update({
                    "recent_posts": [
                        {
                            "content": "Sample Facebook post for OSINT analysis",
                            "date": (datetime.now() - timedelta(days=3)).isoformat(),
                            "likes": random.randint(5, 100),
                            "comments": random.randint(0, 20)
                        }
                    ],
                    "check_ins": ["Coffee Shop Downtown", "Tech Conference 2023"],
                    "interests": ["Technology", "Security", "Privacy"]
                })
            
            return profile
        return None


def get_platform_searcher(platform: str) -> Optional[PlatformSearcher]:
    """Get the appropriate searcher for a platform."""
    searchers = {
        "twitter": TwitterSearcher(),
        "instagram": InstagramSearcher(),
        "linkedin": LinkedInSearcher(),
        "github": GitHubSearcher(),
        "reddit": RedditSearcher(),
        "facebook": FacebookSearcher()
    }
    return searchers.get(platform.lower())


async def search_all_platforms(username: str, platforms: List[str], deep_search: bool = False) -> List[Dict[str, Any]]:
    """Search for profiles across all specified platforms."""
    profiles_found = []
    
    for platform in platforms:
        searcher = get_platform_searcher(platform)
        if searcher:
            try:
                profile = await searcher.search_profile(username, deep_search)
                if profile:
                    profiles_found.append(profile)
            except Exception as e:
                logger.warning(f"Error searching {platform}: {str(e)}")
    
    return profiles_found


def perform_cross_platform_analysis(profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze patterns across multiple platforms."""
    analysis = {
        "platforms_with_profiles": len(profiles),
        "consistent_usernames": True,  # Assume consistent since we're searching by username
        "profile_consistency": {},
        "common_themes": [],
        "timeline_analysis": {}
    }
    
    # Analyze profile consistency
    display_names = [p.get("display_name", "") for p in profiles if p.get("display_name")]
    locations = [p.get("location", "") for p in profiles if p.get("location")]
    
    if display_names:
        analysis["profile_consistency"]["display_names"] = list(set(display_names))
    if locations:
        analysis["profile_consistency"]["locations"] = list(set(locations))
    
    # Look for common themes in bios
    bios = [p.get("bio", "") for p in profiles if p.get("bio")]
    if bios:
        # Simple keyword extraction
        keywords = []
        for bio in bios:
            words = re.findall(r'\b\w+\b', bio.lower())
            keywords.extend([w for w in words if len(w) > 3])
        
        # Find most common keywords
        from collections import Counter
        common_words = Counter(keywords).most_common(5)
        analysis["common_themes"] = [word for word, count in common_words if count > 1]
    
    # Timeline analysis
    creation_dates = []
    for profile in profiles:
        if profile.get("account_created"):
            try:
                date = datetime.fromisoformat(profile["account_created"].replace('Z', '+00:00'))
                creation_dates.append((profile["platform"], date))
            except (ValueError, KeyError) as e:
                logger.debug(f"Error parsing creation date for profile: {e}")
                pass
    
    if creation_dates:
        creation_dates.sort(key=lambda x: x[1])
        analysis["timeline_analysis"] = {
            "first_platform": creation_dates[0][0],
            "latest_platform": creation_dates[-1][0],
            "account_creation_span": str(creation_dates[-1][1] - creation_dates[0][1])
        }
    
    return analysis


def analyze_metadata(profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze metadata patterns across profiles."""
    metadata = {
        "posting_patterns": {},
        "engagement_analysis": {},
        "content_themes": {},
        "temporal_analysis": {},
        "privacy_settings": {}
    }
    
    # Analyze posting patterns
    platforms_with_patterns = []
    for profile in profiles:
        if profile.get("posting_patterns"):
            platforms_with_patterns.append({
                "platform": profile["platform"],
                "patterns": profile["posting_patterns"]
            })
    
    if platforms_with_patterns:
        metadata["posting_patterns"] = platforms_with_patterns
    
    # Engagement analysis
    engagement_data = []
    for profile in profiles:
        platform_engagement = {"platform": profile["platform"]}
        
        if "followers_count" in profile:
            platform_engagement["followers"] = profile["followers_count"]
        if "following_count" in profile:
            platform_engagement["following"] = profile["following_count"]
        if "connections" in profile:
            platform_engagement["connections"] = profile["connections"]
        
        if len(platform_engagement) > 1:
            engagement_data.append(platform_engagement)
    
    if engagement_data:
        metadata["engagement_analysis"] = engagement_data
    
    # Privacy analysis
    privacy_data = []
    for profile in profiles:
        if "is_private" in profile:
            privacy_data.append({
                "platform": profile["platform"],
                "is_private": profile["is_private"]
            })
    
    if privacy_data:
        metadata["privacy_settings"] = privacy_data
    
    return metadata


def identify_risk_indicators(profiles: List[Dict[str, Any]], cross_platform_analysis: Dict[str, Any]) -> List[str]:
    """Identify potential security and privacy risks."""
    risks = []
    
    # Check for public profiles
    public_profiles = [p for p in profiles if not p.get("is_private", False)]
    if len(public_profiles) > 3:
        risks.append(f"Multiple public profiles ({len(public_profiles)}) may expose personal information")
    
    # Check for location exposure
    locations = [p.get("location", "") for p in profiles if p.get("location")]
    if len(set(locations)) == 1 and locations[0]:
        risks.append("Consistent location information across platforms may aid in physical tracking")
    
    # Check for oversharing
    for profile in profiles:
        if profile.get("recent_posts") or profile.get("recent_activity"):
            risks.append(f"Active posting on {profile['platform']} may reveal patterns and personal information")
    
    # Check for professional information exposure
    linkedin_profiles = [p for p in profiles if p["platform"] == "LinkedIn"]
    other_profiles = [p for p in profiles if p["platform"] != "LinkedIn"]
    
    if linkedin_profiles and other_profiles:
        risks.append("Professional information on LinkedIn combined with personal social media may create comprehensive profile")
    
    # Check for username consistency
    if len(profiles) > 2:
        risks.append("Consistent username across platforms makes correlation easier for adversaries")
    
    # Check for high engagement
    high_engagement_profiles = []
    for profile in profiles:
        if (profile.get("followers_count", 0) > 1000 or 
            profile.get("public_repos", 0) > 50 or
            profile.get("comment_karma", 0) > 10000):
            high_engagement_profiles.append(profile["platform"])
    
    if high_engagement_profiles:
        risks.append(f"High visibility on {', '.join(high_engagement_profiles)} increases exposure to social engineering")
    
    return risks


def generate_intelligence_summary(profiles: List[Dict[str, Any]], 
                                cross_platform_analysis: Dict[str, Any],
                                risk_indicators: List[str]) -> Dict[str, Any]:
    """Generate an intelligence summary."""
    summary = {
        "target_profile": {
            "digital_footprint_size": "Large" if len(profiles) > 3 else "Medium" if len(profiles) > 1 else "Small",
            "platforms_present": [p["platform"] for p in profiles],
            "estimated_activity_level": "High" if any(p.get("recent_posts") or p.get("recent_activity") for p in profiles) else "Low"
        },
        "osint_value": {
            "information_richness": "High" if len(profiles) > 2 else "Medium" if len(profiles) > 0 else "Low",
            "correlation_potential": "High" if cross_platform_analysis.get("platforms_with_profiles", 0) > 2 else "Medium",
            "verification_sources": len([p for p in profiles if p.get("verified", False) or p.get("is_verified", False)])
        },
        "security_posture": {
            "privacy_awareness": "Low" if len([p for p in profiles if p.get("is_private", False)]) < len(profiles) // 2 else "High",
            "risk_level": "High" if len(risk_indicators) > 3 else "Medium" if len(risk_indicators) > 1 else "Low",
            "exposure_points": len(profiles)
        },
        "recommendations": [
            "Cross-reference information across platforms for verification",
            "Monitor for social engineering opportunities",
            "Analyze posting patterns for behavioral insights",
            "Check for data correlation opportunities"
        ]
    }
    
    return summary


async def execute_tool(request: SocialMediaOSINTRequest) -> SocialMediaOSINTResponse:
    """Execute social media OSINT analysis."""
    try:
        logger.info(f"Starting social media OSINT for username: {request.username}")
        
        # Search across all requested platforms
        profiles_found = await search_all_platforms(
            request.username, 
            request.platforms, 
            request.deep_search
        )
        
        # Perform cross-platform analysis
        cross_platform_analysis = perform_cross_platform_analysis(profiles_found)
        
        # Analyze metadata if requested
        metadata_analysis = None
        if request.include_metadata:
            metadata_analysis = analyze_metadata(profiles_found)
        
        # Identify risk indicators
        risk_indicators = identify_risk_indicators(profiles_found, cross_platform_analysis)
        
        # Generate intelligence summary
        intelligence_summary = generate_intelligence_summary(
            profiles_found, cross_platform_analysis, risk_indicators
        )
        
        return SocialMediaOSINTResponse(
            username=request.username,
            platforms_searched=request.platforms,
            profiles_found=profiles_found,
            cross_platform_analysis=cross_platform_analysis,
            metadata_analysis=metadata_analysis,
            risk_indicators=risk_indicators,
            intelligence_summary=intelligence_summary,
            timestamp=datetime.now().isoformat(),
            success=True,
            message=f"Found {len(profiles_found)} profiles across {len(request.platforms)} platforms"
        )
        
    except Exception as e:
        logger.error(f"Error in social media OSINT: {str(e)}")
        return SocialMediaOSINTResponse(
            username=request.username,
            platforms_searched=request.platforms,
            profiles_found=[],
            cross_platform_analysis={},
            risk_indicators=[],
            intelligence_summary={},
            timestamp=datetime.now().isoformat(),
            success=False,
            message=f"OSINT analysis failed: {str(e)}"
        )
