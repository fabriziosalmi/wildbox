import asyncio
import re
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from schemas import ThreatIntelligenceRequest, ThreatIntelligenceResponse, ThreatIntelligenceSource

# Tool metadata
TOOL_INFO = {
    "name": "threat_intelligence_aggregator",
    "display_name": "Threat Intelligence Aggregator",
    "description": "Aggregates threat intelligence data from multiple sources for comprehensive threat analysis",
    "category": "threat_intelligence",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": ThreatIntelligenceRequest.model_json_schema(),
    "output_schema": ThreatIntelligenceResponse.model_json_schema(),
    "requires_api_key": False,
    "rate_limit": {
        "requests_per_minute": 30,
        "requests_per_hour": 500
    }
}

class ThreatIntelligenceAggregator:
    """Threat Intelligence Aggregator for comprehensive threat analysis"""
    
    def __init__(self):
        self.malware_families_db = {
            "trojan": ["emotet", "trickbot", "qakbot", "dridex", "azorult"],
            "ransomware": ["lockbit", "conti", "ryuk", "maze", "sodinokibi"],
            "apt": ["apt1", "apt28", "apt29", "lazarus", "equation"],
            "botnet": ["mirai", "conficker", "sality", "necurs", "gameover"]
        }
        
        self.threat_types = [
            "malware", "phishing", "c2", "exploit_kit", "ransomware",
            "trojan", "botnet", "apt", "suspicious", "malicious"
        ]
        
        self.country_codes = {
            "US": "United States", "CN": "China", "RU": "Russia",
            "KP": "North Korea", "IR": "Iran", "DE": "Germany"
        }
    
    def _validate_indicator(self, indicator: str, indicator_type: str) -> bool:
        """Validate indicator format"""
        patterns = {
            "ip": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
            "domain": r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
            "hash": r"^[a-fA-F0-9]{32,64}$",
            "url": r"^https?://",
            "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        }
        
        pattern = patterns.get(indicator_type.lower())
        if not pattern:
            return False
            
        return bool(re.match(pattern, indicator))
    
    def _simulate_virustotal_data(self, indicator: str, indicator_type: str) -> ThreatIntelligenceSource:
        """Simulate VirusTotal API response"""
        threat_score = hash(indicator) % 100
        confidence = 85 + (hash(indicator + "vt") % 15)
        
        malware_families = []
        threat_types = []
        
        if threat_score > 70:
            malware_families = ["emotet", "trickbot"]
            threat_types = ["trojan", "malware"]
        elif threat_score > 40:
            malware_families = ["mirai"]
            threat_types = ["botnet"]
        
        return ThreatIntelligenceSource(
            name="VirusTotal",
            reputation_score=100 - threat_score if threat_score > 30 else None,
            last_seen=datetime.now().strftime("%Y-%m-%d") if threat_score > 20 else None,
            first_seen=(datetime.now() - timedelta(days=hash(indicator) % 365)).strftime("%Y-%m-%d"),
            malware_families=malware_families,
            threat_types=threat_types,
            confidence=confidence,
            source_url="https://virustotal.com"
        )
    
    def _simulate_alienvault_data(self, indicator: str, indicator_type: str) -> ThreatIntelligenceSource:
        """Simulate AlienVault OTX API response"""
        threat_score = hash(indicator + "otx") % 100
        confidence = 70 + (hash(indicator + "otx") % 25)
        
        malware_families = []
        threat_types = []
        
        if threat_score > 60:
            malware_families = ["apt28", "lazarus"]
            threat_types = ["apt", "c2"]
        elif threat_score > 30:
            threat_types = ["suspicious"]
        
        return ThreatIntelligenceSource(
            name="AlienVault OTX",
            reputation_score=100 - threat_score if threat_score > 25 else None,
            last_seen=datetime.now().strftime("%Y-%m-%d") if threat_score > 15 else None,
            first_seen=(datetime.now() - timedelta(days=hash(indicator + "otx") % 200)).strftime("%Y-%m-%d"),
            malware_families=malware_families,
            threat_types=threat_types,
            confidence=confidence,
            source_url="https://otx.alienvault.com"
        )
    
    def _simulate_threatcrowd_data(self, indicator: str, indicator_type: str) -> ThreatIntelligenceSource:
        """Simulate ThreatCrowd API response"""
        threat_score = hash(indicator + "tc") % 100
        confidence = 60 + (hash(indicator + "tc") % 30)
        
        malware_families = []
        threat_types = []
        
        if threat_score > 75:
            malware_families = ["lockbit", "conti"]
            threat_types = ["ransomware"]
        elif threat_score > 45:
            threat_types = ["phishing"]
        
        return ThreatIntelligenceSource(
            name="ThreatCrowd",
            reputation_score=100 - threat_score if threat_score > 35 else None,
            last_seen=datetime.now().strftime("%Y-%m-%d") if threat_score > 25 else None,
            first_seen=(datetime.now() - timedelta(days=hash(indicator + "tc") % 300)).strftime("%Y-%m-%d"),
            malware_families=malware_families,
            threat_types=threat_types,
            confidence=confidence,
            source_url="https://threatcrowd.org"
        )
    
    def _simulate_malwarebazaar_data(self, indicator: str, indicator_type: str) -> ThreatIntelligenceSource:
        """Simulate MalwareBazaar API response"""
        threat_score = hash(indicator + "mb") % 100
        confidence = 80 + (hash(indicator + "mb") % 20)
        
        malware_families = []
        threat_types = []
        
        if indicator_type == "hash" and threat_score > 50:
            malware_families = ["azorult", "dridex"]
            threat_types = ["trojan", "malware"]
        elif threat_score > 40:
            threat_types = ["exploit_kit"]
        
        return ThreatIntelligenceSource(
            name="MalwareBazaar",
            reputation_score=100 - threat_score if threat_score > 40 else None,
            last_seen=datetime.now().strftime("%Y-%m-%d") if threat_score > 30 else None,
            first_seen=(datetime.now() - timedelta(days=hash(indicator + "mb") % 180)).strftime("%Y-%m-%d"),
            malware_families=malware_families,
            threat_types=threat_types,
            confidence=confidence,
            source_url="https://bazaar.abuse.ch"
        )
    
    def _calculate_overall_threat_score(self, sources: List[ThreatIntelligenceSource]) -> int:
        """Calculate overall threat score from multiple sources"""
        total_score = 0
        total_weight = 0
        
        for source in sources:
            if source.reputation_score is not None:
                weight = source.confidence / 100
                score = 100 - source.reputation_score
                total_score += score * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0
        
        return int(total_score / total_weight)
    
    def _get_confidence_level(self, score: int, sources_count: int) -> str:
        """Determine confidence level based on score and sources"""
        if sources_count >= 3 and score > 80:
            return "Very High"
        elif sources_count >= 2 and score > 60:
            return "High"
        elif score > 40:
            return "Medium"
        elif score > 20:
            return "Low"
        else:
            return "Very Low"
    
    def _classify_threat(self, threat_types: List[str], malware_families: List[str]) -> str:
        """Classify threat based on types and families"""
        if "ransomware" in threat_types:
            return "Ransomware"
        elif "apt" in threat_types:
            return "Advanced Persistent Threat"
        elif "trojan" in threat_types or "malware" in threat_types:
            return "Malware"
        elif "botnet" in threat_types:
            return "Botnet"
        elif "phishing" in threat_types:
            return "Phishing"
        elif "c2" in threat_types:
            return "Command & Control"
        elif any(t in threat_types for t in ["suspicious", "exploit_kit"]):
            return "Suspicious Activity"
        else:
            return "Unknown"
    
    def _generate_risk_factors(self, sources: List[ThreatIntelligenceSource], 
                             threat_score: int) -> List[str]:
        """Generate risk factors based on analysis"""
        factors = []
        
        if threat_score > 80:
            factors.append("High threat confidence across multiple sources")
        
        malware_families = set()
        threat_types = set()
        
        for source in sources:
            malware_families.update(source.malware_families)
            threat_types.update(source.threat_types)
        
        if "ransomware" in threat_types:
            factors.append("Associated with ransomware campaigns")
        
        if "apt" in threat_types:
            factors.append("Linked to Advanced Persistent Threat groups")
        
        if len(malware_families) > 2:
            factors.append("Multiple malware family associations")
        
        recent_activity = any(
            source.last_seen and 
            datetime.strptime(source.last_seen, "%Y-%m-%d") > datetime.now() - timedelta(days=30)
            for source in sources if source.last_seen
        )
        
        if recent_activity:
            factors.append("Recent malicious activity detected")
        
        return factors
    
    def _generate_mitigations(self, threat_classification: str, 
                            threat_types: List[str]) -> List[str]:
        """Generate mitigation recommendations"""
        mitigations = []
        
        if threat_classification == "Ransomware":
            mitigations.extend([
                "Implement robust backup and recovery procedures",
                "Deploy endpoint detection and response (EDR) solutions",
                "Conduct regular security awareness training"
            ])
        elif threat_classification == "Advanced Persistent Threat":
            mitigations.extend([
                "Implement network segmentation",
                "Deploy advanced threat detection systems",
                "Conduct regular threat hunting activities"
            ])
        elif "botnet" in threat_types:
            mitigations.extend([
                "Block communication to C2 servers",
                "Implement DNS filtering",
                "Monitor for unusual network traffic patterns"
            ])
        elif "phishing" in threat_types:
            mitigations.extend([
                "Implement email security gateways",
                "Conduct phishing simulation exercises",
                "Deploy URL filtering solutions"
            ])
        
        # General mitigations
        mitigations.extend([
            "Monitor for indicators of compromise (IoCs)",
            "Update threat intelligence feeds",
            "Review and update security policies"
        ])
        
        return mitigations

async def execute_tool(request: ThreatIntelligenceRequest) -> ThreatIntelligenceResponse:
    """Execute threat intelligence aggregation analysis"""
    start_time = time.time()
    
    aggregator = ThreatIntelligenceAggregator()
    
    # Validate indicator
    if not aggregator._validate_indicator(request.indicator, request.indicator_type):
        raise ValueError(f"Invalid {request.indicator_type} format: {request.indicator}")
    
    # Simulate API calls to different sources
    sources_data = []
    
    if "virustotal" in request.sources:
        vt_data = aggregator._simulate_virustotal_data(request.indicator, request.indicator_type)
        if vt_data.confidence >= request.confidence_threshold:
            sources_data.append(vt_data)
    
    if "alienvault" in request.sources:
        otx_data = aggregator._simulate_alienvault_data(request.indicator, request.indicator_type)
        if otx_data.confidence >= request.confidence_threshold:
            sources_data.append(otx_data)
    
    if "threatcrowd" in request.sources:
        tc_data = aggregator._simulate_threatcrowd_data(request.indicator, request.indicator_type)
        if tc_data.confidence >= request.confidence_threshold:
            sources_data.append(tc_data)
    
    if "malwarebazaar" in request.sources:
        mb_data = aggregator._simulate_malwarebazaar_data(request.indicator, request.indicator_type)
        if mb_data.confidence >= request.confidence_threshold:
            sources_data.append(mb_data)
    
    # Add small delay to simulate real API calls
    await asyncio.sleep(0.1)
    
    # Aggregate data
    all_malware_families = list(set([
        family for source in sources_data for family in source.malware_families
    ]))
    
    all_threat_types = list(set([
        threat_type for source in sources_data for threat_type in source.threat_types
    ]))
    
    overall_threat_score = aggregator._calculate_overall_threat_score(sources_data)
    confidence_level = aggregator._get_confidence_level(overall_threat_score, len(sources_data))
    threat_classification = aggregator._classify_threat(all_threat_types, all_malware_families)
    
    # Generate timeline
    activity_timeline = []
    for source in sources_data:
        if source.first_seen:
            activity_timeline.append({
                "date": source.first_seen,
                "event": f"First seen by {source.name}",
                "type": "first_detection"
            })
        if source.last_seen:
            activity_timeline.append({
                "date": source.last_seen,
                "event": f"Last seen by {source.name}",
                "type": "recent_activity"
            })
    
    # Sort timeline by date
    activity_timeline.sort(key=lambda x: x["date"])
    
    # Generate additional intelligence
    risk_factors = aggregator._generate_risk_factors(sources_data, overall_threat_score)
    mitigations = aggregator._generate_mitigations(threat_classification, all_threat_types)
    
    # Simulate related indicators and campaign attribution
    related_indicators = []
    campaign_attribution = []
    
    if overall_threat_score > 70:
        related_indicators = [
            f"192.168.{hash(request.indicator) % 255}.{hash(request.indicator + '1') % 255}",
            f"evil-{hash(request.indicator) % 1000}.com"
        ]
        campaign_attribution = ["Operation ShadowStorm", "APT-SimGroup"]
    
    # Calculate processing time
    processing_time = int((time.time() - start_time) * 1000)
    
    return ThreatIntelligenceResponse(
        indicator=request.indicator,
        indicator_type=request.indicator_type,
        overall_threat_score=overall_threat_score,
        confidence_level=confidence_level,
        threat_classification=threat_classification,
        sources_data=sources_data,
        malware_families=all_malware_families,
        threat_types=all_threat_types,
        countries=["US", "RU", "CN"],  # Simulated
        asn_info={"asn": "AS12345", "org": "Example ISP", "country": "US"},
        first_seen=activity_timeline[0]["date"] if activity_timeline else None,
        last_seen=activity_timeline[-1]["date"] if activity_timeline else None,
        activity_timeline=activity_timeline,
        risk_factors=risk_factors,
        mitigations=mitigations,
        related_indicators=related_indicators,
        campaign_attribution=campaign_attribution,
        timestamp=datetime.now().isoformat(),
        processing_time_ms=processing_time
    )
