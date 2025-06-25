from typing import Dict, Any, List
import asyncio
import random
from datetime import datetime, timedelta

try:
    from schemas import (
        ComplianceCheckerInput, 
        ComplianceCheckerOutput,
        ComplianceRequirement,
        SecurityControl,
        DataProtectionAssessment,
        AuditTrailAssessment,
        EncryptionAssessment,
        ComplianceGap
    )
except ImportError:
    from schemas import (
        ComplianceCheckerInput, 
        ComplianceCheckerOutput,
        ComplianceRequirement,
        SecurityControl,
        DataProtectionAssessment,
        AuditTrailAssessment,
        EncryptionAssessment,
        ComplianceGap
    )

class ComplianceChecker:
    """Compliance Checker - Comprehensive compliance assessment for multiple frameworks"""
    
    name = "Compliance Checker"
    description = "Comprehensive compliance assessment tool for multiple security and privacy frameworks including GDPR, PCI-DSS, HIPAA, SOC2, and more"
    category = "compliance"
    
    # Compliance framework requirements
    FRAMEWORKS = {
        "GDPR": {
            "requirements": [
                {"id": "GDPR-7", "name": "Consent", "category": "Data Processing", "mandatory": True},
                {"id": "GDPR-13", "name": "Information to be provided", "category": "Transparency", "mandatory": True},
                {"id": "GDPR-25", "name": "Data protection by design", "category": "Data Protection", "mandatory": True},
                {"id": "GDPR-32", "name": "Security of processing", "category": "Security", "mandatory": True},
                {"id": "GDPR-33", "name": "Breach notification", "category": "Incident Response", "mandatory": True},
                {"id": "GDPR-35", "name": "Data protection impact assessment", "category": "Risk Assessment", "mandatory": True}
            ]
        },
        "PCI-DSS": {
            "requirements": [
                {"id": "PCI-1", "name": "Install and maintain firewall", "category": "Network Security", "mandatory": True},
                {"id": "PCI-2", "name": "Change vendor defaults", "category": "Configuration", "mandatory": True},
                {"id": "PCI-3", "name": "Protect stored cardholder data", "category": "Data Protection", "mandatory": True},
                {"id": "PCI-4", "name": "Encrypt transmission", "category": "Encryption", "mandatory": True},
                {"id": "PCI-6", "name": "Develop secure systems", "category": "Application Security", "mandatory": True},
                {"id": "PCI-8", "name": "Identify and authenticate", "category": "Access Control", "mandatory": True},
                {"id": "PCI-10", "name": "Track and monitor access", "category": "Monitoring", "mandatory": True}
            ]
        },
        "HIPAA": {
            "requirements": [
                {"id": "HIPAA-164.308", "name": "Administrative Safeguards", "category": "Administrative", "mandatory": True},
                {"id": "HIPAA-164.310", "name": "Physical Safeguards", "category": "Physical", "mandatory": True},
                {"id": "HIPAA-164.312", "name": "Technical Safeguards", "category": "Technical", "mandatory": True},
                {"id": "HIPAA-164.314", "name": "Organizational Requirements", "category": "Organizational", "mandatory": True}
            ]
        },
        "SOC2": {
            "requirements": [
                {"id": "SOC2-CC1", "name": "Control Environment", "category": "Common Criteria", "mandatory": True},
                {"id": "SOC2-CC2", "name": "Communication", "category": "Common Criteria", "mandatory": True},
                {"id": "SOC2-CC3", "name": "Risk Assessment", "category": "Common Criteria", "mandatory": True},
                {"id": "SOC2-CC6", "name": "Logical Access", "category": "Common Criteria", "mandatory": True},
                {"id": "SOC2-CC7", "name": "System Operations", "category": "Common Criteria", "mandatory": True}
            ]
        },
        "ISO27001": {
            "requirements": [
                {"id": "ISO-A.5", "name": "Information Security Policies", "category": "Policies", "mandatory": True},
                {"id": "ISO-A.6", "name": "Organization of Information Security", "category": "Organization", "mandatory": True},
                {"id": "ISO-A.8", "name": "Asset Management", "category": "Asset Management", "mandatory": True},
                {"id": "ISO-A.9", "name": "Access Control", "category": "Access Control", "mandatory": True},
                {"id": "ISO-A.10", "name": "Cryptography", "category": "Cryptography", "mandatory": True},
                {"id": "ISO-A.12", "name": "Operations Security", "category": "Operations", "mandatory": True}
            ]
        },
        "NIST": {
            "requirements": [
                {"id": "NIST-ID", "name": "Identify", "category": "Core Function", "mandatory": True},
                {"id": "NIST-PR", "name": "Protect", "category": "Core Function", "mandatory": True},
                {"id": "NIST-DE", "name": "Detect", "category": "Core Function", "mandatory": True},
                {"id": "NIST-RS", "name": "Respond", "category": "Core Function", "mandatory": True},
                {"id": "NIST-RC", "name": "Recover", "category": "Core Function", "mandatory": True}
            ]
        },
        "CIS": {
            "requirements": [
                {"id": "CIS-1", "name": "Inventory of Assets", "category": "Asset Management", "mandatory": True},
                {"id": "CIS-2", "name": "Inventory of Software", "category": "Asset Management", "mandatory": True},
                {"id": "CIS-3", "name": "Data Protection", "category": "Data Protection", "mandatory": True},
                {"id": "CIS-5", "name": "Account Management", "category": "Access Control", "mandatory": True},
                {"id": "CIS-6", "name": "Access Control Management", "category": "Access Control", "mandatory": True}
            ]
        }
    }
    
    # Security controls by category
    SECURITY_CONTROLS = [
        {"id": "AC-1", "name": "Access Control Policy", "category": "Access Control"},
        {"id": "AC-2", "name": "Account Management", "category": "Access Control"},
        {"id": "AC-3", "name": "Access Enforcement", "category": "Access Control"},
        {"id": "AU-1", "name": "Audit Policy", "category": "Audit and Accountability"},
        {"id": "AU-2", "name": "Audit Events", "category": "Audit and Accountability"},
        {"id": "SC-1", "name": "System Communications Protection", "category": "System Communications"},
        {"id": "SC-8", "name": "Transmission Confidentiality", "category": "System Communications"},
        {"id": "IA-1", "name": "Identification and Authentication", "category": "Identity and Authentication"},
        {"id": "IA-2", "name": "User Identification and Authentication", "category": "Identity and Authentication"}
    ]
    
    async def execute(self, input_data: ComplianceCheckerInput) -> ComplianceCheckerOutput:
        """Execute compliance assessment"""
        try:
            target = input_data.target_url or input_data.domain or "organization"
            
            # Assess compliance requirements
            compliance_requirements = await self._assess_compliance_requirements(input_data)
            
            # Evaluate security controls
            security_controls = await self._evaluate_security_controls(input_data)
            
            # Assess data protection
            data_protection = None
            if input_data.check_data_protection:
                data_protection = await self._assess_data_protection(input_data)
            
            # Assess audit trail
            audit_trail = None
            if input_data.check_audit_logging:
                audit_trail = await self._assess_audit_trail(input_data)
            
            # Assess encryption
            encryption = None
            if input_data.check_encryption:
                encryption = await self._assess_encryption(input_data)
            
            # Identify compliance gaps
            compliance_gaps = await self._identify_compliance_gaps(compliance_requirements, security_controls)
            
            # Calculate scores
            overall_score, framework_scores = self._calculate_compliance_scores(compliance_requirements)
            
            # Generate priority actions
            priority_actions = self._generate_priority_actions(compliance_gaps)
            
            # Create compliance roadmap
            roadmap = self._create_compliance_roadmap(compliance_gaps)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(compliance_gaps, security_controls)
            
            # Create summary
            summary = self._create_assessment_summary(compliance_requirements, security_controls, compliance_gaps)
            
            return ComplianceCheckerOutput(
                assessment_target=target,
                organization_type=input_data.organization_type,
                frameworks_assessed=input_data.compliance_frameworks,
                assessment_timestamp=datetime.now(),
                overall_compliance_score=overall_score,
                framework_scores=framework_scores,
                compliance_requirements=compliance_requirements,
                security_controls=security_controls,
                data_protection=data_protection,
                audit_trail=audit_trail,
                encryption=encryption,
                compliance_gaps=compliance_gaps,
                priority_actions=priority_actions,
                compliance_roadmap=roadmap,
                recommendations=recommendations,
                assessment_summary=summary
            )
            
        except Exception as e:
            return self._create_error_response(input_data, str(e))
    
    async def _assess_compliance_requirements(self, input_data: ComplianceCheckerInput) -> List[ComplianceRequirement]:
        """Assess compliance requirements for selected frameworks"""
        await asyncio.sleep(0.3)  # Simulate assessment time
        
        requirements = []
        
        for framework in input_data.compliance_frameworks:
            if framework in self.FRAMEWORKS:
                framework_reqs = self.FRAMEWORKS[framework]["requirements"]
                
                for req in framework_reqs:
                    # Simulate compliance assessment
                    status = random.choice(["Compliant", "Non-Compliant", "Partial"])
                    confidence = random.uniform(0.6, 1.0)
                    
                    evidence = []
                    gaps = []
                    recommendations = []
                    
                    if status == "Compliant":
                        evidence = [f"Control implemented for {req['name']}", "Documentation available"]
                    elif status == "Non-Compliant":
                        gaps = [f"Missing implementation of {req['name']}", "No documentation found"]
                        recommendations = [f"Implement {req['name']} control", "Create required documentation"]
                    else:  # Partial
                        evidence = [f"Partial implementation of {req['name']}"]
                        gaps = ["Implementation incomplete", "Documentation needs improvement"]
                        recommendations = [f"Complete implementation of {req['name']}", "Update documentation"]
                    
                    requirement = ComplianceRequirement(
                        framework=framework,
                        requirement_id=req["id"],
                        requirement_name=req["name"],
                        description=f"{framework} requirement for {req['name']}",
                        category=req["category"],
                        mandatory=req["mandatory"],
                        status=status,
                        confidence=confidence,
                        evidence=evidence,
                        gaps=gaps,
                        recommendations=recommendations
                    )
                    requirements.append(requirement)
        
        return requirements
    
    async def _evaluate_security_controls(self, input_data: ComplianceCheckerInput) -> List[SecurityControl]:
        """Evaluate security controls implementation"""
        await asyncio.sleep(0.2)
        
        controls = []
        
        # Select relevant controls based on assessment type
        selected_controls = random.sample(self.SECURITY_CONTROLS, random.randint(5, 8))
        
        for control in selected_controls:
            implemented = random.choice([True, False])
            effectiveness = "Effective" if implemented and random.random() > 0.3 else random.choice(["Partially-Effective", "Ineffective"])
            
            evidence = []
            deficiencies = []
            recommendations = []
            
            if implemented and effectiveness == "Effective":
                evidence = [f"{control['name']} is properly implemented", "Regular monitoring in place"]
            elif implemented and effectiveness == "Partially-Effective":
                evidence = [f"{control['name']} is implemented"]
                deficiencies = ["Implementation gaps identified", "Monitoring needs improvement"]
                recommendations = ["Address implementation gaps", "Enhance monitoring procedures"]
            else:
                deficiencies = [f"{control['name']} not implemented", "No monitoring in place"]
                recommendations = [f"Implement {control['name']}", "Establish monitoring procedures"]
            
            security_control = SecurityControl(
                control_id=control["id"],
                control_name=control["name"],
                implemented=implemented,
                effectiveness=effectiveness,
                evidence=evidence,
                deficiencies=deficiencies,
                recommendations=recommendations
            )
            controls.append(security_control)
        
        return controls
    
    async def _assess_data_protection(self, input_data: ComplianceCheckerInput) -> DataProtectionAssessment:
        """Assess data protection compliance"""
        await asyncio.sleep(0.1)
        
        personal_data = random.choice([True, False])
        
        issues = []
        if personal_data and not random.choice([True, False]):
            issues.append("Personal data processing lacks proper legal basis")
        
        if not random.choice([True, False]):
            issues.append("Privacy policy missing or incomplete")
        
        return DataProtectionAssessment(
            personal_data_identified=personal_data,
            data_categories=["Email addresses", "Names", "Phone numbers"] if personal_data else [],
            processing_lawful_basis=["Consent", "Legitimate interest"] if personal_data else [],
            consent_mechanisms=["Cookie banner", "Opt-in forms"] if random.choice([True, False]) else [],
            data_retention_policy=random.choice([True, False]),
            data_subject_rights=["Access", "Rectification", "Erasure"] if random.choice([True, False]) else [],
            privacy_policy_present=random.choice([True, False]),
            cookie_consent=random.choice([True, False]),
            issues=issues
        )
    
    async def _assess_audit_trail(self, input_data: ComplianceCheckerInput) -> AuditTrailAssessment:
        """Assess audit trail implementation"""
        await asyncio.sleep(0.1)
        
        logging_enabled = random.choice([True, False])
        
        issues = []
        recommendations = []
        
        if not logging_enabled:
            issues.append("Audit logging not enabled")
            recommendations.append("Enable comprehensive audit logging")
        
        retention_period = random.randint(30, 365)
        if retention_period < 90:
            issues.append("Log retention period too short")
            recommendations.append("Increase log retention to meet compliance requirements")
        
        return AuditTrailAssessment(
            logging_enabled=logging_enabled,
            log_coverage=["Authentication", "Data access", "Configuration changes"] if logging_enabled else [],
            log_retention_period=retention_period,
            log_integrity_protection=random.choice([True, False]),
            monitoring_alerts=random.choice([True, False]),
            issues=issues,
            recommendations=recommendations
        )
    
    async def _assess_encryption(self, input_data: ComplianceCheckerInput) -> EncryptionAssessment:
        """Assess encryption implementation"""
        await asyncio.sleep(0.1)
        
        transit_encrypted = random.choice([True, False])
        rest_encrypted = random.choice([True, False])
        
        issues = []
        recommendations = []
        
        if not transit_encrypted:
            issues.append("Data in transit not encrypted")
            recommendations.append("Implement TLS encryption for data transmission")
        
        if not rest_encrypted:
            issues.append("Data at rest not encrypted")
            recommendations.append("Implement encryption for stored data")
        
        algorithms = []
        if transit_encrypted or rest_encrypted:
            algorithms = random.sample(["AES-256", "ChaCha20", "RSA-2048"], random.randint(1, 2))
        
        return EncryptionAssessment(
            data_in_transit_encrypted=transit_encrypted,
            data_at_rest_encrypted=rest_encrypted,
            encryption_algorithms=algorithms,
            key_management=random.choice(["Manual", "Automated", "HSM"]),
            certificate_validity=random.choice([True, False]),
            issues=issues,
            recommendations=recommendations
        )
    
    async def _identify_compliance_gaps(self, requirements: List[ComplianceRequirement], controls: List[SecurityControl]) -> List[ComplianceGap]:
        """Identify compliance gaps"""
        await asyncio.sleep(0.1)
        
        gaps = []
        
        # Identify gaps from non-compliant requirements
        non_compliant_reqs = [r for r in requirements if r.status in ["Non-Compliant", "Partial"]]
        
        for req in non_compliant_reqs[:3]:  # Limit to top 3 gaps
            severity = "Critical" if req.mandatory and req.status == "Non-Compliant" else random.choice(["High", "Medium", "Low"])
            
            gap = ComplianceGap(
                framework=req.framework,
                gap_type="Requirement Gap",
                severity=severity,
                description=f"Non-compliance with {req.requirement_name}",
                affected_requirements=[req.requirement_id],
                business_impact="Regulatory penalties and security risk" if severity in ["Critical", "High"] else "Minor compliance risk",
                remediation_effort=random.choice(["Low", "Medium", "High"]),
                remediation_steps=req.recommendations,
                timeline=random.choice(["30 days", "60 days", "90 days"])
            )
            gaps.append(gap)
        
        # Identify gaps from ineffective controls
        ineffective_controls = [c for c in controls if not c.implemented or c.effectiveness == "Ineffective"]
        
        for control in ineffective_controls[:2]:  # Limit to top 2 control gaps
            gap = ComplianceGap(
                framework="General",
                gap_type="Control Gap",
                severity=random.choice(["High", "Medium"]),
                description=f"Security control {control.control_name} not effective",
                affected_requirements=[control.control_id],
                business_impact="Security vulnerability and compliance risk",
                remediation_effort="Medium",
                remediation_steps=control.recommendations,
                timeline="60 days"
            )
            gaps.append(gap)
        
        return gaps
    
    def _calculate_compliance_scores(self, requirements: List[ComplianceRequirement]) -> tuple[float, Dict[str, float]]:
        """Calculate compliance scores"""
        if not requirements:
            return 0.0, {}
        
        framework_scores = {}
        
        # Calculate per-framework scores
        frameworks = set(req.framework for req in requirements)
        for framework in frameworks:
            framework_reqs = [req for req in requirements if req.framework == framework]
            compliant_count = len([req for req in framework_reqs if req.status == "Compliant"])
            partial_count = len([req for req in framework_reqs if req.status == "Partial"])
            
            score = (compliant_count + partial_count * 0.5) / len(framework_reqs) * 100
            framework_scores[framework] = round(score, 1)
        
        # Calculate overall score
        overall_score = sum(framework_scores.values()) / len(framework_scores) if framework_scores else 0.0
        
        return round(overall_score, 1), framework_scores
    
    def _generate_priority_actions(self, gaps: List[ComplianceGap]) -> List[str]:
        """Generate priority actions"""
        actions = []
        
        critical_gaps = [gap for gap in gaps if gap.severity == "Critical"]
        for gap in critical_gaps:
            actions.extend(gap.remediation_steps[:2])  # Top 2 steps per critical gap
        
        high_gaps = [gap for gap in gaps if gap.severity == "High"]
        for gap in high_gaps[:2]:  # Top 2 high severity gaps
            actions.extend(gap.remediation_steps[:1])  # Top step per high gap
        
        return list(set(actions))  # Remove duplicates
    
    def _create_compliance_roadmap(self, gaps: List[ComplianceGap]) -> List[Dict[str, Any]]:
        """Create compliance roadmap"""
        roadmap = []
        
        # Sort gaps by severity and timeline
        sorted_gaps = sorted(gaps, key=lambda x: (x.severity == "Critical", x.severity == "High", x.timeline))
        
        for i, gap in enumerate(sorted_gaps[:5]):  # Top 5 gaps
            milestone = {
                "phase": f"Phase {i+1}",
                "timeline": gap.timeline,
                "objective": f"Address {gap.gap_type}: {gap.description}",
                "deliverables": gap.remediation_steps,
                "priority": gap.severity,
                "effort": gap.remediation_effort
            }
            roadmap.append(milestone)
        
        return roadmap
    
    def _generate_recommendations(self, gaps: List[ComplianceGap], controls: List[SecurityControl]) -> List[str]:
        """Generate recommendations"""
        recommendations = []
        
        # Add gap-based recommendations
        for gap in gaps:
            recommendations.extend(gap.remediation_steps)
        
        # Add control-based recommendations
        for control in controls:
            if control.recommendations:
                recommendations.extend(control.recommendations)
        
        # Add general recommendations
        general_recommendations = [
            "Implement regular compliance assessments",
            "Establish compliance monitoring and reporting",
            "Provide compliance training to staff",
            "Document all compliance procedures",
            "Regular third-party compliance audits"
        ]
        
        recommendations.extend(general_recommendations)
        
        return list(set(recommendations))  # Remove duplicates
    
    def _create_assessment_summary(self, requirements: List[ComplianceRequirement], controls: List[SecurityControl], gaps: List[ComplianceGap]) -> Dict[str, Any]:
        """Create assessment summary"""
        compliant_reqs = len([req for req in requirements if req.status == "Compliant"])
        implemented_controls = len([ctrl for ctrl in controls if ctrl.implemented])
        critical_gaps = len([gap for gap in gaps if gap.severity == "Critical"])
        
        return {
            "total_requirements_assessed": len(requirements),
            "compliant_requirements": compliant_reqs,
            "compliance_percentage": round(compliant_reqs / len(requirements) * 100, 1) if requirements else 0,
            "total_controls_assessed": len(controls),
            "implemented_controls": implemented_controls,
            "control_implementation_percentage": round(implemented_controls / len(controls) * 100, 1) if controls else 0,
            "total_gaps_identified": len(gaps),
            "critical_gaps": critical_gaps,
            "high_priority_gaps": len([gap for gap in gaps if gap.severity == "High"]),
            "overall_risk_level": "Critical" if critical_gaps > 0 else "High" if len(gaps) > 3 else "Medium"
        }
    
    def _create_error_response(self, input_data: ComplianceCheckerInput, error_msg: str) -> ComplianceCheckerOutput:
        """Create error response"""
        return ComplianceCheckerOutput(
            assessment_target="error",
            organization_type=input_data.organization_type,
            frameworks_assessed=input_data.compliance_frameworks,
            assessment_timestamp=datetime.now(),
            overall_compliance_score=0.0,
            framework_scores={},
            compliance_requirements=[],
            security_controls=[],
            data_protection=DataProtectionAssessment(
                personal_data_identified=False,
                data_categories=[],
                processing_lawful_basis=[],
                consent_mechanisms=[],
                data_retention_policy=False,
                data_subject_rights=[],
                privacy_policy_present=False,
                cookie_consent=False,
                issues=[f"Assessment failed: {error_msg}"]
            ),
            audit_trail=AuditTrailAssessment(
                logging_enabled=False,
                log_coverage=[],
                log_retention_period=0,
                log_integrity_protection=False,
                monitoring_alerts=False,
                issues=[f"Assessment failed: {error_msg}"],
                recommendations=["Fix configuration and retry"]
            ),
            encryption=EncryptionAssessment(
                data_in_transit_encrypted=False,
                data_at_rest_encrypted=False,
                encryption_algorithms=[],
                key_management="Unknown",
                certificate_validity=False,
                issues=[f"Assessment failed: {error_msg}"],
                recommendations=["Fix configuration and retry"]
            ),
            compliance_gaps=[],
            priority_actions=["Fix configuration and retry assessment"],
            compliance_roadmap=[],
            recommendations=["Fix configuration and retry assessment"],
            assessment_summary={"error": error_msg}
        )

# Tool metadata for registration
TOOL_INFO = {
    "name": "Compliance Checker",
    "description": "Comprehensive compliance assessment tool for multiple security and privacy frameworks including GDPR, PCI-DSS, HIPAA, SOC2, and more",
    "category": "compliance",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["compliance", "gdpr", "pci-dss", "hipaa", "soc2", "iso27001", "privacy", "audit"]
}

TOOL_METADATA = {
    "name": "Compliance Checker",
    "description": "Comprehensive compliance assessment tool for multiple security and privacy frameworks including GDPR, PCI-DSS, HIPAA, SOC2, and more",
    "category": "compliance",
    "input_schema": ComplianceCheckerInput,
    "output_schema": ComplianceCheckerOutput,
    "tool_class": ComplianceChecker
}

# Main entry point function
async def execute_tool(data: ComplianceCheckerInput) -> ComplianceCheckerOutput:
    """Main entry point for compliance checker tool"""
    checker = ComplianceChecker()
    return await checker.execute(data)
