from typing import Dict, Any, List
import asyncio
import random
from datetime import datetime, timedelta

try:
    from schemas import (
        ComplianceCheckInput,
        SecurityComplianceOutput,
        ControlAssessment,
        ComplianceReport,
        RemediationPlan
    )
except ImportError:
    from schemas import (
        ComplianceCheckInput,
        SecurityComplianceOutput,
        ControlAssessment,
        ComplianceReport,
        RemediationPlan
    )

class SecurityComplianceChecker:
    """Security Compliance Checker - Comprehensive compliance assessment and reporting"""
    
    name = "Security Compliance Checker"
    description = "Comprehensive security compliance assessment tool supporting multiple frameworks"
    category = "compliance"
    
    def __init__(self):
        self.frameworks = {
            "ISO27001": "ISO/IEC 27001 Information Security Management",
            "SOC2": "SOC 2 Type II Security Controls",
            "PCI_DSS": "Payment Card Industry Data Security Standard",
            "GDPR": "General Data Protection Regulation",
            "HIPAA": "Health Insurance Portability and Accountability Act",
            "NIST": "NIST Cybersecurity Framework"
        }
        
        self.control_libraries = {
            "ISO27001": self._get_iso27001_controls(),
            "SOC2": self._get_soc2_controls(),
            "PCI_DSS": self._get_pci_controls(),
            "GDPR": self._get_gdpr_controls(),
            "HIPAA": self._get_hipaa_controls(),
            "NIST": self._get_nist_controls()
        }

    async def execute_compliance_check(self, check_input: ComplianceCheckInput) -> SecurityComplianceOutput:
        """Execute compliance assessment"""
        
        assessment_id = f"COMP-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        
        # Get framework controls
        controls = self.control_libraries.get(check_input.framework, [])
        
        # Filter out excluded controls
        if check_input.exclude_controls:
            controls = [c for c in controls if c["id"] not in check_input.exclude_controls]
        
        # Perform control assessments
        control_assessments = await self._assess_controls(controls, check_input)
        
        # Generate compliance report
        compliance_report = await self._generate_compliance_report(
            check_input.framework, control_assessments
        )
        
        # Generate remediation plans
        remediation_plans = await self._generate_remediation_plans(control_assessments)
        
        # Simulate assessment execution
        await asyncio.sleep(2)
        
        return SecurityComplianceOutput(
            success=True,
            assessment_id=assessment_id,
            framework=check_input.framework,
            compliance_report=compliance_report,
            remediation_plans=remediation_plans,
            executive_summary=self._generate_executive_summary(compliance_report),
            next_assessment_date=(datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
            certification_readiness=self._determine_certification_readiness(compliance_report)
        )

    async def _assess_controls(self, controls: List[Dict], check_input: ComplianceCheckInput) -> List[ControlAssessment]:
        """Assess individual controls"""
        
        assessments = []
        
        for control in controls:
            # Simulate assessment logic
            compliance_score = random.uniform(0.4, 1.0)
            implementation_status = self._determine_status(compliance_score)
            
            # Generate mock evidence and gaps
            evidence = self._generate_evidence(control["id"])
            gaps = self._generate_gaps(control["id"], compliance_score)
            recommendations = self._generate_recommendations(control["id"], gaps)
            
            assessment = ControlAssessment(
                control_id=control["id"],
                control_name=control["name"],
                description=control["description"],
                requirement=control["requirement"],
                implementation_status=implementation_status,
                compliance_score=round(compliance_score, 2),
                evidence=evidence,
                gaps=gaps,
                recommendations=recommendations,
                risk_level=self._determine_risk_level(compliance_score)
            )
            assessments.append(assessment)
        
        return assessments

    async def _generate_compliance_report(self, framework: str, assessments: List[ControlAssessment]) -> ComplianceReport:
        """Generate comprehensive compliance report"""
        
        total_controls = len(assessments)
        compliant_controls = len([a for a in assessments if a.compliance_score >= 0.8])
        non_compliant_controls = total_controls - compliant_controls
        
        overall_score = sum(a.compliance_score for a in assessments) / total_controls if assessments else 0
        
        critical_gaps = []
        high_priority_recommendations = []
        
        for assessment in assessments:
            if assessment.compliance_score < 0.6:
                critical_gaps.extend(assessment.gaps[:2])
            if assessment.risk_level in ["High", "Critical"]:
                high_priority_recommendations.extend(assessment.recommendations[:1])
        
        return ComplianceReport(
            framework=framework,
            assessment_date=datetime.now(),
            overall_score=round(overall_score, 2),
            total_controls=total_controls,
            compliant_controls=compliant_controls,
            non_compliant_controls=non_compliant_controls,
            control_assessments=assessments,
            critical_gaps=list(set(critical_gaps))[:10],
            high_priority_recommendations=list(set(high_priority_recommendations))[:10]
        )

    async def _generate_remediation_plans(self, assessments: List[ControlAssessment]) -> List[RemediationPlan]:
        """Generate remediation plans for non-compliant controls"""
        
        plans = []
        
        # Focus on controls with low compliance scores
        priority_assessments = [a for a in assessments if a.compliance_score < 0.8]
        priority_assessments.sort(key=lambda x: x.compliance_score)
        
        for i, assessment in enumerate(priority_assessments[:10]):
            priority = "High" if assessment.compliance_score < 0.6 else "Medium"
            
            plan = RemediationPlan(
                priority=priority,
                control_id=assessment.control_id,
                action_required=f"Implement {assessment.control_name} requirements",
                estimated_effort=random.choice(["1-2 weeks", "2-4 weeks", "1-2 months", "2-3 months"]),
                target_completion=(datetime.now() + timedelta(days=random.randint(30, 120))).strftime("%Y-%m-%d"),
                responsible_party=random.choice(["Security Team", "IT Operations", "Compliance Team", "Risk Management"]),
                dependencies=[]
            )
            plans.append(plan)
        
        return plans

    def _determine_status(self, score: float) -> str:
        """Determine implementation status based on score"""
        if score >= 0.9:
            return "Fully Implemented"
        elif score >= 0.7:
            return "Partially Implemented"
        elif score >= 0.5:
            return "Minimally Implemented"
        else:
            return "Not Implemented"

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on compliance score"""
        if score >= 0.9:
            return "Low"
        elif score >= 0.7:
            return "Medium"
        elif score >= 0.5:
            return "High"
        else:
            return "Critical"

    def _generate_evidence(self, control_id: str) -> List[str]:
        """Generate mock evidence for control"""
        evidence_types = [
            "Policy documentation",
            "Configuration screenshots",
            "Audit logs",
            "Training records",
            "System documentation",
            "Security assessments",
            "Vendor certifications"
        ]
        return random.sample(evidence_types, random.randint(2, 4))

    def _generate_gaps(self, control_id: str, score: float) -> List[str]:
        """Generate gaps based on control and score"""
        if score >= 0.8:
            return []
        
        gap_examples = [
            "Missing documentation",
            "Insufficient monitoring",
            "Incomplete implementation",
            "Lack of regular testing",
            "Insufficient training",
            "Missing technical controls",
            "Inadequate review processes"
        ]
        
        num_gaps = 1 if score >= 0.6 else random.randint(2, 4)
        return random.sample(gap_examples, num_gaps)

    def _generate_recommendations(self, control_id: str, gaps: List[str]) -> List[str]:
        """Generate recommendations based on gaps"""
        if not gaps:
            return ["Maintain current implementation"]
        
        recommendation_map = {
            "Missing documentation": "Develop and maintain comprehensive documentation",
            "Insufficient monitoring": "Implement continuous monitoring capabilities",
            "Incomplete implementation": "Complete control implementation",
            "Lack of regular testing": "Establish regular testing procedures",
            "Insufficient training": "Enhance security awareness training",
            "Missing technical controls": "Deploy required technical controls",
            "Inadequate review processes": "Establish regular review processes"
        }
        
        return [recommendation_map.get(gap, f"Address {gap}") for gap in gaps]

    def _generate_executive_summary(self, report: ComplianceReport) -> str:
        """Generate executive summary"""
        compliance_percentage = (report.compliant_controls / report.total_controls) * 100
        
        summary = f"Compliance assessment for {report.framework} completed with an overall score of {report.overall_score}/1.0 "
        summary += f"({compliance_percentage:.1f}% of controls fully compliant). "
        
        if report.overall_score >= 0.8:
            summary += "Organization demonstrates strong compliance posture with minor improvements needed."
        elif report.overall_score >= 0.6:
            summary += "Organization has good foundation but requires focused improvements for full compliance."
        else:
            summary += "Significant compliance gaps identified requiring immediate attention and remediation."
        
        return summary

    def _determine_certification_readiness(self, report: ComplianceReport) -> str:
        """Determine certification readiness"""
        if report.overall_score >= 0.9:
            return "Ready for Certification"
        elif report.overall_score >= 0.8:
            return "Near Ready - Minor Improvements Needed"
        elif report.overall_score >= 0.7:
            return "Moderate Preparation Required"
        else:
            return "Significant Preparation Required"

    def _get_iso27001_controls(self) -> List[Dict]:
        """Get ISO 27001 control set"""
        return [
            {"id": "A.5.1.1", "name": "Information Security Policies", "description": "Information security policy", "requirement": "Management direction and support for information security"},
            {"id": "A.6.1.1", "name": "Information Security Roles", "description": "Information security responsibilities", "requirement": "Allocation of information security responsibilities"},
            {"id": "A.7.2.2", "name": "Information Security Awareness", "description": "Information security awareness training", "requirement": "All employees receive appropriate awareness education"},
            {"id": "A.8.1.1", "name": "Inventory of Assets", "description": "Responsibility for assets", "requirement": "Assets associated with information and facilities are identified"},
            {"id": "A.9.1.1", "name": "Access Control Policy", "description": "Business requirement of access control", "requirement": "Access control policy established and reviewed"},
        ]

    def _get_soc2_controls(self) -> List[Dict]:
        """Get SOC 2 control set"""
        return [
            {"id": "CC1.1", "name": "Control Environment", "description": "Integrity and ethical values", "requirement": "Entity demonstrates commitment to integrity and ethical values"},
            {"id": "CC2.1", "name": "Communication", "description": "Internal communication", "requirement": "Entity communicates information internally"},
            {"id": "CC3.1", "name": "Risk Assessment", "description": "Risk identification", "requirement": "Entity specifies objectives relevant to reporting"},
            {"id": "CC4.1", "name": "Monitoring Activities", "description": "Control monitoring", "requirement": "Entity selects, develops, and performs ongoing monitoring"},
            {"id": "CC5.1", "name": "Control Activities", "description": "Control selection", "requirement": "Entity selects and develops control activities"},
        ]

    def _get_pci_controls(self) -> List[Dict]:
        """Get PCI DSS control set"""
        return [
            {"id": "1.1", "name": "Firewall Configuration", "description": "Firewall configuration standards", "requirement": "Establish firewall configuration standards"},
            {"id": "2.1", "name": "Default Passwords", "description": "Change default passwords", "requirement": "Change vendor-supplied defaults"},
            {"id": "3.1", "name": "Data Protection", "description": "Protect stored cardholder data", "requirement": "Keep cardholder data storage to minimum"},
            {"id": "4.1", "name": "Transmission Encryption", "description": "Encrypt transmission", "requirement": "Encrypt transmission of cardholder data"},
            {"id": "6.1", "name": "Secure Development", "description": "Secure development processes", "requirement": "Establish secure coding practices"},
        ]

    def _get_gdpr_controls(self) -> List[Dict]:
        """Get GDPR control set"""
        return [
            {"id": "Art.5", "name": "Data Processing Principles", "description": "Principles relating to processing", "requirement": "Process personal data lawfully, fairly and transparently"},
            {"id": "Art.6", "name": "Lawfulness of Processing", "description": "Lawfulness of processing", "requirement": "Processing shall be lawful only if conditions are met"},
            {"id": "Art.25", "name": "Data Protection by Design", "description": "Data protection by design and by default", "requirement": "Implement appropriate technical and organisational measures"},
            {"id": "Art.32", "name": "Security of Processing", "description": "Security of processing", "requirement": "Implement appropriate technical and organisational measures"},
            {"id": "Art.33", "name": "Breach Notification", "description": "Notification of personal data breach", "requirement": "Notify supervisory authority within 72 hours"},
        ]

    def _get_hipaa_controls(self) -> List[Dict]:
        """Get HIPAA control set"""
        return [
            {"id": "164.308", "name": "Administrative Safeguards", "description": "Security officer", "requirement": "Assign security responsibility to specific individual"},
            {"id": "164.310", "name": "Physical Safeguards", "description": "Facility access controls", "requirement": "Implement procedures to limit physical access"},
            {"id": "164.312", "name": "Technical Safeguards", "description": "Access control", "requirement": "Implement technical safeguards to control access"},
            {"id": "164.314", "name": "Business Associate", "description": "Business associate contracts", "requirement": "Written contract with business associates"},
            {"id": "164.316", "name": "Policies and Procedures", "description": "Security policies", "requirement": "Implement policies and procedures"},
        ]

    def _get_nist_controls(self) -> List[Dict]:
        """Get NIST CSF control set"""
        return [
            {"id": "ID.AM", "name": "Asset Management", "description": "Asset management", "requirement": "Physical devices and systems are inventoried"},
            {"id": "PR.AC", "name": "Access Control", "description": "Identity management and access control", "requirement": "Access to assets is limited"},
            {"id": "DE.AE", "name": "Anomalies and Events", "description": "Anomalies and events are detected", "requirement": "Anomalous activity is detected"},
            {"id": "RS.RP", "name": "Response Planning", "description": "Response planning", "requirement": "Response processes and procedures are executed"},
            {"id": "RC.RP", "name": "Recovery Planning", "description": "Recovery planning", "requirement": "Recovery processes and procedures are executed"},
        ]

# Required async function for tool execution
async def execute_tool(tool_input: ComplianceCheckInput) -> SecurityComplianceOutput:
    """Execute the Security Compliance Checker tool"""
    checker = SecurityComplianceChecker()
    return await checker.execute_compliance_check(tool_input)

# Tool metadata for registration
TOOL_INFO = {
    "name": "Security Compliance Checker",
    "description": "Comprehensive security compliance assessment tool supporting multiple frameworks",
    "category": "compliance",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": ComplianceCheckInput,
    "output_schema": SecurityComplianceOutput,
    "tool_class": SecurityComplianceChecker
}
