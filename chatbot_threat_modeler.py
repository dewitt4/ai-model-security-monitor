from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
import json
from datetime import datetime
import logging

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory(Enum):
    DATA_EXPOSURE = "data_exposure"
    API_SECURITY = "api_security"
    INPUT_VALIDATION = "input_validation"
    RATE_LIMITING = "rate_limiting"
    AUTHENTICATION = "authentication"
    PROMPT_INJECTION = "prompt_injection"
    COST_EXPLOITATION = "cost_exploitation"
    DATA_PRIVACY = "data_privacy"
    USER_SAFETY = "user_safety"
    MODEL_SECURITY = "model_security"

@dataclass
class SecurityControl:
    name: str
    description: str
    implemented: bool = False
    implementation_notes: Optional[str] = None
    
@dataclass
class Threat:
    category: ThreatCategory
    severity: ThreatSeverity
    description: str
    impact: str
    likelihood: str
    recommended_controls: List[str]
    notes: Optional[str] = None

@dataclass
class ThreatAssessment:
    threats: List[Threat]
    missing_controls: List[SecurityControl]
    risk_score: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class ChatbotThreatModeler:
    def __init__(self):
        """Initialize the threat modeler with security controls and known threats"""
        self.security_controls = self._initialize_security_controls()
        self.known_threats = self._initialize_known_threats()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def _initialize_security_controls(self) -> Dict[str, SecurityControl]:
        """Define standard security controls for chatbot implementations"""
        return {
            "api_authentication": SecurityControl(
                name="API Authentication",
                description="Secure authentication mechanism for API calls"
            ),
            "api_key_rotation": SecurityControl(
                name="API Key Rotation",
                description="Regular rotation of API keys and secrets"
            ),
            "rate_limiting": SecurityControl(
                name="Rate Limiting",
                description="Implement rate limiting per user/session"
            ),
            "input_sanitization": SecurityControl(
                name="Input Sanitization",
                description="Sanitize and validate all user inputs"
            ),
            "output_filtering": SecurityControl(
                name="Output Filtering",
                description="Filter and sanitize AI model outputs"
            ),
            "prompt_validation": SecurityControl(
                name="Prompt Validation",
                description="Validate and sanitize prompts before sending to API"
            ),
            "cost_monitoring": SecurityControl(
                name="Cost Monitoring",
                description="Monitor and limit API usage costs"
            ),
            "data_encryption": SecurityControl(
                name="Data Encryption",
                description="Encrypt sensitive data in transit and at rest"
            ),
            "audit_logging": SecurityControl(
                name="Audit Logging",
                description="Comprehensive logging of all interactions"
            ),
            "user_authentication": SecurityControl(
                name="User Authentication",
                description="Authenticate and authorize chatbot users"
            ),
            "session_management": SecurityControl(
                name="Session Management",
                description="Secure session handling and timeout"
            ),
            "content_filtering": SecurityControl(
                name="Content Filtering",
                description="Filter inappropriate or malicious content"
            ),
            "error_handling": SecurityControl(
                name="Error Handling",
                description="Secure error handling and logging"
            ),
            "backup_fallback": SecurityControl(
                name="Backup/Fallback",
                description="Fallback mechanisms for API failures"
            )
        }
    
    def _initialize_known_threats(self) -> List[Threat]:
        """Define known threats for chatbot implementations"""
        return [
            Threat(
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.CRITICAL,
                description="Malicious prompt injection attempts to bypass constraints",
                impact="Could lead to unauthorized responses or system manipulation",
                likelihood="High - Common attack vector",
                recommended_controls=["prompt_validation", "input_sanitization", "content_filtering"]
            ),
            Threat(
                category=ThreatCategory.API_SECURITY,
                severity=ThreatSeverity.CRITICAL,
                description="Exposed or compromised API credentials",
                impact="Unauthorized API access and potential abuse",
                likelihood="Medium - Requires security breach",
                recommended_controls=["api_authentication", "api_key_rotation", "audit_logging"]
            ),
            Threat(
                category=ThreatCategory.COST_EXPLOITATION,
                severity=ThreatSeverity.HIGH,
                description="Denial of service through excessive API calls",
                impact="High costs and service disruption",
                likelihood="Medium - Requires bypass of basic controls",
                recommended_controls=["rate_limiting", "cost_monitoring", "user_authentication"]
            ),
            # Add more threats as needed...
        ]

    def assess_implementation(self, implemented_controls: Set[str]) -> ThreatAssessment:
        """
        Assess security based on implemented controls
        
        Args:
            implemented_controls: Set of control IDs that are implemented
        """
        # Mark implemented controls
        for control_id in implemented_controls:
            if control_id in self.security_controls:
                self.security_controls[control_id].implemented = True
        
        # Identify missing controls and applicable threats
        missing_controls = []
        applicable_threats = []
        
        for threat in self.known_threats:
            missing_recommendations = [
                control for control in threat.recommended_controls
                if control not in implemented_controls
            ]
            
            if missing_recommendations:
                applicable_threats.append(threat)
                for control_id in missing_recommendations:
                    if control_id in self.security_controls:
                        missing_controls.append(self.security_controls[control_id])
        
        # Calculate risk score (0-100, higher is riskier)
        total_controls = len(self.security_controls)
        implemented_count = len(implemented_controls)
        risk_score = (1 - (implemented_count / total_controls)) * 100
        
        # Additional risk factors
        critical_threats = sum(1 for threat in applicable_threats 
                             if threat.severity == ThreatSeverity.CRITICAL)
        risk_score += critical_threats * 10  # Extra penalty for critical threats
        
        return ThreatAssessment(
            threats=applicable_threats,
            missing_controls=missing_controls,
            risk_score=min(100, risk_score)  # Cap at 100
        )

    def generate_report(self, assessment: ThreatAssessment) -> Dict:
        """Generate a detailed security assessment report"""
        report = {
            "timestamp": assessment.timestamp,
            "risk_score": assessment.risk_score,
            "risk_level": self._get_risk_level(assessment.risk_score),
            "threats": [
                {
                    "category": threat.category.value,
                    "severity": threat.severity.value,
                    "description": threat.description,
                    "impact": threat.impact,
                    "likelihood": threat.likelihood,
                    "recommended_controls": threat.recommended_controls
                }
                for threat in assessment.threats
            ],
            "missing_controls": [
                {
                    "name": control.name,
                    "description": control.description
                }
                for control in assessment.missing_controls
            ],
            "recommendations": self._generate_recommendations(assessment)
        }
        
        return report

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to categorical risk level"""
        if risk_score >= 75:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        return "Low"

    def _generate_recommendations(self, assessment: ThreatAssessment) -> List[str]:
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # Prioritize critical threats
        critical_controls = set()
        for threat in assessment.threats:
            if threat.severity == ThreatSeverity.CRITICAL:
                critical_controls.update(threat.recommended_controls)
        
        if critical_controls:
            recommendations.append("Critical Priority Controls:")
            for control_id in critical_controls:
                if control_id in self.security_controls:
                    control = self.security_controls[control_id]
                    recommendations.append(f"- Implement {control.name}: {control.description}")
        
        # Add general recommendations
        if assessment.risk_score > 50:
            recommendations.append("\nGeneral Security Improvements:")
            for control in assessment.missing_controls:
                if control.name not in critical_controls:
                    recommendations.append(f"- Consider implementing {control.name}: {control.description}")
        
        return recommendations

    def export_report(self, report: Dict, filename: str) -> None:
        """Export the security report to a file"""
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            logging.info(f"Security report exported to {filename}")
        except Exception as e:
            logging.error(f"Failed to export report: {str(e)}")