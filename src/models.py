"""
Data models for the honeypot system.

This module defines the core data structures used throughout the honeypot
application, following the Single Responsibility Principle.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class HoneypotType(Enum):
    """Enumeration of supported honeypot types."""
    ADMIN_PANEL = "admin_panel"
    API_ENDPOINT = "api_endpoint"
    FILE_UPLOAD = "file_upload"
    BOT_TRAP = "bot_trap"
    SSH_SIMULATION = "ssh_simulation"
    VULNERABLE_WEBAPP = "vulnerable_webapp"


class ThreatLevel(Enum):
    """Enumeration of threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RequestInfo:
    """
    Structured representation of an incoming HTTP request.
    
    This class encapsulates all relevant information about an HTTP request
    that needs to be analyzed for security threats.
    """
    timestamp: str
    session_id: str
    client_ip: str
    method: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, Any]
    body: str
    user_agent: str
    referer: str
    request_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the request info to a dictionary for logging."""
        return {
            'timestamp': self.timestamp,
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'method': self.method,
            'path': self.path,
            'headers': self.headers,
            'query_params': self.query_params,
            'body': self.body,
            'user_agent': self.user_agent,
            'referer': self.referer,
            'request_id': self.request_id
        }


@dataclass
class ThreatIndicator:
    """
    Represents a detected security threat indicator.
    
    This class encapsulates information about detected threats,
    including the type, severity, and detection details.
    """
    pattern: str
    category: str
    severity: ThreatLevel
    description: str
    matched_text: Optional[str] = None
    location: Optional[str] = None  # where in the request it was found
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat indicator to dictionary format."""
        return {
            'pattern': self.pattern,
            'category': self.category,
            'severity': self.severity.value,
            'description': self.description,
            'matched_text': self.matched_text,
            'location': self.location
        }


@dataclass
class HoneypotInteraction:
    """
    Complete record of a honeypot interaction.
    
    This class combines request information with threat analysis results
    and honeypot classification.
    """
    request_info: RequestInfo
    honeypot_type: HoneypotType
    threat_indicators: List[ThreatIndicator] = field(default_factory=list)
    processing_time_ms: Optional[float] = None
    
    def to_log_entry(self) -> Dict[str, Any]:
        """Convert interaction to structured log entry."""
        return {
            **self.request_info.to_dict(),
            'honeypot_type': self.honeypot_type.value,
            'threat_indicators': [indicator.to_dict() for indicator in self.threat_indicators],
            'threat_count': len(self.threat_indicators),
            'max_threat_level': self._get_max_threat_level().value if self.threat_indicators else 'none',
            'processing_time_ms': self.processing_time_ms
        }
    
    def _get_max_threat_level(self) -> ThreatLevel:
        """Determine the highest threat level detected."""
        if not self.threat_indicators:
            return ThreatLevel.LOW
        
        severity_order = {
            ThreatLevel.LOW: 0,
            ThreatLevel.MEDIUM: 1,
            ThreatLevel.HIGH: 2,
            ThreatLevel.CRITICAL: 3
        }
        
        max_severity = max(
            self.threat_indicators,
            key=lambda x: severity_order[x.severity]
        ).severity
        
        return max_severity


@dataclass
class HoneypotResponse:
    """
    Structured representation of a honeypot response.
    
    This class encapsulates the HTTP response that will be sent back
    to the client, including status, headers, and body.
    """
    status_code: int
    headers: Dict[str, str]
    body: str
    content_type: str = "text/html"
    
    def to_lambda_response(self) -> Dict[str, Any]:
        """Convert to AWS Lambda response format."""
        response_headers = {
            'Content-Type': self.content_type,
            **self.headers
        }
        
        return {
            'statusCode': self.status_code,
            'headers': response_headers,
            'body': self.body
        }


@dataclass
class MetricData:
    """
    Structured representation of CloudWatch metrics data.
    
    This class encapsulates metrics that will be sent to CloudWatch
    for monitoring and alerting.
    """
    metric_name: str
    value: float
    unit: str
    dimensions: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[datetime] = None
    
    def to_cloudwatch_format(self) -> Dict[str, Any]:
        """Convert to CloudWatch PutMetricData format."""
        metric_data = {
            'MetricName': self.metric_name,
            'Value': self.value,
            'Unit': self.unit
        }
        
        if self.dimensions:
            metric_data['Dimensions'] = [
                {'Name': name, 'Value': value}
                for name, value in self.dimensions.items()
            ]
        
        if self.timestamp:
            metric_data['Timestamp'] = self.timestamp
            
        return metric_data