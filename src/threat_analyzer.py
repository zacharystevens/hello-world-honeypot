"""
Threat analysis engine for the honeypot system.

This module contains the logic for detecting and analyzing security threats
in incoming requests, following the Single Responsibility Principle.
"""

import re
from typing import List, Dict, Pattern
from urllib.parse import unquote

from .models import RequestInfo, ThreatIndicator, ThreatLevel
from .config import THREAT_PATTERNS, SECURITY_TOOLS


class ThreatAnalyzer:
    """
    Analyzes requests for security threats and malicious patterns.
    
    This class encapsulates all threat detection logic, making it easy
    to extend with new detection patterns and maintain existing ones.
    """
    
    def __init__(self):
        """Initialize the threat analyzer with compiled patterns."""
        self._compiled_patterns = self._compile_patterns()
    
    def analyze_request(self, request_info: RequestInfo) -> List[ThreatIndicator]:
        """
        Analyze a request for security threats and suspicious patterns.
        
        Args:
            request_info: Structured request information to analyze
            
        Returns:
            List[ThreatIndicator]: List of detected threat indicators
        """
        indicators = []
        
        # Analyze different parts of the request
        indicators.extend(self._analyze_path(request_info.path))
        indicators.extend(self._analyze_query_params(request_info.query_params))
        indicators.extend(self._analyze_body(request_info.body))
        indicators.extend(self._analyze_headers(request_info.headers))
        indicators.extend(self._analyze_user_agent(request_info.user_agent))
        
        return indicators
    
    def _compile_patterns(self) -> Dict[str, List[Pattern[str]]]:
        """
        Compile regex patterns for better performance.
        
        Pre-compiling patterns avoids repeated compilation during analysis.
        """
        compiled = {}
        
        for category, patterns in THREAT_PATTERNS.items():
            compiled[category] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            ]
        
        return compiled
    
    def _analyze_path(self, path: str) -> List[ThreatIndicator]:
        """Analyze the request path for malicious patterns."""
        indicators = []
        
        # URL decode the path to catch encoded attacks
        decoded_path = unquote(path)
        
        # Check against all pattern categories
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(decoded_path):
                    indicators.append(ThreatIndicator(
                        pattern=pattern.pattern,
                        category=category,
                        severity=self._get_severity_for_category(category),
                        description=f"Suspicious {category} pattern detected in path",
                        matched_text=decoded_path,
                        location="path"
                    ))
        
        return indicators
    
    def _analyze_query_params(self, query_params: Dict[str, str]) -> List[ThreatIndicator]:
        """Analyze query parameters for malicious patterns."""
        indicators = []
        
        # Combine all query parameters into a single string for analysis
        query_string = " ".join([
            f"{key}={value}" for key, value in query_params.items()
        ])
        
        if not query_string:
            return indicators
        
        # URL decode query parameters
        decoded_query = unquote(query_string)
        
        # Check against all pattern categories
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(decoded_query):
                    indicators.append(ThreatIndicator(
                        pattern=pattern.pattern,
                        category=category,
                        severity=self._get_severity_for_category(category),
                        description=f"Suspicious {category} pattern detected in query parameters",
                        matched_text=decoded_query,
                        location="query_params"
                    ))
        
        return indicators
    
    def _analyze_body(self, body: str) -> List[ThreatIndicator]:
        """Analyze the request body for malicious patterns."""
        indicators = []
        
        if not body:
            return indicators
        
        # URL decode the body content
        try:
            decoded_body = unquote(body)
        except Exception:
            decoded_body = body
        
        # Check against all pattern categories
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(decoded_body)
                if match:
                    indicators.append(ThreatIndicator(
                        pattern=pattern.pattern,
                        category=category,
                        severity=self._get_severity_for_category(category),
                        description=f"Suspicious {category} pattern detected in request body",
                        matched_text=match.group(0),
                        location="body"
                    ))
        
        return indicators
    
    def _analyze_headers(self, headers: Dict[str, str]) -> List[ThreatIndicator]:
        """Analyze HTTP headers for suspicious patterns."""
        indicators = []
        
        # Combine all headers into a single string for analysis
        headers_string = " ".join([
            f"{key}: {value}" for key, value in headers.items()
        ])
        
        # Check for suspicious header patterns
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(headers_string)
                if match:
                    indicators.append(ThreatIndicator(
                        pattern=pattern.pattern,
                        category=category,
                        severity=self._get_severity_for_category(category),
                        description=f"Suspicious {category} pattern detected in headers",
                        matched_text=match.group(0),
                        location="headers"
                    ))
        
        return indicators
    
    def _analyze_user_agent(self, user_agent: str) -> List[ThreatIndicator]:
        """Analyze the User-Agent header for security tools and suspicious patterns."""
        indicators = []
        
        if not user_agent:
            return indicators
        
        user_agent_lower = user_agent.lower()
        
        # Check for known security tools
        for tool in SECURITY_TOOLS:
            if tool in user_agent_lower:
                indicators.append(ThreatIndicator(
                    pattern=tool,
                    category="security_tool",
                    severity=ThreatLevel.MEDIUM,
                    description=f"Security tool detected: {tool}",
                    matched_text=user_agent,
                    location="user_agent"
                ))
        
        # Check for automated tool indicators
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'scanner']
        for indicator in bot_indicators:
            if indicator in user_agent_lower:
                indicators.append(ThreatIndicator(
                    pattern=indicator,
                    category="automated_tool",
                    severity=ThreatLevel.LOW,
                    description=f"Automated tool detected: {indicator}",
                    matched_text=user_agent,
                    location="user_agent"
                ))
        
        return indicators
    
    def _get_severity_for_category(self, category: str) -> ThreatLevel:
        """
        Determine the threat severity level based on the category.
        
        This method maps threat categories to severity levels,
        allowing for easy adjustment of threat prioritization.
        """
        severity_mapping = {
            'sql_injection': ThreatLevel.HIGH,
            'xss': ThreatLevel.HIGH,
            'command_injection': ThreatLevel.CRITICAL,
            'directory_traversal': ThreatLevel.HIGH,
            'file_inclusion': ThreatLevel.HIGH,
            'obfuscation': ThreatLevel.MEDIUM,
            'security_tool': ThreatLevel.MEDIUM,
            'automated_tool': ThreatLevel.LOW
        }
        
        return severity_mapping.get(category, ThreatLevel.LOW)


class ThreatIntelligence:
    """
    Provides threat intelligence and contextual information about detected threats.
    
    This class can be extended to include external threat feeds,
    IP reputation data, and other intelligence sources.
    """
    
    def __init__(self):
        """Initialize the threat intelligence system."""
        self._known_malicious_ips = set()  # Could be loaded from external sources
        self._known_attack_patterns = {}   # Could be updated from threat feeds
    
    def enrich_threats(self, indicators: List[ThreatIndicator], 
                      request_info: RequestInfo) -> List[ThreatIndicator]:
        """
        Enrich threat indicators with additional intelligence.
        
        Args:
            indicators: List of detected threat indicators
            request_info: Original request information
            
        Returns:
            List[ThreatIndicator]: Enriched threat indicators
        """
        enriched = indicators.copy()
        
        # Add IP-based threat intelligence
        if self._is_known_malicious_ip(request_info.client_ip):
            enriched.append(ThreatIndicator(
                pattern="known_malicious_ip",
                category="ip_reputation",
                severity=ThreatLevel.HIGH,
                description="Request from known malicious IP address",
                matched_text=request_info.client_ip,
                location="source_ip"
            ))
        
        # Add additional contextual information
        # This could include:
        # - Geolocation data
        # - ASN information
        # - Historical attack patterns
        # - Threat feed correlations
        
        return enriched
    
    def _is_known_malicious_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address is known to be malicious.
        
        In a production system, this would query external threat
        intelligence feeds or local blacklists.
        """
        # Placeholder implementation - in reality, this would
        # check against threat intelligence feeds
        return ip_address in self._known_malicious_ips
    
    def update_threat_intelligence(self, new_threats: Dict[str, any]) -> None:
        """
        Update threat intelligence with new data.
        
        This method would be called periodically to update
        threat intelligence from external sources.
        """
        # Implementation would update internal threat data
        # from external feeds, databases, etc.
        pass