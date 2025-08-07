"""
Honeypot classification engine.

This module determines which type of honeypot to simulate based on
request characteristics, following the Open-Closed Principle for easy extension.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from .models import RequestInfo, HoneypotType


class HoneypotClassificationRule(ABC):
    """
    Abstract base class for honeypot classification rules.
    
    This design allows for easy extension with new classification rules
    without modifying existing code (Open-Closed Principle).
    """
    
    @abstractmethod
    def matches(self, request_info: RequestInfo) -> bool:
        """
        Check if this rule matches the given request.
        
        Args:
            request_info: Structured request information
            
        Returns:
            bool: True if this rule matches the request
        """
        pass
    
    @abstractmethod
    def get_honeypot_type(self) -> HoneypotType:
        """
        Get the honeypot type this rule classifies to.
        
        Returns:
            HoneypotType: The type of honeypot to simulate
        """
        pass
    
    @abstractmethod
    def get_priority(self) -> int:
        """
        Get the priority of this rule (higher numbers = higher priority).
        
        Returns:
            int: Rule priority (0-100, where 100 is highest priority)
        """
        pass


class AdminPanelRule(HoneypotClassificationRule):
    """Rule for detecting admin panel access attempts."""
    
    def __init__(self):
        """Initialize with common admin panel paths."""
        self.admin_paths = [
            '/admin', '/wp-admin', '/administrator', '/phpmyadmin',
            '/cpanel', '/webmin', '/panel', '/dashboard', '/control',
            '/manage', '/backend', '/cms', '/admin.php', '/wp-login.php'
        ]
    
    def matches(self, request_info: RequestInfo) -> bool:
        """Check if request is accessing admin panel paths."""
        path = request_info.path.lower()
        return any(admin_path in path for admin_path in self.admin_paths)
    
    def get_honeypot_type(self) -> HoneypotType:
        """Return admin panel honeypot type."""
        return HoneypotType.ADMIN_PANEL
    
    def get_priority(self) -> int:
        """High priority for admin panel detection."""
        return 90


class ApiEndpointRule(HoneypotClassificationRule):
    """Rule for detecting API endpoint access attempts."""
    
    def matches(self, request_info: RequestInfo) -> bool:
        """Check if request is accessing API endpoints."""
        path = request_info.path.lower()
        api_indicators = [
            '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
            'api.', '.json', '/users', '/config', '/status'
        ]
        return any(indicator in path for indicator in api_indicators)
    
    def get_honeypot_type(self) -> HoneypotType:
        """Return API endpoint honeypot type."""
        return HoneypotType.API_ENDPOINT
    
    def get_priority(self) -> int:
        """Medium-high priority for API detection."""
        return 80


class FileUploadRule(HoneypotClassificationRule):
    """Rule for detecting file upload attempts."""
    
    def matches(self, request_info: RequestInfo) -> bool:
        """Check if request is a file upload attempt."""
        path = request_info.path.lower()
        method = request_info.method.upper()
        content_type = request_info.headers.get('content-type', '').lower()
        
        # Check for upload-related paths
        upload_paths = ['upload', 'file', 'attachment', 'media', 'documents']
        path_match = any(upload_path in path for upload_path in upload_paths)
        
        # Check for POST with multipart content type
        is_multipart_post = (
            method == 'POST' and 
            'multipart/form-data' in content_type
        )
        
        return path_match or is_multipart_post
    
    def get_honeypot_type(self) -> HoneypotType:
        """Return file upload honeypot type."""
        return HoneypotType.FILE_UPLOAD
    
    def get_priority(self) -> int:
        """High priority for file upload detection."""
        return 85


class BotTrapRule(HoneypotClassificationRule):
    """Rule for detecting automated bots and scanners."""
    
    def __init__(self):
        """Initialize with bot detection patterns."""
        self.bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'scanner',
            'curl', 'wget', 'python-requests', 'go-http-client'
        ]
    
    def matches(self, request_info: RequestInfo) -> bool:
        """Check if request appears to be from an automated bot."""
        user_agent = request_info.user_agent.lower()
        return any(indicator in user_agent for indicator in self.bot_indicators)
    
    def get_honeypot_type(self) -> HoneypotType:
        """Return bot trap honeypot type."""
        return HoneypotType.BOT_TRAP
    
    def get_priority(self) -> int:
        """Medium priority for bot detection."""
        return 70


class SshSimulationRule(HoneypotClassificationRule):
    """Rule for detecting SSH-related access attempts."""
    
    def matches(self, request_info: RequestInfo) -> bool:
        """Check if request is SSH-related."""
        path = request_info.path.lower()
        ssh_indicators = ['ssh', 'terminal', 'console', 'shell', 'putty']
        return any(indicator in path for indicator in ssh_indicators)
    
    def get_honeypot_type(self) -> HoneypotType:
        """Return SSH simulation honeypot type."""
        return HoneypotType.SSH_SIMULATION
    
    def get_priority(self) -> int:
        """Medium priority for SSH detection."""
        return 75


class VulnerableWebappRule(HoneypotClassificationRule):
    """Default rule for general vulnerable web application simulation."""
    
    def matches(self, request_info: RequestInfo) -> bool:
        """This rule always matches as a fallback."""
        return True
    
    def get_honeypot_type(self) -> HoneypotType:
        """Return vulnerable webapp honeypot type."""
        return HoneypotType.VULNERABLE_WEBAPP
    
    def get_priority(self) -> int:
        """Lowest priority - this is the default fallback."""
        return 10


class HoneypotClassifier:
    """
    Classifies requests to determine appropriate honeypot type.
    
    This class uses a rule-based system that follows the Open-Closed Principle,
    making it easy to add new classification rules without modifying existing code.
    """
    
    def __init__(self, custom_rules: Optional[List[HoneypotClassificationRule]] = None):
        """
        Initialize the classifier with classification rules.
        
        Args:
            custom_rules: Optional list of custom classification rules
        """
        # Default rules - these can be extended without modification
        self.rules: List[HoneypotClassificationRule] = [
            AdminPanelRule(),
            ApiEndpointRule(),
            FileUploadRule(),
            BotTrapRule(),
            SshSimulationRule(),
            VulnerableWebappRule()  # This should always be last (lowest priority)
        ]
        
        # Add any custom rules
        if custom_rules:
            self.rules.extend(custom_rules)
        
        # Sort rules by priority (highest first)
        self.rules.sort(key=lambda rule: rule.get_priority(), reverse=True)
    
    def classify_request(self, request_info: RequestInfo) -> HoneypotType:
        """
        Classify a request to determine the appropriate honeypot type.
        
        Args:
            request_info: Structured request information
            
        Returns:
            HoneypotType: The type of honeypot to simulate
        """
        # Apply rules in priority order
        for rule in self.rules:
            if rule.matches(request_info):
                return rule.get_honeypot_type()
        
        # This should never happen due to the fallback rule,
        # but provide a safe default just in case
        return HoneypotType.VULNERABLE_WEBAPP
    
    def add_rule(self, rule: HoneypotClassificationRule) -> None:
        """
        Add a new classification rule.
        
        Args:
            rule: Classification rule to add
        """
        self.rules.append(rule)
        # Re-sort rules by priority
        self.rules.sort(key=lambda r: r.get_priority(), reverse=True)
    
    def get_classification_details(self, request_info: RequestInfo) -> Dict[str, Any]:
        """
        Get detailed classification information for debugging/analysis.
        
        Args:
            request_info: Structured request information
            
        Returns:
            Dict containing classification details and rule matches
        """
        matched_rules = []
        final_classification = None
        
        for rule in self.rules:
            if rule.matches(request_info):
                rule_info = {
                    'rule_name': rule.__class__.__name__,
                    'honeypot_type': rule.get_honeypot_type().value,
                    'priority': rule.get_priority()
                }
                matched_rules.append(rule_info)
                
                # First match is the winner (highest priority)
                if final_classification is None:
                    final_classification = rule.get_honeypot_type()
        
        return {
            'final_classification': final_classification.value if final_classification else None,
            'matched_rules': matched_rules,
            'total_rules_checked': len(self.rules)
        }