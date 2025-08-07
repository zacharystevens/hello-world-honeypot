"""
Unit tests for threat analysis functionality.

This module tests the threat detection and analysis components,
ensuring proper identification of malicious patterns and security threats.
"""

import unittest
from datetime import datetime

from src.threat_analyzer import ThreatAnalyzer, ThreatIntelligence
from src.models import RequestInfo, ThreatLevel


class TestThreatAnalyzer(unittest.TestCase):
    """Test cases for the ThreatAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = ThreatAnalyzer()
    
    def _create_test_request(self, path="/", body="", headers=None, user_agent="test-agent"):
        """Helper method to create test request info."""
        return RequestInfo(
            timestamp=datetime.utcnow().isoformat(),
            session_id="session123",
            client_ip="192.168.1.1",
            method="GET",
            path=path,
            headers=headers or {},
            query_params={},
            body=body,
            user_agent=user_agent,
            referer="",
            request_id="req123"
        )
    
    def test_detect_sql_injection_in_path(self):
        """Test detection of SQL injection patterns in URL path."""
        request = self._create_test_request(path="/admin?id=1' UNION SELECT * FROM users--")
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect SQL injection
        sql_indicators = [i for i in indicators if i.category == 'sql_injection']
        self.assertTrue(len(sql_indicators) > 0)
        self.assertEqual(sql_indicators[0].severity, ThreatLevel.HIGH)
        self.assertEqual(sql_indicators[0].location, "path")
    
    def test_detect_xss_in_body(self):
        """Test detection of XSS patterns in request body."""
        request = self._create_test_request(
            body="comment=<script>alert('xss')</script>&submit=true"
        )
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect XSS
        xss_indicators = [i for i in indicators if i.category == 'xss']
        self.assertTrue(len(xss_indicators) > 0)
        self.assertEqual(xss_indicators[0].severity, ThreatLevel.HIGH)
        self.assertEqual(xss_indicators[0].location, "body")
    
    def test_detect_directory_traversal(self):
        """Test detection of directory traversal attacks."""
        request = self._create_test_request(path="/files?file=../../../etc/passwd")
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect directory traversal
        traversal_indicators = [i for i in indicators if i.category == 'directory_traversal']
        self.assertTrue(len(traversal_indicators) > 0)
        self.assertEqual(traversal_indicators[0].severity, ThreatLevel.HIGH)
    
    def test_detect_command_injection(self):
        """Test detection of command injection patterns."""
        request = self._create_test_request(body="cmd=ls -la; cat /etc/passwd")
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect command injection
        cmd_indicators = [i for i in indicators if i.category == 'command_injection']
        self.assertTrue(len(cmd_indicators) > 0)
        self.assertEqual(cmd_indicators[0].severity, ThreatLevel.CRITICAL)
    
    def test_detect_security_tools_in_user_agent(self):
        """Test detection of security tools via User-Agent."""
        request = self._create_test_request(user_agent="sqlmap/1.5.2")
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect security tool
        tool_indicators = [i for i in indicators if i.category == 'security_tool']
        self.assertTrue(len(tool_indicators) > 0)
        self.assertEqual(tool_indicators[0].severity, ThreatLevel.MEDIUM)
        self.assertEqual(tool_indicators[0].location, "user_agent")
    
    def test_detect_automated_tools(self):
        """Test detection of automated tools and bots."""
        request = self._create_test_request(user_agent="Mozilla/5.0 (compatible; bot)")
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect automated tool
        bot_indicators = [i for i in indicators if i.category == 'automated_tool']
        self.assertTrue(len(bot_indicators) > 0)
        self.assertEqual(bot_indicators[0].severity, ThreatLevel.LOW)
    
    def test_detect_obfuscation_patterns(self):
        """Test detection of obfuscation techniques."""
        request = self._create_test_request(
            body="data=eval(base64_decode('c2NyaXB0'))"
        )
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect obfuscation
        obf_indicators = [i for i in indicators if i.category == 'obfuscation']
        self.assertTrue(len(obf_indicators) > 0)
        self.assertEqual(obf_indicators[0].severity, ThreatLevel.MEDIUM)
    
    def test_url_decoding_analysis(self):
        """Test that URL-encoded attacks are properly decoded and detected."""
        # URL-encoded XSS payload
        encoded_path = "/search?q=%3Cscript%3Ealert('xss')%3C/script%3E"
        request = self._create_test_request(path=encoded_path)
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect XSS even when URL-encoded
        xss_indicators = [i for i in indicators if i.category == 'xss']
        self.assertTrue(len(xss_indicators) > 0)
    
    def test_multiple_threat_detection(self):
        """Test detection of multiple threats in a single request."""
        request = self._create_test_request(
            path="/admin?id=1' UNION SELECT password FROM users--",
            body="<script>alert('xss')</script>",
            user_agent="sqlmap/1.5.2"
        )
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should detect multiple categories
        categories = [i.category for i in indicators]
        self.assertIn('sql_injection', categories)
        self.assertIn('xss', categories)
        self.assertIn('security_tool', categories)
    
    def test_clean_request_no_threats(self):
        """Test that clean requests don't trigger false positives."""
        request = self._create_test_request(
            path="/about",
            body="name=John&email=john@example.com&message=Hello world",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        
        indicators = self.analyzer.analyze_request(request)
        
        # Should not detect any threats
        self.assertEqual(len(indicators), 0)
    
    def test_threat_location_tracking(self):
        """Test that threat locations are properly tracked."""
        request = self._create_test_request(
            path="/admin?debug=true",
            body="password=' OR 1=1--",
            headers={'x-custom': '<script>alert(1)</script>'}
        )
        
        indicators = self.analyzer.analyze_request(request)
        
        # Check that locations are properly assigned
        locations = [i.location for i in indicators]
        self.assertIn('body', locations)
        self.assertIn('headers', locations)


class TestThreatIntelligence(unittest.TestCase):
    """Test cases for the ThreatIntelligence class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.threat_intel = ThreatIntelligence()
    
    def test_enrich_threats_with_ip_reputation(self):
        """Test enrichment of threats with IP reputation data."""
        # Mock a known malicious IP
        self.threat_intel._known_malicious_ips.add("192.168.1.100")
        
        request = RequestInfo(
            timestamp=datetime.utcnow().isoformat(),
            session_id="session123",
            client_ip="192.168.1.100",  # Known malicious IP
            method="GET",
            path="/admin",
            headers={},
            query_params={},
            body="",
            user_agent="test-agent",
            referer="",
            request_id="req123"
        )
        
        # Start with no indicators
        indicators = []
        
        # Enrich with threat intelligence
        enriched = self.threat_intel.enrich_threats(indicators, request)
        
        # Should add IP reputation indicator
        ip_indicators = [i for i in enriched if i.category == 'ip_reputation']
        self.assertTrue(len(ip_indicators) > 0)
        self.assertEqual(ip_indicators[0].severity, ThreatLevel.HIGH)
    
    def test_enrich_threats_preserves_original(self):
        """Test that enrichment preserves original threat indicators."""
        from src.models import ThreatIndicator
        
        original_indicator = ThreatIndicator(
            pattern="test_pattern",
            category="test_category",
            severity=ThreatLevel.MEDIUM,
            description="Test indicator"
        )
        
        request = RequestInfo(
            timestamp=datetime.utcnow().isoformat(),
            session_id="session123",
            client_ip="192.168.1.1",
            method="GET",
            path="/test",
            headers={},
            query_params={},
            body="",
            user_agent="test-agent",
            referer="",
            request_id="req123"
        )
        
        enriched = self.threat_intel.enrich_threats([original_indicator], request)
        
        # Should preserve the original indicator
        self.assertIn(original_indicator, enriched)
    
    def test_update_threat_intelligence(self):
        """Test updating threat intelligence data."""
        # This is a placeholder test for the update mechanism
        new_threats = {"malicious_ips": ["10.0.0.1", "10.0.0.2"]}
        
        # Should not raise an exception
        self.threat_intel.update_threat_intelligence(new_threats)


if __name__ == '__main__':
    unittest.main()