"""
Unit tests for request parsing functionality.

This module tests the request parsing and validation components,
ensuring proper handling of various Lambda event formats.
"""

import unittest
from unittest.mock import Mock
from datetime import datetime

from src.request_parser import RequestParser, RequestValidator
from src.config import HoneypotConfig
from src.models import RequestInfo


class TestRequestParser(unittest.TestCase):
    """Test cases for the RequestParser class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = HoneypotConfig(
            honeypot_bucket="test-bucket",
            log_level="INFO",
            aws_region="us-west-2",
            max_body_size=1024,
            max_headers=50
        )
        self.parser = RequestParser(self.config)
        self.context = Mock()
        self.context.aws_request_id = "test-request-id-123"
    
    def test_parse_basic_get_request(self):
        """Test parsing a basic GET request."""
        event = {
            'requestContext': {
                'http': {
                    'method': 'GET',
                    'sourceIp': '192.168.1.100'
                }
            },
            'headers': {
                'host': 'example.com',
                'user-agent': 'Mozilla/5.0 (compatible; test-browser)'
            },
            'rawPath': '/admin',
            'queryStringParameters': None,
            'body': None,
            'isBase64Encoded': False
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        self.assertIsInstance(result, RequestInfo)
        self.assertEqual(result.method, 'GET')
        self.assertEqual(result.path, '/admin')
        self.assertEqual(result.client_ip, '192.168.1.100')
        self.assertEqual(result.user_agent, 'Mozilla/5.0 (compatible; test-browser)')
        self.assertEqual(result.body, '')
        self.assertEqual(result.request_id, 'test-request-id-123')
    
    def test_parse_post_request_with_body(self):
        """Test parsing a POST request with body content."""
        event = {
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': '10.0.0.1'
                }
            },
            'headers': {
                'content-type': 'application/x-www-form-urlencoded',
                'user-agent': 'curl/7.68.0'
            },
            'rawPath': '/admin',
            'queryStringParameters': None,
            'body': 'username=admin&password=secret123',
            'isBase64Encoded': False
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        self.assertEqual(result.method, 'POST')
        self.assertEqual(result.body, 'username=admin&password=secret123')
        self.assertEqual(result.client_ip, '10.0.0.1')
    
    def test_parse_request_with_x_forwarded_for(self):
        """Test IP extraction from X-Forwarded-For header."""
        event = {
            'requestContext': {
                'http': {
                    'method': 'GET',
                    'sourceIp': '10.0.0.1'  # This should be overridden
                }
            },
            'headers': {
                'x-forwarded-for': '203.0.113.1, 10.0.0.1',
                'user-agent': 'test-agent'
            },
            'rawPath': '/',
            'queryStringParameters': None,
            'body': None
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        # Should extract the first IP from X-Forwarded-For
        self.assertEqual(result.client_ip, '203.0.113.1')
    
    def test_parse_base64_encoded_body(self):
        """Test parsing base64-encoded request body."""
        import base64
        
        original_body = 'username=test&password=encoded'
        encoded_body = base64.b64encode(original_body.encode()).decode()
        
        event = {
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': '192.168.1.1'
                }
            },
            'headers': {'user-agent': 'test'},
            'rawPath': '/login',
            'body': encoded_body,
            'isBase64Encoded': True
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        self.assertEqual(result.body, original_body)
    
    def test_parse_request_with_query_parameters(self):
        """Test parsing request with query parameters."""
        event = {
            'requestContext': {
                'http': {
                    'method': 'GET',
                    'sourceIp': '192.168.1.1'
                }
            },
            'headers': {'user-agent': 'test'},
            'rawPath': '/search',
            'queryStringParameters': {
                'q': 'test query',
                'category': 'admin'
            }
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        self.assertEqual(result.query_params['q'], 'test query')
        self.assertEqual(result.query_params['category'], 'admin')
    
    def test_body_size_limit_enforcement(self):
        """Test that large request bodies are truncated."""
        large_body = 'x' * (self.config.max_body_size + 100)
        
        event = {
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': '192.168.1.1'
                }
            },
            'headers': {'user-agent': 'test'},
            'rawPath': '/upload',
            'body': large_body,
            'isBase64Encoded': False
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        # Body should be truncated
        self.assertTrue(result.body.endswith('[TRUNCATED]'))
        self.assertLessEqual(len(result.body), self.config.max_body_size + 20)
    
    def test_header_count_limit_enforcement(self):
        """Test that excessive headers are limited."""
        # Create more headers than the limit
        headers = {f'header-{i}': f'value-{i}' for i in range(self.config.max_headers + 10)}
        headers['user-agent'] = 'test-agent'
        
        event = {
            'requestContext': {
                'http': {
                    'method': 'GET',
                    'sourceIp': '192.168.1.1'
                }
            },
            'headers': headers,
            'rawPath': '/'
        }
        
        result = self.parser.parse_lambda_event(event, self.context)
        
        # Should have at most max_headers
        self.assertLessEqual(len(result.headers), self.config.max_headers)


class TestRequestValidator(unittest.TestCase):
    """Test cases for the RequestValidator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = HoneypotConfig(
            honeypot_bucket="test-bucket",
            log_level="INFO",
            aws_region="us-west-2"
        )
        self.validator = RequestValidator(self.config)
    
    def test_validate_valid_request(self):
        """Test validation of a valid request."""
        request_info = RequestInfo(
            timestamp=datetime.utcnow().isoformat(),
            session_id="session123",
            client_ip="192.168.1.1",
            method="GET",
            path="/admin",
            headers={'user-agent': 'test'},
            query_params={},
            body="",
            user_agent="test-agent",
            referer="",
            request_id="req123"
        )
        
        result = self.validator.validate_request(request_info)
        self.assertTrue(result)
    
    def test_validate_invalid_method(self):
        """Test validation fails for invalid HTTP method."""
        request_info = RequestInfo(
            timestamp=datetime.utcnow().isoformat(),
            session_id="session123",
            client_ip="192.168.1.1",
            method="INVALID",  # Invalid HTTP method
            path="/admin",
            headers={'user-agent': 'test'},
            query_params={},
            body="",
            user_agent="test-agent",
            referer="",
            request_id="req123"
        )
        
        result = self.validator.validate_request(request_info)
        self.assertFalse(result)
    
    def test_validate_missing_required_fields(self):
        """Test validation fails when required fields are missing."""
        request_info = RequestInfo(
            timestamp="",  # Missing timestamp
            session_id="session123",
            client_ip="",  # Missing IP
            method="GET",
            path="/admin",
            headers={'user-agent': 'test'},
            query_params={},
            body="",
            user_agent="test-agent",
            referer="",
            request_id="req123"
        )
        
        result = self.validator.validate_request(request_info)
        self.assertFalse(result)
    
    def test_validate_invalid_path(self):
        """Test validation fails for invalid path format."""
        request_info = RequestInfo(
            timestamp=datetime.utcnow().isoformat(),
            session_id="session123",
            client_ip="192.168.1.1",
            method="GET",
            path="invalid-path",  # Should start with /
            headers={'user-agent': 'test'},
            query_params={},
            body="",
            user_agent="test-agent",
            referer="",
            request_id="req123"
        )
        
        result = self.validator.validate_request(request_info)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()