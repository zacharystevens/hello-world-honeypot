"""
Request parsing utilities for the honeypot system.

This module handles the extraction and processing of HTTP request data
from AWS Lambda events, following the Single Responsibility Principle.
"""

import base64
import hashlib
import time
from datetime import datetime
from typing import Dict, Any, Optional

from .models import RequestInfo
from .config import HoneypotConfig


class RequestParser:
    """
    Responsible for parsing AWS Lambda events into structured RequestInfo objects.
    
    This class encapsulates all the logic needed to extract meaningful
    information from AWS API Gateway Lambda proxy events.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize the request parser with configuration."""
        self.config = config
    
    def parse_lambda_event(self, event: Dict[str, Any], context: Any) -> RequestInfo:
        """
        Parse an AWS Lambda event into a structured RequestInfo object.
        
        Args:
            event: AWS Lambda event data from API Gateway
            context: AWS Lambda context object
            
        Returns:
            RequestInfo: Structured request information
            
        Raises:
            ValueError: If required event data is missing or invalid
        """
        try:
            # Extract and validate basic request information
            client_ip = self._extract_client_ip(event)
            headers = self._extract_headers(event)
            method = self._extract_method(event)
            path = self._extract_path(event)
            query_params = self._extract_query_params(event)
            body = self._extract_body(event)
            
            # Generate session ID for tracking
            session_id = self._generate_session_id(client_ip)
            
            return RequestInfo(
                timestamp=datetime.utcnow().isoformat(),
                session_id=session_id,
                client_ip=client_ip,
                method=method,
                path=path,
                headers=headers,
                query_params=query_params,
                body=body,
                user_agent=headers.get('user-agent', 'Unknown'),
                referer=headers.get('referer', ''),
                request_id=context.aws_request_id
            )
            
        except Exception as e:
            raise ValueError(f"Failed to parse Lambda event: {str(e)}") from e
    
    def _extract_client_ip(self, event: Dict[str, Any]) -> str:
        """
        Extract the real client IP address from the event.
        
        Handles various proxy scenarios including CloudFront,
        load balancers, and direct connections.
        """
        headers = event.get('headers', {})
        
        # Check for CloudFront viewer address
        if 'cloudfront-viewer-address' in headers:
            return headers['cloudfront-viewer-address'].split(':')[0]
        
        # Check for X-Forwarded-For (most common)
        if 'x-forwarded-for' in headers:
            # Take the first IP in the chain (original client)
            return headers['x-forwarded-for'].split(',')[0].strip()
        
        # Check for X-Real-IP
        if 'x-real-ip' in headers:
            return headers['x-real-ip']
        
        # Fallback to source IP from request context
        request_context = event.get('requestContext', {})
        http_info = request_context.get('http', {})
        return http_info.get('sourceIp', 'Unknown')
    
    def _extract_headers(self, event: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract and sanitize HTTP headers from the event.
        
        Applies security limits and normalizes header names.
        """
        headers = event.get('headers', {})
        
        # Apply security limit on number of headers
        if len(headers) > self.config.max_headers:
            # Log security event but continue processing
            headers = dict(list(headers.items())[:self.config.max_headers])
        
        # Normalize header names to lowercase for consistent processing
        return {key.lower(): str(value) for key, value in headers.items()}
    
    def _extract_method(self, event: Dict[str, Any]) -> str:
        """Extract HTTP method from the event."""
        request_context = event.get('requestContext', {})
        http_info = request_context.get('http', {})
        return http_info.get('method', 'GET').upper()
    
    def _extract_path(self, event: Dict[str, Any]) -> str:
        """Extract the request path from the event."""
        # Prefer rawPath for exact path representation
        path = event.get('rawPath', event.get('path', '/'))
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
            
        return path
    
    def _extract_query_params(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract query parameters from the event."""
        query_params = event.get('queryStringParameters')
        
        # Handle None case (when no query parameters exist)
        if query_params is None:
            return {}
        
        # Ensure all values are strings for consistent processing
        return {key: str(value) for key, value in query_params.items()}
    
    def _extract_body(self, event: Dict[str, Any]) -> str:
        """
        Extract and decode the request body from the event.
        
        Handles both plain text and base64-encoded bodies.
        Applies security limits on body size.
        """
        body = event.get('body', '')
        
        if not body:
            return ''
        
        # Handle base64-encoded bodies
        if event.get('isBase64Encoded', False):
            try:
                body = base64.b64decode(body).decode('utf-8')
            except Exception:
                # If decoding fails, return a safe placeholder
                return '[Base64 decode failed - potentially malicious content]'
        
        # Apply security limit on body size
        if len(body) > self.config.max_body_size:
            body = body[:self.config.max_body_size] + '[TRUNCATED]'
        
        return body
    
    def _generate_session_id(self, client_ip: str) -> str:
        """
        Generate a unique session ID for tracking purposes.
        
        Uses a combination of client IP and timestamp to create
        a reasonably unique identifier for this session.
        """
        session_data = f"{client_ip}{time.time()}"
        return hashlib.md5(session_data.encode()).hexdigest()[:12]


class RequestValidator:
    """
    Validates parsed request data for security and correctness.
    
    This class provides additional validation beyond basic parsing
    to ensure data integrity and security.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize the validator with configuration."""
        self.config = config
    
    def validate_request(self, request_info: RequestInfo) -> bool:
        """
        Validate a parsed request for basic security and correctness.
        
        Args:
            request_info: Parsed request information
            
        Returns:
            bool: True if request passes validation, False otherwise
        """
        try:
            # Validate required fields are present
            if not all([
                request_info.client_ip,
                request_info.method,
                request_info.path,
                request_info.timestamp
            ]):
                return False
            
            # Validate method is a known HTTP method
            valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
            if request_info.method not in valid_methods:
                return False
            
            # Validate path format
            if not request_info.path.startswith('/'):
                return False
            
            # Additional security validations can be added here
            return True
            
        except Exception:
            return False