"""
AWS Lambda function handler for the honeypot system.

This module provides the main entry point for AWS Lambda,
following the principle of keeping the handler as simple as possible.
"""

from typing import Dict, Any

from .honeypot_orchestrator import HoneypotOrchestrator
from .config import HoneypotConfig


# Global orchestrator instance for reuse across Lambda invocations
# This follows AWS Lambda best practices for performance optimization
_orchestrator: HoneypotOrchestrator = None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda function handler for honeypot requests.
    
    This is the main entry point called by AWS Lambda. It delegates
    all processing to the HoneypotOrchestrator while maintaining
    the simple interface required by Lambda.
    
    Args:
        event: AWS Lambda event data from API Gateway
        context: AWS Lambda context object
        
    Returns:
        Dict[str, Any]: HTTP response in AWS Lambda format
    """
    global _orchestrator
    
    # Initialize orchestrator on first invocation (Lambda container reuse)
    if _orchestrator is None:
        try:
            config = HoneypotConfig.from_environment()
            _orchestrator = HoneypotOrchestrator(config)
        except Exception as e:
            # If initialization fails, return a basic error response
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'text/plain'},
                'body': f'Honeypot initialization failed: {str(e)}'
            }
    
    # Process the request through the honeypot system
    return _orchestrator.process_request(event, context)


def health_check_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Health check handler for monitoring purposes.
    
    This function can be called by monitoring systems to check
    the health of the honeypot system components.
    
    Args:
        event: AWS Lambda event data
        context: AWS Lambda context object
        
    Returns:
        Dict[str, Any]: Health status response
    """
    global _orchestrator
    
    try:
        # Initialize orchestrator if needed
        if _orchestrator is None:
            config = HoneypotConfig.from_environment()
            _orchestrator = HoneypotOrchestrator(config)
        
        # Get health status
        health_status = _orchestrator.get_health_status()
        
        # Determine HTTP status code based on health
        status_code = 200
        if health_status.get('overall_status') == 'degraded':
            status_code = 200  # Still operational but degraded
        elif health_status.get('overall_status') == 'critical':
            status_code = 503  # Service unavailable
        
        return {
            'statusCode': status_code,
            'headers': {'Content-Type': 'application/json'},
            'body': str(health_status)  # JSON serialization handled by response
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': f'{{"error": "Health check failed", "details": "{str(e)}"}}'
        }


def debug_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Debug handler for development and troubleshooting.
    
    This function provides detailed information about how requests
    are being classified and processed. Should only be used in
    development environments.
    
    Args:
        event: AWS Lambda event data
        context: AWS Lambda context object
        
    Returns:
        Dict[str, Any]: Debug information response
    """
    global _orchestrator
    
    try:
        # Initialize orchestrator if needed
        if _orchestrator is None:
            config = HoneypotConfig.from_environment()
            _orchestrator = HoneypotOrchestrator(config)
        
        # Get classification details
        debug_info = _orchestrator.get_classification_details(event, context)
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': str(debug_info)  # JSON serialization handled by response
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': f'{{"error": "Debug handler failed", "details": "{str(e)}"}}'
        }


# For backwards compatibility with the original honeypot_lambda.py
def honeypot_lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Backwards compatibility handler.
    
    This maintains compatibility with existing Terraform configurations
    that reference the original function name.
    """
    return lambda_handler(event, context)