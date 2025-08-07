"""
Honeypot Security System

A sophisticated honeypot implementation designed to attract, detect, and analyze
malicious activities against web applications and APIs. This system follows
software engineering best practices including SOLID principles, clean
architecture, and comprehensive logging.

Main Components:
- Request parsing and validation
- Threat detection and analysis
- Honeypot classification and response generation
- Comprehensive logging and monitoring
- Extensible rule-based system

Usage:
    from src.lambda_handler import lambda_handler
    
    # AWS Lambda handler
    response = lambda_handler(event, context)

Author: [Your Name]
Version: 2.0.0
License: MIT
"""

from .lambda_handler import (
    lambda_handler,
    health_check_handler,
    debug_handler,
    honeypot_lambda_handler
)

from .honeypot_orchestrator import HoneypotOrchestrator
from .config import HoneypotConfig
from .models import (
    HoneypotType,
    ThreatLevel,
    RequestInfo,
    ThreatIndicator,
    HoneypotInteraction,
    HoneypotResponse,
    MetricData
)

# Version information
__version__ = "2.0.0"
__author__ = "Your Name"
__license__ = "MIT"

# Public API
__all__ = [
    # Main handlers
    'lambda_handler',
    'health_check_handler', 
    'debug_handler',
    'honeypot_lambda_handler',
    
    # Core classes
    'HoneypotOrchestrator',
    'HoneypotConfig',
    
    # Data models
    'HoneypotType',
    'ThreatLevel',
    'RequestInfo',
    'ThreatIndicator',
    'HoneypotInteraction',
    'HoneypotResponse',
    'MetricData',
    
    # Version info
    '__version__',
    '__author__',
    '__license__'
]