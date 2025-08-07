"""
Main orchestrator for the honeypot system.

This module coordinates all components of the honeypot system,
following the Facade Pattern to provide a clean interface for the Lambda function.
"""

import time
from typing import Dict, Any, Optional

from .config import HoneypotConfig
from .models import HoneypotInteraction, HoneypotType
from .request_parser import RequestParser, RequestValidator
from .threat_analyzer import ThreatAnalyzer, ThreatIntelligence
from .honeypot_classifier import HoneypotClassifier
from .response_generator import ResponseGeneratorFactory
from .logging_manager import MonitoringManager


class HoneypotOrchestrator:
    """
    Main orchestrator that coordinates all honeypot components.
    
    This class implements the Facade Pattern, providing a simplified
    interface for the Lambda function while managing all the complex
    interactions between different components.
    """
    
    def __init__(self, config: Optional[HoneypotConfig] = None):
        """
        Initialize the honeypot orchestrator with all components.
        
        Args:
            config: Optional configuration object. If not provided,
                   configuration will be loaded from environment variables.
        """
        # Load configuration
        self.config = config or HoneypotConfig.from_environment()
        
        # Initialize all components
        self.request_parser = RequestParser(self.config)
        self.request_validator = RequestValidator(self.config)
        self.threat_analyzer = ThreatAnalyzer()
        self.threat_intelligence = ThreatIntelligence()
        self.honeypot_classifier = HoneypotClassifier()
        self.response_generator_factory = ResponseGeneratorFactory(self.config)
        self.monitoring_manager = MonitoringManager(self.config)
        
        # Performance tracking
        self._start_time: Optional[float] = None
    
    def process_request(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Process an incoming request through the complete honeypot pipeline.
        
        This is the main entry point that coordinates all honeypot operations:
        1. Parse and validate the request
        2. Analyze for threats
        3. Classify the honeypot type
        4. Generate appropriate response
        5. Log everything for analysis
        
        Args:
            event: AWS Lambda event from API Gateway
            context: AWS Lambda context object
            
        Returns:
            Dict[str, Any]: HTTP response in Lambda format
        """
        # Start performance tracking
        self._start_time = time.time()
        
        try:
            # Step 1: Parse the incoming request
            request_info = self._parse_request(event, context)
            if not request_info:
                return self._create_error_response("Invalid request format", 400)
            
            # Step 2: Validate the request
            if not self._validate_request(request_info):
                return self._create_error_response("Request validation failed", 400)
            
            # Step 3: Analyze for security threats
            threat_indicators = self._analyze_threats(request_info)
            
            # Step 4: Classify the honeypot type
            honeypot_type = self._classify_honeypot(request_info)
            
            # Step 5: Generate appropriate response
            response = self._generate_response(honeypot_type, request_info)
            
            # Step 6: Create complete interaction record
            interaction = self._create_interaction_record(
                request_info, honeypot_type, threat_indicators
            )
            
            # Step 7: Log and monitor everything
            self._record_interaction(interaction)
            
            # Step 8: Return the response
            return response.to_lambda_response()
            
        except Exception as e:
            # Handle any unexpected errors gracefully
            return self._handle_error(e, event, context)
    
    def _parse_request(self, event: Dict[str, Any], context: Any):
        """Parse the Lambda event into structured request information."""
        try:
            return self.request_parser.parse_lambda_event(event, context)
        except Exception as e:
            self.monitoring_manager.record_error(
                "Request parsing failed",
                {"error": str(e), "event_keys": list(event.keys())}
            )
            return None
    
    def _validate_request(self, request_info) -> bool:
        """Validate the parsed request information."""
        try:
            return self.request_validator.validate_request(request_info)
        except Exception as e:
            self.monitoring_manager.record_error(
                "Request validation failed",
                {"error": str(e)}
            )
            return False
    
    def _analyze_threats(self, request_info):
        """Analyze the request for security threats."""
        try:
            # Basic threat analysis
            threat_indicators = self.threat_analyzer.analyze_request(request_info)
            
            # Enrich with threat intelligence
            enriched_indicators = self.threat_intelligence.enrich_threats(
                threat_indicators, request_info
            )
            
            return enriched_indicators
            
        except Exception as e:
            self.monitoring_manager.record_error(
                "Threat analysis failed",
                {"error": str(e)}
            )
            return []  # Continue with empty threat list
    
    def _classify_honeypot(self, request_info) -> HoneypotType:
        """Classify the request to determine honeypot type."""
        try:
            return self.honeypot_classifier.classify_request(request_info)
        except Exception as e:
            self.monitoring_manager.record_error(
                "Honeypot classification failed",
                {"error": str(e)}
            )
            # Fallback to default honeypot type
            return HoneypotType.VULNERABLE_WEBAPP
    
    def _generate_response(self, honeypot_type: HoneypotType, request_info):
        """Generate the appropriate honeypot response."""
        try:
            return self.response_generator_factory.generate_response(
                honeypot_type, request_info
            )
        except Exception as e:
            self.monitoring_manager.record_error(
                "Response generation failed",
                {"error": str(e), "honeypot_type": honeypot_type.value}
            )
            # Fallback to a basic response
            return self._create_fallback_response()
    
    def _create_interaction_record(self, request_info, honeypot_type, threat_indicators):
        """Create a complete interaction record for logging."""
        processing_time = None
        if self._start_time:
            processing_time = (time.time() - self._start_time) * 1000  # Convert to milliseconds
        
        return HoneypotInteraction(
            request_info=request_info,
            honeypot_type=honeypot_type,
            threat_indicators=threat_indicators,
            processing_time_ms=processing_time
        )
    
    def _record_interaction(self, interaction: HoneypotInteraction) -> None:
        """Record the interaction for monitoring and analysis."""
        try:
            results = self.monitoring_manager.record_interaction(interaction)
            
            # Record performance metric
            if interaction.processing_time_ms:
                self.monitoring_manager.record_performance_metric(
                    'request_processing', interaction.processing_time_ms
                )
            
        except Exception as e:
            # Don't let logging failures break the honeypot
            print(f"Failed to record interaction: {e}")
    
    def _handle_error(self, error: Exception, event: Dict[str, Any], 
                     context: Any) -> Dict[str, Any]:
        """Handle unexpected errors gracefully."""
        try:
            # Record the error
            self.monitoring_manager.record_error(
                f"Honeypot processing error: {str(error)}",
                {
                    "error_type": type(error).__name__,
                    "request_id": getattr(context, 'aws_request_id', 'unknown'),
                    "event_path": event.get('rawPath', event.get('path', 'unknown'))
                }
            )
        except Exception:
            # If even error recording fails, just print
            print(f"Critical error in honeypot: {error}")
        
        # Return a generic error response that doesn't reveal system details
        return self._create_error_response("Internal server error", 500)
    
    def _create_error_response(self, message: str, status_code: int) -> Dict[str, Any]:
        """Create a generic error response."""
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'text/html'
            },
            'body': f'''
            <html>
            <head><title>Error {status_code}</title></head>
            <body>
                <h1>Error {status_code}</h1>
                <p>{message}</p>
            </body>
            </html>
            '''
        }
    
    def _create_fallback_response(self):
        """Create a fallback response when normal processing fails."""
        from .models import HoneypotResponse
        
        return HoneypotResponse(
            status_code=200,
            headers={},
            body='''
            <html>
            <head><title>Welcome</title></head>
            <body>
                <h1>Welcome</h1>
                <p>This is a basic web server.</p>
            </body>
            </html>
            ''',
            content_type='text/html'
        )
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get the health status of all honeypot components.
        
        Returns:
            Dict[str, Any]: Comprehensive health status
        """
        try:
            return self.monitoring_manager.health_check()
        except Exception as e:
            return {
                'overall_status': 'critical',
                'error': str(e),
                'timestamp': time.time()
            }
    
    def get_classification_details(self, event: Dict[str, Any], 
                                 context: Any) -> Dict[str, Any]:
        """
        Get detailed classification information for debugging purposes.
        
        This method is useful for understanding how requests are being
        classified and can help with tuning classification rules.
        
        Args:
            event: AWS Lambda event from API Gateway
            context: AWS Lambda context object
            
        Returns:
            Dict[str, Any]: Detailed classification information
        """
        try:
            # Parse request
            request_info = self.request_parser.parse_lambda_event(event, context)
            
            # Get classification details
            classification_details = self.honeypot_classifier.get_classification_details(
                request_info
            )
            
            # Add threat analysis details
            threat_indicators = self.threat_analyzer.analyze_request(request_info)
            threat_summary = {
                'total_threats': len(threat_indicators),
                'categories': list(set(indicator.category for indicator in threat_indicators)),
                'max_severity': max(
                    (indicator.severity.value for indicator in threat_indicators),
                    default='none'
                )
            }
            
            return {
                'request_summary': {
                    'method': request_info.method,
                    'path': request_info.path,
                    'client_ip': request_info.client_ip,
                    'user_agent': request_info.user_agent[:100]  # Truncate for readability
                },
                'classification': classification_details,
                'threat_analysis': threat_summary,
                'timestamp': request_info.timestamp
            }
            
        except Exception as e:
            return {
                'error': f"Failed to get classification details: {str(e)}",
                'timestamp': time.time()
            }