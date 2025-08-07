"""
Logging and monitoring management for the honeypot system.

This module handles all logging, metrics collection, and monitoring
functions, following the Single Responsibility Principle.
"""

import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from .models import HoneypotInteraction, MetricData, ThreatLevel
from .config import HoneypotConfig


class HoneypotLogger:
    """
    Manages structured logging for honeypot interactions.
    
    This class handles logging to CloudWatch Logs with proper
    error handling and structured data formatting.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize the logger with configuration."""
        self.config = config
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Configure the Python logger for structured output."""
        # Configure root logger for CloudWatch Logs
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper(), logging.INFO),
            format='%(message)s',  # CloudWatch Logs will handle timestamps
            force=True
        )
        
        self.logger = logging.getLogger('honeypot')
    
    def log_interaction(self, interaction: HoneypotInteraction) -> bool:
        """
        Log a honeypot interaction with structured data.
        
        Args:
            interaction: Complete honeypot interaction data
            
        Returns:
            bool: True if logging was successful, False otherwise
        """
        try:
            # Create structured log entry
            log_entry = interaction.to_log_entry()
            
            # Add additional metadata
            log_entry['log_type'] = 'honeypot_interaction'
            log_entry['log_version'] = '1.0'
            
            # Log as structured JSON
            self.logger.info(json.dumps(log_entry, ensure_ascii=False))
            
            return True
            
        except Exception as e:
            # Log the error but don't raise - we don't want logging
            # failures to break the honeypot functionality
            self.logger.error(f"Failed to log interaction: {str(e)}")
            return False
    
    def log_error(self, error_message: str, error_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Log an error with optional context information.
        
        Args:
            error_message: Description of the error
            error_context: Optional additional context information
        """
        try:
            error_entry = {
                'log_type': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'message': error_message,
                'context': error_context or {}
            }
            
            self.logger.error(json.dumps(error_entry))
            
        except Exception:
            # Fallback to simple string logging if JSON serialization fails
            self.logger.error(f"Error: {error_message}")
    
    def log_metric_event(self, metric_name: str, value: float, 
                        dimensions: Optional[Dict[str, str]] = None) -> None:
        """
        Log a metric event for later processing.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            dimensions: Optional metric dimensions
        """
        try:
            metric_entry = {
                'log_type': 'metric',
                'timestamp': datetime.utcnow().isoformat(),
                'metric_name': metric_name,
                'value': value,
                'dimensions': dimensions or {}
            }
            
            self.logger.info(json.dumps(metric_entry))
            
        except Exception as e:
            self.log_error(f"Failed to log metric {metric_name}", {'error': str(e)})


class CloudWatchMetricsManager:
    """
    Manages CloudWatch metrics for honeypot monitoring.
    
    This class handles sending custom metrics to CloudWatch
    for monitoring and alerting purposes.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize the metrics manager with configuration."""
        self.config = config
        try:
            self.cloudwatch = boto3.client('cloudwatch', region_name=config.aws_region)
        except Exception as e:
            # Initialize without CloudWatch if it's not available
            self.cloudwatch = None
            print(f"Warning: CloudWatch client initialization failed: {e}")
    
    def send_interaction_metrics(self, interaction: HoneypotInteraction) -> bool:
        """
        Send metrics for a honeypot interaction.
        
        Args:
            interaction: Honeypot interaction data
            
        Returns:
            bool: True if metrics were sent successfully, False otherwise
        """
        if not self.cloudwatch:
            return False
        
        try:
            metrics_data = self._create_interaction_metrics(interaction)
            
            # Send metrics in batches (CloudWatch limit is 20 metrics per call)
            batch_size = 20
            for i in range(0, len(metrics_data), batch_size):
                batch = metrics_data[i:i + batch_size]
                
                self.cloudwatch.put_metric_data(
                    Namespace=self.config.metrics_namespace,
                    MetricData=[metric.to_cloudwatch_format() for metric in batch]
                )
            
            return True
            
        except (ClientError, BotoCoreError) as e:
            print(f"CloudWatch metrics error: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error sending metrics: {e}")
            return False
    
    def _create_interaction_metrics(self, interaction: HoneypotInteraction) -> List[MetricData]:
        """
        Create CloudWatch metrics from a honeypot interaction.
        
        Args:
            interaction: Honeypot interaction data
            
        Returns:
            List[MetricData]: List of metrics to send to CloudWatch
        """
        metrics = []
        request_info = interaction.request_info
        
        # Basic interaction count metric
        metrics.append(MetricData(
            metric_name='TotalInteractions',
            value=1.0,
            unit='Count',
            dimensions={
                'HoneypotType': interaction.honeypot_type.value,
                'ClientIP': request_info.client_ip,
                'Method': request_info.method
            }
        ))
        
        # Threat-related metrics
        if interaction.threat_indicators:
            # Total threats detected
            metrics.append(MetricData(
                metric_name='ThreatsDetected',
                value=len(interaction.threat_indicators),
                unit='Count',
                dimensions={
                    'HoneypotType': interaction.honeypot_type.value,
                    'ClientIP': request_info.client_ip
                }
            ))
            
            # Metrics by threat category
            threat_categories = {}
            for indicator in interaction.threat_indicators:
                category = indicator.category
                threat_categories[category] = threat_categories.get(category, 0) + 1
            
            for category, count in threat_categories.items():
                metrics.append(MetricData(
                    metric_name='ThreatsByCategory',
                    value=count,
                    unit='Count',
                    dimensions={
                        'ThreatCategory': category,
                        'HoneypotType': interaction.honeypot_type.value
                    }
                ))
            
            # High-severity threat alerts
            high_severity_count = sum(
                1 for indicator in interaction.threat_indicators
                if indicator.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            )
            
            if high_severity_count > 0:
                metrics.append(MetricData(
                    metric_name='HighSeverityThreats',
                    value=high_severity_count,
                    unit='Count',
                    dimensions={
                        'ClientIP': request_info.client_ip,
                        'HoneypotType': interaction.honeypot_type.value
                    }
                ))
        
        # Performance metrics
        if interaction.processing_time_ms:
            metrics.append(MetricData(
                metric_name='ProcessingTime',
                value=interaction.processing_time_ms,
                unit='Milliseconds',
                dimensions={
                    'HoneypotType': interaction.honeypot_type.value
                }
            ))
        
        # Geographic and source metrics (if available)
        user_agent = request_info.user_agent.lower()
        if any(bot in user_agent for bot in ['bot', 'crawler', 'scanner']):
            metrics.append(MetricData(
                metric_name='AutomatedRequests',
                value=1.0,
                unit='Count',
                dimensions={
                    'HoneypotType': interaction.honeypot_type.value,
                    'UserAgentType': 'automated'
                }
            ))
        
        return metrics
    
    def send_custom_metric(self, metric_name: str, value: float, unit: str = 'Count',
                          dimensions: Optional[Dict[str, str]] = None) -> bool:
        """
        Send a custom metric to CloudWatch.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Metric unit (Count, Seconds, etc.)
            dimensions: Optional metric dimensions
            
        Returns:
            bool: True if metric was sent successfully, False otherwise
        """
        if not self.cloudwatch:
            return False
        
        try:
            metric = MetricData(
                metric_name=metric_name,
                value=value,
                unit=unit,
                dimensions=dimensions or {}
            )
            
            self.cloudwatch.put_metric_data(
                Namespace=self.config.metrics_namespace,
                MetricData=[metric.to_cloudwatch_format()]
            )
            
            return True
            
        except Exception as e:
            print(f"Failed to send custom metric {metric_name}: {e}")
            return False


class MonitoringManager:
    """
    Coordinates logging and monitoring for the honeypot system.
    
    This class provides a unified interface for all logging and
    monitoring operations, following the Facade Pattern.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize the monitoring manager with all components."""
        self.config = config
        self.logger = HoneypotLogger(config)
        self.metrics_manager = CloudWatchMetricsManager(config)
    
    def record_interaction(self, interaction: HoneypotInteraction) -> Dict[str, bool]:
        """
        Record a complete honeypot interaction with logging and metrics.
        
        Args:
            interaction: Complete honeypot interaction data
            
        Returns:
            Dict[str, bool]: Status of each recording operation
        """
        results = {}
        
        # Log the interaction
        results['logging'] = self.logger.log_interaction(interaction)
        
        # Send metrics
        results['metrics'] = self.metrics_manager.send_interaction_metrics(interaction)
        
        # Log any failures
        if not results['logging']:
            self.logger.log_error("Failed to log interaction")
        
        if not results['metrics']:
            self.logger.log_error("Failed to send interaction metrics")
        
        return results
    
    def record_error(self, error_message: str, 
                    error_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Record an error event.
        
        Args:
            error_message: Description of the error
            error_context: Optional additional context information
        """
        self.logger.log_error(error_message, error_context)
        
        # Send error metric
        self.metrics_manager.send_custom_metric(
            metric_name='Errors',
            value=1.0,
            dimensions={'ErrorType': 'application_error'}
        )
    
    def record_performance_metric(self, operation: str, duration_ms: float) -> None:
        """
        Record a performance metric.
        
        Args:
            operation: Name of the operation being measured
            duration_ms: Duration in milliseconds
        """
        self.logger.log_metric_event(
            metric_name=f'{operation}_duration',
            value=duration_ms,
            dimensions={'operation': operation}
        )
        
        self.metrics_manager.send_custom_metric(
            metric_name='OperationDuration',
            value=duration_ms,
            unit='Milliseconds',
            dimensions={'Operation': operation}
        )
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check of monitoring components.
        
        Returns:
            Dict[str, Any]: Health status of each component
        """
        health_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'components': {}
        }
        
        # Check logger
        try:
            self.logger.logger.info("Health check")
            health_status['components']['logger'] = 'healthy'
        except Exception as e:
            health_status['components']['logger'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'degraded'
        
        # Check CloudWatch metrics
        if self.metrics_manager.cloudwatch:
            try:
                # Test metric send
                test_result = self.metrics_manager.send_custom_metric(
                    'HealthCheck', 1.0, dimensions={'test': 'true'}
                )
                health_status['components']['cloudwatch_metrics'] = (
                    'healthy' if test_result else 'unhealthy'
                )
                if not test_result:
                    health_status['overall_status'] = 'degraded'
            except Exception as e:
                health_status['components']['cloudwatch_metrics'] = f'unhealthy: {str(e)}'
                health_status['overall_status'] = 'degraded'
        else:
            health_status['components']['cloudwatch_metrics'] = 'unavailable'
            health_status['overall_status'] = 'degraded'
        
        return health_status