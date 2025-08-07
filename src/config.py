"""
Configuration management for the honeypot system.

This module centralizes all configuration values and provides a clean interface
for accessing environment-specific settings.
"""

import os
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class HoneypotConfig:
    """Configuration class for honeypot settings."""
    
    # AWS Configuration
    honeypot_bucket: str
    log_level: str
    aws_region: str
    
    # Honeypot Behavior Configuration
    simulation_delay_min: float = 0.5
    simulation_delay_max: float = 2.0
    memory_size: int = 256
    timeout: int = 30
    
    # Logging Configuration
    log_retention_days: int = 90
    metrics_namespace: str = "Honeypot/Interactions"
    
    # Security Configuration
    max_body_size: int = 1024 * 1024  # 1MB
    max_headers: int = 50
    
    @classmethod
    def from_environment(cls) -> 'HoneypotConfig':
        """Create configuration from environment variables."""
        return cls(
            honeypot_bucket=os.environ.get('HONEYPOT_BUCKET', ''),
            log_level=os.environ.get('LOG_LEVEL', 'INFO'),
            aws_region=os.environ.get('AWS_REGION', 'us-west-2'),
            simulation_delay_min=float(os.environ.get('SIM_DELAY_MIN', '0.5')),
            simulation_delay_max=float(os.environ.get('SIM_DELAY_MAX', '2.0')),
        )


# Threat detection patterns
THREAT_PATTERNS = {
    'sql_injection': [
        r'union\s+select',
        r'drop\s+table',
        r'insert\s+into',
        r'delete\s+from'
    ],
    'xss': [
        r'<script',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*='
    ],
    'directory_traversal': [
        r'\.\./',
        r'\.\.\\',
        r'/etc/passwd',
        r'/etc/shadow'
    ],
    'command_injection': [
        r'cmd\s*=',
        r'exec\s*\(',
        r'system\s*\(',
        r'eval\s*\('
    ],
    'file_inclusion': [
        r'/etc/passwd',
        r'php://input',
        r'data://',
        r'file://'
    ],
    'obfuscation': [
        r'base64_decode',
        r'chr\s*\(',
        r'hex\s*\(',
        r'%[0-9a-f]{2}'
    ]
}

# Security tool signatures
SECURITY_TOOLS = [
    'sqlmap', 'nikto', 'nmap', 'burp', 'metasploit', 'nuclei',
    'gobuster', 'dirb', 'wfuzz', 'hydra', 'medusa', 'john'
]

# Honeypot response templates
RESPONSE_TEMPLATES = {
    'admin_panel_login': '''
        <html>
        <head>
            <title>Admin Panel Login</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .login-form {{ max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; }}
                input {{ width: 100%; padding: 10px; margin: 10px 0; }}
                .error {{ color: red; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Administrator Login</h2>
                {error_message}
                <form method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="submit" value="Login">
                </form>
                <p><small>Powered by AdminPanel v2.1.3</small></p>
            </div>
        </body>
        </html>
    ''',
    
    'api_error': '''
        {{
            "error": "{error_message}",
            "available_endpoints": {endpoints},
            "api_version": "1.2.3",
            "timestamp": "{timestamp}"
        }}
    ''',
    
    'file_upload': '''
        <html>
        <head>
            <title>File Upload Portal</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .upload-form {{ max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; }}
                input {{ margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="upload-form">
                <h2>File Upload Portal</h2>
                <form method="post" enctype="multipart/form-data">
                    <input type="file" name="file" required><br>
                    <input type="submit" value="Upload File">
                </form>
                <p><small>Accepts: .txt, .doc, .pdf, .jpg, .png</small></p>
                <p><small>Max size: 10MB</small></p>
            </div>
        </body>
        </html>
    '''
}