"""
Response generation for different honeypot types.

This module generates appropriate responses for each honeypot type,
following the Factory Pattern and Strategy Pattern for maintainable code.
"""

import json
import random
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any

from .models import RequestInfo, HoneypotResponse, HoneypotType
from .config import HoneypotConfig, RESPONSE_TEMPLATES


class HoneypotResponseGenerator(ABC):
    """
    Abstract base class for honeypot response generators.
    
    This design follows the Strategy Pattern, allowing different
    response generation strategies for each honeypot type.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize with honeypot configuration."""
        self.config = config
    
    @abstractmethod
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """
        Generate an appropriate response for this honeypot type.
        
        Args:
            request_info: Information about the incoming request
            
        Returns:
            HoneypotResponse: Structured response to send to the client
        """
        pass
    
    def _add_realistic_delay(self) -> None:
        """Add a realistic processing delay to make the honeypot more convincing."""
        delay = random.uniform(
            self.config.simulation_delay_min,
            self.config.simulation_delay_max
        )
        time.sleep(delay)


class AdminPanelResponseGenerator(HoneypotResponseGenerator):
    """Generates responses for admin panel honeypot."""
    
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate admin panel login response."""
        if request_info.method == 'POST':
            return self._generate_login_failure_response(request_info)
        else:
            return self._generate_login_form_response()
    
    def _generate_login_failure_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate a realistic login failure response."""
        # Add realistic delay for authentication processing
        self._add_realistic_delay()
        
        error_message = '<div class="error">Invalid username or password. Please try again.</div>'
        body = RESPONSE_TEMPLATES['admin_panel_login'].format(
            error_message=error_message
        )
        
        headers = {
            'Set-Cookie': f'session_id={request_info.session_id}; HttpOnly; Secure',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        }
        
        return HoneypotResponse(
            status_code=401,
            headers=headers,
            body=body,
            content_type='text/html'
        )
    
    def _generate_login_form_response(self) -> HoneypotResponse:
        """Generate the initial login form."""
        body = RESPONSE_TEMPLATES['admin_panel_login'].format(error_message='')
        
        return HoneypotResponse(
            status_code=200,
            headers={'Cache-Control': 'no-cache'},
            body=body,
            content_type='text/html'
        )


class ApiEndpointResponseGenerator(HoneypotResponseGenerator):
    """Generates responses for API endpoint honeypot."""
    
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate API endpoint response based on the path."""
        path = request_info.path.lower()
        
        if 'users' in path:
            return self._generate_users_response()
        elif 'config' in path:
            return self._generate_config_response()
        else:
            return self._generate_api_error_response(path)
    
    def _generate_users_response(self) -> HoneypotResponse:
        """Generate fake user data response."""
        fake_users = {
            "users": [
                {"id": 1, "username": "admin", "email": "admin@company.com", "role": "administrator"},
                {"id": 2, "username": "user1", "email": "user1@company.com", "role": "user"},
                {"id": 3, "username": "test", "email": "test@company.com", "role": "tester"},
                {"id": 4, "username": "developer", "email": "dev@company.com", "role": "developer"}
            ],
            "total": 4,
            "api_version": "1.2.3",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return HoneypotResponse(
            status_code=200,
            headers={'X-API-Version': '1.2.3'},
            body=json.dumps(fake_users, indent=2),
            content_type='application/json'
        )
    
    def _generate_config_response(self) -> HoneypotResponse:
        """Generate fake configuration data response."""
        fake_config = {
            "database": {
                "host": "db.internal.company.com",
                "port": 5432,
                "name": "production_db",
                "ssl": True
            },
            "cache": {
                "redis_host": "cache.internal.company.com",
                "ttl": 3600
            },
            "features": {
                "debug_mode": False,
                "maintenance_mode": False,
                "new_user_registration": True
            },
            "api_keys": {
                "stripe": "sk_live_51ABC123...",
                "sendgrid": "SG.ABC123...",
                "aws": "AKIA..."
            },
            "version": "1.2.3",
            "last_updated": datetime.utcnow().isoformat()
        }
        
        return HoneypotResponse(
            status_code=200,
            headers={'X-API-Version': '1.2.3'},
            body=json.dumps(fake_config, indent=2),
            content_type='application/json'
        )
    
    def _generate_api_error_response(self, path: str) -> HoneypotResponse:
        """Generate API error response for unknown endpoints."""
        available_endpoints = ["/api/users", "/api/config", "/api/status", "/api/health"]
        
        error_response = {
            "error": "Endpoint not found",
            "message": f"The requested endpoint '{path}' does not exist",
            "available_endpoints": available_endpoints,
            "api_version": "1.2.3",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return HoneypotResponse(
            status_code=404,
            headers={'X-API-Version': '1.2.3'},
            body=json.dumps(error_response, indent=2),
            content_type='application/json'
        )


class FileUploadResponseGenerator(HoneypotResponseGenerator):
    """Generates responses for file upload honeypot."""
    
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate file upload response."""
        if request_info.method == 'POST':
            return self._generate_upload_result_response()
        else:
            return self._generate_upload_form_response()
    
    def _generate_upload_form_response(self) -> HoneypotResponse:
        """Generate file upload form."""
        body = RESPONSE_TEMPLATES['file_upload']
        
        return HoneypotResponse(
            status_code=200,
            headers={'Cache-Control': 'no-cache'},
            body=body,
            content_type='text/html'
        )
    
    def _generate_upload_result_response(self) -> HoneypotResponse:
        """Generate fake upload success response."""
        # Simulate upload processing time
        self._add_realistic_delay()
        
        success_html = '''
        <html>
        <head><title>Upload Success</title></head>
        <body>
            <h2>File Upload Successful</h2>
            <p>Your file has been uploaded successfully.</p>
            <p>File ID: {file_id}</p>
            <p>Upload Time: {timestamp}</p>
            <a href="/upload">Upload Another File</a>
        </body>
        </html>
        '''.format(
            file_id=f"file_{random.randint(100000, 999999)}",
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        return HoneypotResponse(
            status_code=200,
            headers={},
            body=success_html,
            content_type='text/html'
        )


class BotTrapResponseGenerator(HoneypotResponseGenerator):
    """Generates responses for bot trap honeypot."""
    
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate bot trap response with hidden links and forms."""
        bot_trap_html = '''
        <html>
        <head>
            <title>Welcome to Our Site</title>
            <meta name="robots" content="noindex, nofollow">
        </head>
        <body>
            <h1>Welcome to Our Website</h1>
            <p>Please browse our content responsibly.</p>
            
            <!-- Visible content for legitimate users -->
            <nav>
                <a href="/about">About Us</a> |
                <a href="/contact">Contact</a> |
                <a href="/services">Services</a>
            </nav>
            
            <div class="content">
                <p>This is a legitimate website with normal content.</p>
                <p>Please use our navigation menu to explore our site.</p>
            </div>
            
            <!-- Hidden bot traps (invisible to human users) -->
            <div style="display:none;">
                <a href="/admin/secret">Secret Admin Panel</a>
                <a href="/backup.sql">Database Backup</a>
                <a href="/.env">Environment Configuration</a>
                <a href="/wp-config.php">WordPress Config</a>
                <a href="/config.ini">System Configuration</a>
            </div>
            
            <!-- Honeypot form (positioned off-screen) -->
            <form style="position:absolute;left:-9999px;" action="/newsletter" method="post">
                <input type="email" name="email" placeholder="Email Address">
                <input type="text" name="name" placeholder="Full Name">
                <input type="submit" value="Subscribe">
            </form>
            
            <!-- Additional bot traps -->
            <div style="visibility:hidden;height:0;overflow:hidden;">
                <a href="/robots.txt">Robots File</a>
                <a href="/sitemap.xml">Site Map</a>
                <a href="/admin.php">Admin Interface</a>
            </div>
        </body>
        </html>
        '''
        
        return HoneypotResponse(
            status_code=200,
            headers={
                'X-Robots-Tag': 'noindex, nofollow',
                'Cache-Control': 'no-cache'
            },
            body=bot_trap_html,
            content_type='text/html'
        )


class SshSimulationResponseGenerator(HoneypotResponseGenerator):
    """Generates responses for SSH simulation honeypot."""
    
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate SSH terminal simulation."""
        ssh_html = '''
        <html>
        <head>
            <title>SSH Terminal Access</title>
            <style>
                body {
                    background-color: #000;
                    color: #00ff00;
                    font-family: 'Courier New', monospace;
                    margin: 0;
                    padding: 20px;
                }
                .terminal {
                    white-space: pre-wrap;
                    font-size: 14px;
                }
                #cursor {
                    background-color: #00ff00;
                    color: #000;
                    animation: blink 1s infinite;
                }
                @keyframes blink {
                    0%, 50% { opacity: 1; }
                    51%, 100% { opacity: 0; }
                }
            </style>
        </head>
        <body>
            <div class="terminal">
Ubuntu 20.04.3 LTS server01 tty1

server01 login: <span id="cursor">_</span>

Last login: {last_login}
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

System information as of {current_time}:

  System load:  0.08              Processes:           123
  Usage of /:   45.2% of 9.78GB   Users logged in:     0
  Memory usage: 18%               IPv4 address for eth0: 192.168.1.100
  Swap usage:   0%

0 updates can be applied immediately.

$<span id="cursor2"> </span>
            </div>
            
            <script>
                // Simulate blinking cursors
                function blinkCursor(id) {
                    const cursor = document.getElementById(id);
                    if (cursor) {
                        setInterval(() => {
                            cursor.style.visibility = 
                                cursor.style.visibility === 'hidden' ? 'visible' : 'hidden';
                        }, 500);
                    }
                }
                
                blinkCursor('cursor');
                blinkCursor('cursor2');
            </script>
        </body>
        </html>
        '''.format(
            last_login=datetime.utcnow().strftime("Mon %b %d %H:%M:%S %Y from 192.168.1.50"),
            current_time=datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
        )
        
        return HoneypotResponse(
            status_code=200,
            headers={'Cache-Control': 'no-cache'},
            body=ssh_html,
            content_type='text/html'
        )


class VulnerableWebappResponseGenerator(HoneypotResponseGenerator):
    """Generates responses for vulnerable web application honeypot."""
    
    def generate_response(self, request_info: RequestInfo) -> HoneypotResponse:
        """Generate vulnerable web application response."""
        webapp_html = '''
        <html>
        <head>
            <title>Corporate Intranet Portal</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                nav { margin: 20px 0; padding: 10px; background: #f0f0f0; }
                nav a { margin-right: 15px; text-decoration: none; color: #333; }
                nav a:hover { color: #0066cc; }
                .footer { margin-top: 50px; font-size: 12px; color: #666; }
            </style>
        </head>
        <body>
            <h1>Corporate Intranet Portal</h1>
            
            <nav>
                <a href="/admin">Admin Panel</a> |
                <a href="/api/users">User Management API</a> |
                <a href="/upload">File Upload</a> |
                <a href="/backup">System Backups</a> |
                <a href="/config">Configuration</a>
            </nav>
            
            <div class="content">
                <h2>Welcome to the Internal Portal</h2>
                <p>This portal provides access to internal company resources and tools.</p>
                <p>Please use the navigation menu above to access different sections.</p>
                
                <h3>Quick Links</h3>
                <ul>
                    <li><a href="/reports">Monthly Reports</a></li>
                    <li><a href="/documents">Shared Documents</a></li>
                    <li><a href="/helpdesk">IT Support</a></li>
                    <li><a href="/directory">Employee Directory</a></li>
                </ul>
            </div>
            
            <div class="footer">
                <p>Version 2.1.3 | Last updated: 2023-12-15 | 
                   <a href="/debug">Debug Info</a></p>
                <!-- TODO: Remove debug info before production -->
                <!-- Database: mysql://admin:password123@db.internal:3306/corporate_db -->
                <!-- Cache: redis://cache.internal:6379/0 -->
            </div>
        </body>
        </html>
        '''
        
        return HoneypotResponse(
            status_code=200,
            headers={},
            body=webapp_html,
            content_type='text/html'
        )


class ResponseGeneratorFactory:
    """
    Factory class for creating appropriate response generators.
    
    This implements the Factory Pattern, centralizing the creation
    of response generators and making the system easily extensible.
    """
    
    def __init__(self, config: HoneypotConfig):
        """Initialize the factory with configuration."""
        self.config = config
        self._generators = {
            HoneypotType.ADMIN_PANEL: AdminPanelResponseGenerator(config),
            HoneypotType.API_ENDPOINT: ApiEndpointResponseGenerator(config),
            HoneypotType.FILE_UPLOAD: FileUploadResponseGenerator(config),
            HoneypotType.BOT_TRAP: BotTrapResponseGenerator(config),
            HoneypotType.SSH_SIMULATION: SshSimulationResponseGenerator(config),
            HoneypotType.VULNERABLE_WEBAPP: VulnerableWebappResponseGenerator(config)
        }
    
    def get_generator(self, honeypot_type: HoneypotType) -> HoneypotResponseGenerator:
        """
        Get the appropriate response generator for a honeypot type.
        
        Args:
            honeypot_type: Type of honeypot to generate responses for
            
        Returns:
            HoneypotResponseGenerator: Appropriate response generator
            
        Raises:
            ValueError: If honeypot type is not supported
        """
        if honeypot_type not in self._generators:
            raise ValueError(f"Unsupported honeypot type: {honeypot_type}")
        
        return self._generators[honeypot_type]
    
    def generate_response(self, honeypot_type: HoneypotType, 
                         request_info: RequestInfo) -> HoneypotResponse:
        """
        Generate an appropriate response for the given honeypot type and request.
        
        Args:
            honeypot_type: Type of honeypot to simulate
            request_info: Information about the incoming request
            
        Returns:
            HoneypotResponse: Generated response
        """
        generator = self.get_generator(honeypot_type)
        return generator.generate_response(request_info)