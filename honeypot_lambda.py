import json
import boto3
import time
import hashlib
import random
from datetime import datetime
import base64
import re

# Initialize AWS clients
cloudwatch = boto3.client('cloudwatch')
s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Multi-purpose honeypot that can simulate various vulnerable services
    """
    
    # Extract request information
    request_info = extract_request_info(event, context)
    
    # Determine honeypot type based on path or headers
    honeypot_type = determine_honeypot_type(event)
    
    # Log the interaction
    log_interaction(request_info, honeypot_type)
    
    # Generate appropriate response based on honeypot type
    response = generate_honeypot_response(honeypot_type, request_info)
    
    return response

def extract_request_info(event, context):
    """Extract comprehensive request information for analysis"""
    
    # Get client IP (handle various proxy scenarios)
    client_ip = get_client_ip(event)
    
    # Extract headers
    headers = event.get('headers', {})
    
    # Extract query parameters
    query_params = event.get('queryStringParameters') or {}
    
    # Extract body
    body = event.get('body', '')
    if event.get('isBase64Encoded', False):
        try:
            body = base64.b64decode(body).decode('utf-8')
        except:
            body = '[Base64 decode failed]'
    
    # Extract path and method
    path = event.get('rawPath', '/')
    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    
    # Generate session ID
    session_id = hashlib.md5(f"{client_ip}{time.time()}".encode()).hexdigest()[:12]
    
    return {
        'timestamp': datetime.utcnow().isoformat(),
        'session_id': session_id,
        'client_ip': client_ip,
        'method': method,
        'path': path,
        'headers': headers,
        'query_params': query_params,
        'body': body,
        'user_agent': headers.get('user-agent', 'Unknown'),
        'referer': headers.get('referer', ''),
        'request_id': context.aws_request_id
    }

def get_client_ip(event):
    """Extract real client IP handling various proxy scenarios"""
    
    # Check for CloudFront
    if 'cloudfront-viewer-address' in event.get('headers', {}):
        return event['headers']['cloudfront-viewer-address'].split(':')[0]
    
    # Check for X-Forwarded-For
    if 'x-forwarded-for' in event.get('headers', {}):
        return event['headers']['x-forwarded-for'].split(',')[0].strip()
    
    # Check for X-Real-IP
    if 'x-real-ip' in event.get('headers', {}):
        return event['headers']['x-real-ip']
    
    # Fallback to source IP
    return event.get('requestContext', {}).get('http', {}).get('sourceIp', 'Unknown')

def determine_honeypot_type(event):
    """Determine which type of honeypot to simulate based on request"""
    
    path = event.get('rawPath', '/').lower()
    headers = event.get('headers', {})
    user_agent = headers.get('user-agent', '').lower()
    
    # Admin panel honeypot
    if any(admin_path in path for admin_path in ['/admin', '/wp-admin', '/administrator', '/phpmyadmin']):
        return 'admin_panel'
    
    # API honeypot
    elif path.startswith('/api/'):
        return 'api_endpoint'
    
    # File upload honeypot
    elif 'upload' in path or event.get('requestContext', {}).get('http', {}).get('method') == 'POST':
        return 'file_upload'
    
    # Bot/scanner honeypot
    elif any(bot in user_agent for bot in ['bot', 'crawler', 'scanner', 'curl', 'wget']):
        return 'bot_trap'
    
    # SSH honeypot simulation (for web-based SSH clients)
    elif 'ssh' in path or 'terminal' in path:
        return 'ssh_simulation'
    
    # Default: fake vulnerable web app
    else:
        return 'vulnerable_webapp'

def generate_honeypot_response(honeypot_type, request_info):
    """Generate appropriate response based on honeypot type"""
    
    if honeypot_type == 'admin_panel':
        return generate_admin_panel_response(request_info)
    elif honeypot_type == 'api_endpoint':
        return generate_api_response(request_info)
    elif honeypot_type == 'file_upload':
        return generate_upload_response(request_info)
    elif honeypot_type == 'bot_trap':
        return generate_bot_trap_response(request_info)
    elif honeypot_type == 'ssh_simulation':
        return generate_ssh_response(request_info)
    else:
        return generate_vulnerable_webapp_response(request_info)

def generate_admin_panel_response(request_info):
    """Simulate a vulnerable admin login panel"""
    
    if request_info['method'] == 'POST':
        # Simulate login attempt processing
        time.sleep(random.uniform(0.5, 2.0))  # Realistic delay
        
        # Always return "invalid credentials" but log the attempt
        return {
            'statusCode': 401,
            'headers': {
                'Content-Type': 'text/html',
                'Set-Cookie': f'session_id={request_info["session_id"]}; HttpOnly'
            },
            'body': '''
            <html>
            <head><title>Admin Login - Access Denied</title></head>
            <body>
                <h2>Login Failed</h2>
                <p>Invalid username or password. Please try again.</p>
                <form method="post">
                    <input type="text" name="username" placeholder="Username" required><br><br>
                    <input type="password" name="password" placeholder="Password" required><br><br>
                    <input type="submit" value="Login">
                </form>
                <p><small>Powered by AdminPanel v2.1.3</small></p>
            </body>
            </html>
            '''
        }
    
    # GET request - show login form
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': '''
        <html>
        <head><title>Admin Panel Login</title></head>
        <body>
            <h2>Administrator Login</h2>
            <form method="post">
                <input type="text" name="username" placeholder="Username" required><br><br>
                <input type="password" name="password" placeholder="Password" required><br><br>
                <input type="submit" value="Login">
            </form>
            <p><small>Powered by AdminPanel v2.1.3</small></p>
        </body>
        </html>
        '''
    }

def generate_api_response(request_info):
    """Simulate a vulnerable API endpoint"""
    
    # Simulate various API vulnerabilities
    path = request_info['path']
    
    if 'users' in path:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'users': [
                    {'id': 1, 'username': 'admin', 'email': 'admin@company.com'},
                    {'id': 2, 'username': 'user1', 'email': 'user1@company.com'},
                    {'id': 3, 'username': 'test', 'email': 'test@company.com'}
                ],
                'total': 3,
                'api_version': '1.2.3'
            })
        }
    
    elif 'config' in path:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'database_host': 'db.internal.company.com',
                'debug_mode': True,
                'api_keys': ['key_123456', 'key_789012'],
                'version': '1.2.3'
            })
        }
    
    else:
        return {
            'statusCode': 404,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Endpoint not found', 'available_endpoints': ['/api/users', '/api/config']})
        }

def generate_upload_response(request_info):
    """Simulate a file upload vulnerability"""
    
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': '''
        <html>
        <head><title>File Upload</title></head>
        <body>
            <h2>File Upload Portal</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" required><br><br>
                <input type="submit" value="Upload File">
            </form>
            <p><small>Accepts: .txt, .doc, .pdf, .jpg, .png</small></p>
            <p><small>Max size: 10MB</small></p>
        </body>
        </html>
        '''
    }

def generate_bot_trap_response(request_info):
    """Generate response designed to trap bots and scanners"""
    
    # Include hidden links and forms that only bots would interact with
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': '''
        <html>
        <head><title>Welcome</title></head>
        <body>
            <h1>Welcome to Our Site</h1>
            <p>Please browse our content.</p>
            
            <!-- Hidden bot traps -->
            <div style="display:none;">
                <a href="/admin/secret">Admin Access</a>
                <a href="/backup.sql">Database Backup</a>
                <a href="/.env">Environment File</a>
            </div>
            
            <!-- Honeypot form -->
            <form style="position:absolute;left:-9999px;">
                <input type="text" name="email" placeholder="Email">
                <input type="submit" value="Subscribe">
            </form>
        </body>
        </html>
        '''
    }

def generate_ssh_response(request_info):
    """Simulate SSH-like terminal interface"""
    
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': '''
        <html>
        <head><title>SSH Terminal</title></head>
        <body style="background-color: black; color: green; font-family: monospace;">
            <pre>
Ubuntu 20.04.3 LTS server01 tty1

server01 login: <span id="cursor">_</span>

Last login: Mon Jan 15 10:30:22 2024 from 192.168.1.100
            </pre>
            <script>
                // Simulate blinking cursor
                setInterval(function() {
                    var cursor = document.getElementById('cursor');
                    cursor.style.visibility = cursor.style.visibility === 'hidden' ? 'visible' : 'hidden';
                }, 500);
            </script>
        </body>
        </html>
        '''
    }

def generate_vulnerable_webapp_response(request_info):
    """Generate response for a fake vulnerable web application"""
    
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': '''
        <html>
        <head><title>Corporate Portal</title></head>
        <body>
            <h1>Corporate Intranet Portal</h1>
            <nav>
                <a href="/admin">Admin Panel</a> |
                <a href="/api/users">User API</a> |
                <a href="/upload">File Upload</a> |
                <a href="/backup">Backups</a>
            </nav>
            <p>Welcome to our internal corporate portal.</p>
            <p><small>Version 2.1.3 | Last updated: 2023-12-15</small></p>
            
            <!-- Intentionally vulnerable comment -->
            <!-- TODO: Remove debug info - DB: mysql://admin:password123@db.internal:3306/corporate -->
        </body>
        </html>
        '''
    }

def log_interaction(request_info, honeypot_type):
    """Log interaction to CloudWatch and S3 for analysis"""
    
    # Create detailed log entry
    log_entry = {
        **request_info,
        'honeypot_type': honeypot_type,
        'threat_indicators': analyze_threat_indicators(request_info)
    }
    
    # Send to CloudWatch Logs
    print(json.dumps(log_entry))  # This goes to CloudWatch Logs automatically
    
    # Send custom metrics to CloudWatch
    try:
        cloudwatch.put_metric_data(
            Namespace='Honeypot/Interactions',
            MetricData=[
                {
                    'MetricName': 'TotalInteractions',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'HoneypotType', 'Value': honeypot_type},
                        {'Name': 'ClientIP', 'Value': request_info['client_ip']}
                    ]
                }
            ]
        )
    except Exception as e:
        print(f"CloudWatch metric error: {e}")

def analyze_threat_indicators(request_info):
    """Analyze request for threat indicators"""
    
    indicators = []
    
    # Check for common attack patterns
    suspicious_patterns = [
        r'union\s+select',  # SQL injection
        r'<script',         # XSS
        r'\.\./',          # Directory traversal
        r'cmd=',           # Command injection
        r'eval\(',         # Code injection
        r'/etc/passwd',    # File inclusion
        r'base64_decode',  # Obfuscation
    ]
    
    full_request = f"{request_info['path']} {request_info['body']} {str(request_info['query_params'])}"
    
    for pattern in suspicious_patterns:
        if re.search(pattern, full_request, re.IGNORECASE):
            indicators.append(f"Suspicious pattern: {pattern}")
    
    # Check user agent
    user_agent = request_info['user_agent'].lower()
    if any(tool in user_agent for tool in ['sqlmap', 'nikto', 'nmap', 'burp', 'metasploit']):
        indicators.append(f"Security tool detected: {user_agent}")
    
    # Check for automated behavior
    if 'bot' in user_agent or 'crawler' in user_agent:
        indicators.append("Automated tool detected")
    
    return indicators 