# 📡 API Documentation

## Honeypot API Reference

The honeypot system exposes multiple endpoints designed to simulate vulnerable services and attract malicious actors.

## Base URLs

- **Honeypot API**: `https://{api-id}.execute-api.us-west-2.amazonaws.com`
- **Hello World API**: `https://{api-id}.execute-api.us-west-2.amazonaws.com`

*Replace `{api-id}` with your actual API Gateway deployment ID from `terraform output`*

## Authentication

**🍯 Honeypot Note**: These endpoints are intentionally designed to appear vulnerable. No real authentication is required or processed.

## Endpoints

### Admin Panel Simulation

#### `GET /admin`
Simulates a vulnerable admin login panel.

**Response Example:**
```html
<html>
<head><title>Admin Panel Login</title></head>
<body>
    <h2>Administrator Login</h2>
    <form method="post">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="submit" value="Login">
    </form>
</body>
</html>
```

#### `POST /admin`
Processes login attempts (always fails, logs attempt).

**Request Example:**
```bash
curl -X POST https://honeypot-url.com/admin \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=secret123"
```

**Response:**
- **Status**: `401 Unauthorized`
- **Body**: HTML login form with error message
- **Headers**: `Set-Cookie: session_id={generated}; HttpOnly`

### API Endpoints Simulation

#### `GET /api/users`
Simulates a vulnerable user management API.

**Response Example:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@company.com",
      "role": "administrator"
    },
    {
      "id": 2,
      "username": "user1", 
      "email": "user1@company.com",
      "role": "user"
    }
  ],
  "total": 2,
  "api_version": "1.2.3"
}
```

#### `GET /api/config`
Simulates exposed configuration endpoint.

**Response Example:**
```json
{
  "database_host": "db.internal.company.com",
  "debug_mode": true,
  "api_keys": ["key_123456", "key_789012"],
  "version": "1.2.3"
}
```

### File Upload Simulation

#### `GET /upload`
Displays file upload interface.

**Response Example:**
```html
<html>
<head><title>File Upload Portal</title></head>
<body>
    <h2>File Upload Portal</h2>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="Upload File">
    </form>
    <p><small>Accepts: .txt, .doc, .pdf, .jpg, .png</small></p>
</body>
</html>
```

#### `POST /upload`
Simulates file upload processing.

### SSH Terminal Simulation

#### `GET /ssh` or `GET /terminal`
Simulates SSH terminal interface.

**Response Example:**
```html
<html>
<head><title>SSH Terminal</title></head>
<body style="background-color: black; color: green; font-family: monospace;">
    <pre>
Ubuntu 20.04.3 LTS server01 tty1

server01 login: <span id="cursor">_</span>

Last login: Mon Jan 15 10:30:22 2024 from 192.168.1.100
    </pre>
</body>
</html>
```

### Vulnerable Web Application

#### `GET /` (Default)
Simulates corporate intranet portal.

**Response Example:**
```html
<html>
<head><title>Corporate Intranet Portal</title></head>
<body>
    <h1>Corporate Intranet Portal</h1>
    <nav>
        <a href="/admin">Admin Panel</a> |
        <a href="/api/users">User Management API</a> |
        <a href="/upload">File Upload</a> |
        <a href="/backup">System Backups</a>
    </nav>
    <p>Welcome to our internal corporate portal.</p>
    <!-- TODO: Remove debug info - DB: mysql://admin:password123@db.internal:3306 -->
</body>
</html>
```

## Request/Response Logging

All requests are automatically logged with comprehensive details:

### Logged Information
- **Timestamp**: ISO 8601 format
- **Client IP**: Real IP (handles X-Forwarded-For)
- **HTTP Method**: GET, POST, PUT, DELETE, etc.
- **Path**: Full request path
- **Headers**: All HTTP headers
- **Query Parameters**: Parsed query string
- **Body**: Request body content
- **User Agent**: Client identification
- **Session ID**: Generated unique identifier

### Threat Analysis
Each request is analyzed for:
- **SQL Injection** patterns
- **XSS** attempts
- **Directory Traversal** attacks
- **Command Injection** patterns
- **Security Tools** (sqlmap, nikto, nmap, etc.)
- **Automated Bots** and crawlers

### Response Format (Internal Logging)
```json
{
  "timestamp": "2024-01-15T10:30:22.123456",
  "session_id": "abc123def456",
  "client_ip": "203.0.113.1",
  "method": "POST",
  "path": "/admin",
  "headers": {...},
  "query_params": {...},
  "body": "username=admin&password=' OR 1=1--",
  "user_agent": "sqlmap/1.5.2",
  "honeypot_type": "admin_panel",
  "threat_indicators": [
    {
      "pattern": "' OR ",
      "category": "sql_injection", 
      "severity": "high",
      "location": "body"
    },
    {
      "pattern": "sqlmap",
      "category": "security_tool",
      "severity": "medium", 
      "location": "user_agent"
    }
  ],
  "threat_count": 2,
  "max_threat_level": "high",
  "processing_time_ms": 150.5
}
```

## Error Responses

### Standard Error Format
```json
{
  "error": "Error description",
  "status_code": 400,
  "timestamp": "2024-01-15T10:30:22Z"
}
```

### Common HTTP Status Codes
- **200 OK**: Successful honeypot response
- **401 Unauthorized**: Login attempts (admin panel)
- **404 Not Found**: Unknown endpoints
- **500 Internal Server Error**: System errors

## Rate Limiting

No rate limiting is implemented by design - the honeypot should capture all attack attempts.

## Security Considerations

⚠️ **Important**: These endpoints are designed to appear vulnerable for security research and threat intelligence gathering. They should **never** be deployed in production environments with real data.

### Safe Deployment Practices
1. Deploy in isolated AWS accounts
2. Use dedicated VPCs with restricted access
3. Monitor all logs and alerts
4. Implement proper cleanup procedures

## Testing the API

### Basic Functionality Test
```bash
# Test main endpoints
curl -s https://your-honeypot-url.com/
curl -s https://your-honeypot-url.com/admin
curl -s https://your-honeypot-url.com/api/users

# Test threat detection
curl -s "https://your-honeypot-url.com/admin?id=1' UNION SELECT * FROM users--"
curl -s -H "User-Agent: sqlmap/1.5.2" https://your-honeypot-url.com/
```

### Security Testing
```bash
# XSS test
curl -X POST https://your-honeypot-url.com/ \
  -d "comment=<script>alert('xss')</script>"

# SQL injection test
curl "https://your-honeypot-url.com/api/users?id=1' OR '1'='1"

# Directory traversal test  
curl "https://your-honeypot-url.com/files?path=../../../etc/passwd"
```

## Monitoring API Usage

### CloudWatch Logs
```bash
# View real-time logs
aws logs tail /aws/lambda/honeypot --follow

# Filter by threat level
aws logs filter-log-events \
  --log-group-name /aws/lambda/honeypot \
  --filter-pattern "high"
```

### Custom Metrics
- **TotalInteractions**: Count of all requests
- **ThreatDetections**: Count of malicious requests  
- **ProcessingDuration**: Response time metrics

---

**API Status**: ✅ Fully Operational  
**Threat Detection**: ✅ Active  
**Logging**: ✅ Comprehensive