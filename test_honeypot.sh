#!/bin/bash

HONEYPOT_URL="https://jew1h5f5y7.execute-api.us-west-2.amazonaws.com"

echo "🍯 Testing Honeypot Endpoints..."
echo "================================"

# Test 1: Basic web request (should trigger vulnerable_webapp)
echo "1. Testing main page..."
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL" > /dev/null
echo "   ✓ Main page accessed"

# Test 2: Admin panel (should trigger admin_panel)
echo "2. Testing admin panel..."
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/admin" > /dev/null
echo "   ✓ Admin panel accessed"

# Test 3: API endpoints (should trigger api_endpoint)
echo "3. Testing API endpoints..."
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/api/users" > /dev/null
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/api/config" > /dev/null
echo "   ✓ API endpoints accessed"

# Test 4: Bot/Scanner simulation (should trigger bot_trap)
echo "4. Simulating bot/scanner traffic..."
curl -s -H "User-Agent: sqlmap/1.0" "$HONEYPOT_URL" > /dev/null
curl -s -H "User-Agent: Nikto/2.1.6" "$HONEYPOT_URL/admin" > /dev/null
curl -s -H "User-Agent: curl/7.68.0" "$HONEYPOT_URL/api/users" > /dev/null
echo "   ✓ Bot traffic simulated"

# Test 5: Upload attempts (should trigger file_upload)
echo "5. Testing file upload..."
curl -s -X POST -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/upload" > /dev/null
echo "   ✓ Upload endpoint accessed"

# Test 6: SSH simulation (should trigger ssh_simulation)
echo "6. Testing SSH simulation..."
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/ssh" > /dev/null
echo "   ✓ SSH endpoint accessed"

# Test 7: Attack patterns
echo "7. Simulating attack patterns..."
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/?id=1' UNION SELECT * FROM users--" > /dev/null
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/?cmd=ls" > /dev/null
curl -s -H "User-Agent: Mozilla/5.0" "$HONEYPOT_URL/../../../etc/passwd" > /dev/null
echo "   ✓ Attack patterns simulated"

echo ""
echo "[TARGET] Test completed! Check logs in a few minutes:"
echo "   aws logs tail /aws/lambda/honeypot --follow"
echo ""
echo "[DATA] Or run the analyzer:"
echo "   python honeypot_analyzer.py --hours 1 --visualize --export" 