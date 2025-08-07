#!/usr/bin/env python3
"""
Real-time Honeypot Monitor
Displays live honeypot interactions and threat analysis
"""

import boto3
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import sys

class HoneypotMonitor:
    def __init__(self):
        self.logs_client = boto3.client('logs')
        self.log_group_name = "/aws/lambda/honeypot"
        self.last_check = datetime.utcnow() - timedelta(minutes=5)
        
    def get_recent_logs(self):
        """Get logs since last check"""
        try:
            response = self.logs_client.filter_log_events(
                logGroupName=self.log_group_name,
                startTime=int(self.last_check.timestamp() * 1000),
                endTime=int(datetime.utcnow().timestamp() * 1000)
            )
            
            logs = []
            for event in response['events']:
                try:
                    # Skip non-JSON log entries (like START/END/REPORT)
                    if event['message'].startswith('{'):
                        log_data = json.loads(event['message'])
                        logs.append(log_data)
                except json.JSONDecodeError:
                    continue
                    
            self.last_check = datetime.utcnow()
            return logs
            
        except Exception as e:
            print(f"Error fetching logs: {e}")
            return []
    
    def display_interaction(self, log_entry):
        """Display a single interaction"""
        timestamp = log_entry.get('timestamp', 'Unknown')
        client_ip = log_entry.get('client_ip', 'Unknown')
        method = log_entry.get('method', 'GET')
        path = log_entry.get('path', '/')
        honeypot_type = log_entry.get('honeypot_type', 'unknown')
        user_agent = log_entry.get('user_agent', 'Unknown')[:50]
        threat_indicators = log_entry.get('threat_indicators', [])
        
        # Color coding based on threat level
        if threat_indicators:
            color = '\033[91m'  # Red for threats
            threat_level = "🚨 HIGH"
        elif 'bot' in honeypot_type or 'scanner' in user_agent.lower():
            color = '\033[93m'  # Yellow for bots
            threat_level = "⚠  MED"
        else:
            color = '\033[92m'  # Green for normal
            threat_level = "ℹ  LOW"
        
        reset_color = '\033[0m'
        
        print(f"{color}[{timestamp[:19]}] {threat_level} {client_ip:15} {method:4} {path:20} ({honeypot_type}){reset_color}")
        
        if threat_indicators:
            for indicator in threat_indicators:
                print(f"    🔍 {indicator}")
        
        if len(user_agent) > 10:
            print(f"    🤖 {user_agent}...")
    
    def display_summary(self, logs):
        """Display summary statistics"""
        if not logs:
            return
            
        print(f"\n[DATA] SUMMARY (Last {len(logs)} interactions)")
        print("=" * 50)
        
        # Count by IP
        ips = Counter(log['client_ip'] for log in logs)
        print("[TARGET] Top IPs:")
        for ip, count in ips.most_common(5):
            print(f"   {ip}: {count}")
        
        # Count by honeypot type
        types = Counter(log['honeypot_type'] for log in logs)
        print("\n[HONEYPOT] Honeypot Types:")
        for hp_type, count in types.items():
            print(f"   {hp_type}: {count}")
        
        # Count threats
        all_threats = []
        for log in logs:
            all_threats.extend(log.get('threat_indicators', []))
        
        if all_threats:
            print("\n🚨 Threat Indicators:")
            threat_counts = Counter(all_threats)
            for threat, count in threat_counts.most_common(3):
                print(f"   {threat}: {count}")
    
    def run_monitor(self, interval=30):
        """Run continuous monitoring"""
        print("[HONEYPOT] Honeypot Monitor Started")
        print("=" * 50)
        print("Monitoring for new interactions...")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                logs = self.get_recent_logs()
                
                if logs:
                    print(f"\n🔔 {len(logs)} new interaction(s) detected:")
                    print("-" * 50)
                    
                    for log_entry in logs:
                        self.display_interaction(log_entry)
                    
                    self.display_summary(logs)
                    print("\n" + "="*50)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n👋 Monitoring stopped.")
            sys.exit(0)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitor honeypot in real-time')
    parser.add_argument('--interval', type=int, default=30, help='Check interval in seconds (default: 30)')
    parser.add_argument('--once', action='store_true', help='Check once and exit')
    
    args = parser.parse_args()
    
    monitor = HoneypotMonitor()
    
    if args.once:
        logs = monitor.get_recent_logs()
        if logs:
            for log_entry in logs:
                monitor.display_interaction(log_entry)
            monitor.display_summary(logs)
        else:
            print("No recent interactions found.")
    else:
        monitor.run_monitor(interval=args.interval)

if __name__ == "__main__":
    main() 