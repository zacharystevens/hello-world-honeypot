#!/usr/bin/env python3
"""
Honeypot Log Analyzer
Analyzes CloudWatch logs and generates threat intelligence reports
"""

import boto3
import json
import pandas as pd
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import geoip2.database
import argparse

class HoneypotAnalyzer:
    def __init__(self, log_group_name="/aws/lambda/honeypot"):
        self.logs_client = boto3.client('logs')
        self.log_group_name = log_group_name
        
    def fetch_logs(self, hours_back=24):
        """Fetch honeypot logs from CloudWatch"""
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        response = self.logs_client.filter_log_events(
            logGroupName=self.log_group_name,
            startTime=int(start_time.timestamp() * 1000),
            endTime=int(end_time.timestamp() * 1000)
        )
        
        logs = []
        for event in response['events']:
            try:
                log_data = json.loads(event['message'])
                logs.append(log_data)
            except json.JSONDecodeError:
                continue
                
        return logs
    
    def analyze_attack_patterns(self, logs):
        """Analyze attack patterns from logs"""
        
        df = pd.DataFrame(logs)
        
        if df.empty:
            print("No logs found for analysis")
            return
        
        print("🔍 HONEYPOT ANALYSIS REPORT")
        print("=" * 50)
        
        # Basic statistics
        print(f"[DATA] Total Interactions: {len(df)}")
        print(f"🕒 Time Range: {df['timestamp'].min()} to {df['timestamp'].max()}")
        
        # Top attacking IPs
        print("\n[TARGET] Top Attacking IPs:")
        top_ips = df['client_ip'].value_counts().head(10)
        for ip, count in top_ips.items():
            print(f"   {ip}: {count} attempts")
        
        # Honeypot types targeted
        print("\n[HONEYPOT] Honeypot Types Targeted:")
        honeypot_stats = df['honeypot_type'].value_counts()
        for hp_type, count in honeypot_stats.items():
            print(f"   {hp_type}: {count} attempts")
        
        # User agents
        print("\n🤖 Top User Agents:")
        top_agents = df['user_agent'].value_counts().head(5)
        for agent, count in top_agents.items():
            print(f"   {agent[:80]}...: {count}")
        
        # Attack methods
        print("\n[ACTION]  HTTP Methods Used:")
        methods = df['method'].value_counts()
        for method, count in methods.items():
            print(f"   {method}: {count}")
        
        # Threat indicators
        print("\n🚨 Threat Indicators Found:")
        all_indicators = []
        for indicators in df['threat_indicators']:
            if indicators:
                all_indicators.extend(indicators)
        
        if all_indicators:
            indicator_counts = Counter(all_indicators)
            for indicator, count in indicator_counts.most_common(10):
                print(f"   {indicator}: {count} times")
        else:
            print("   No specific threat indicators detected")
        
        return df
    
    def generate_visualizations(self, df):
        """Generate visualization charts"""
        
        if df.empty:
            return
        
        # Set up the plotting style
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Honeypot Attack Analysis Dashboard', fontsize=16)
        
        # 1. Attacks over time
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp').resample('1H').size().plot(ax=axes[0,0], kind='line')
        axes[0,0].set_title('Attacks Over Time (Hourly)')
        axes[0,0].set_ylabel('Number of Attacks')
        
        # 2. Top attacking IPs
        top_ips = df['client_ip'].value_counts().head(10)
        top_ips.plot(ax=axes[0,1], kind='bar')
        axes[0,1].set_title('Top 10 Attacking IPs')
        axes[0,1].set_ylabel('Number of Attacks')
        axes[0,1].tick_params(axis='x', rotation=45)
        
        # 3. Honeypot types
        df['honeypot_type'].value_counts().plot(ax=axes[1,0], kind='pie', autopct='%1.1f%%')
        axes[1,0].set_title('Honeypot Types Targeted')
        
        # 4. HTTP methods
        df['method'].value_counts().plot(ax=axes[1,1], kind='bar')
        axes[1,1].set_title('HTTP Methods Used')
        axes[1,1].set_ylabel('Number of Requests')
        
        plt.tight_layout()
        plt.savefig('honeypot_analysis.png', dpi=300, bbox_inches='tight')
        print("\n[CHART] Visualization saved as 'honeypot_analysis.png'")
    
    def export_threat_intel(self, df, filename="threat_intel.json"):
        """Export threat intelligence data"""
        
        if df.empty:
            return
        
        threat_intel = {
            'generated_at': datetime.utcnow().isoformat(),
            'total_attacks': len(df),
            'unique_ips': df['client_ip'].nunique(),
            'top_attacking_ips': df['client_ip'].value_counts().head(20).to_dict(),
            'attack_methods': df['method'].value_counts().to_dict(),
            'targeted_honeypots': df['honeypot_type'].value_counts().to_dict(),
            'suspicious_user_agents': df['user_agent'].value_counts().head(10).to_dict()
        }
        
        with open(filename, 'w') as f:
            json.dump(threat_intel, f, indent=2)
        
        print(f"\n💾 Threat intelligence exported to '{filename}'")

def main():
    parser = argparse.ArgumentParser(description='Analyze honeypot logs')
    parser.add_argument('--hours', type=int, default=24, help='Hours of logs to analyze (default: 24)')
    parser.add_argument('--visualize', action='store_true', help='Generate visualization charts')
    parser.add_argument('--export', action='store_true', help='Export threat intelligence')
    
    args = parser.parse_args()
    
    analyzer = HoneypotAnalyzer()
    
    print(f"🔍 Fetching logs from last {args.hours} hours...")
    logs = analyzer.fetch_logs(hours_back=args.hours)
    
    if not logs:
        print("✗ No logs found. Make sure your honeypot is receiving traffic.")
        return
    
    df = analyzer.analyze_attack_patterns(logs)
    
    if args.visualize:
        analyzer.generate_visualizations(df)
    
    if args.export:
        analyzer.export_threat_intel(df)

if __name__ == "__main__":
    main() 