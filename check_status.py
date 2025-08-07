#!/usr/bin/env python3
"""
Simple Honeypot Status Checker
"""

import boto3
import json
from datetime import datetime, timedelta


def check_honeypot_status():
    """Check honeypot deployment status"""

    # Initialize clients
    lambda_client = boto3.client("lambda")
    logs_client = boto3.client("logs")
    apigateway_client = boto3.client("apigatewayv2")

    print("[HONEYPOT] HONEYPOT STATUS CHECK")
    print("=" * 40)

    # Check Lambda function
    try:
        response = lambda_client.get_function(FunctionName="honeypot-lambda")
        print("✓ Lambda Function: ACTIVE")
        print(f"   Runtime: {response['Configuration']['Runtime']}")
        print(f"   Memory: {response['Configuration']['MemorySize']} MB")
        print(f"   Timeout: {response['Configuration']['Timeout']} seconds")
    except Exception as e:
        print(f"✗ Lambda Function: ERROR - {e}")
        return

    # Check API Gateway
    try:
        apis = apigateway_client.get_apis()
        honeypot_api = None
        for api in apis["Items"]:
            if api["Name"] == "honeypot-api":
                honeypot_api = api
                break

        if honeypot_api:
            print("✓ API Gateway: ACTIVE")
            print(f"   Endpoint: {honeypot_api['ApiEndpoint']}")
            print(f"   Protocol: {honeypot_api['ProtocolType']}")
        else:
            print("✗ API Gateway: NOT FOUND")
    except Exception as e:
        print(f"✗ API Gateway: ERROR - {e}")

    # Check CloudWatch Log Group
    try:
        response = logs_client.describe_log_groups(
            logGroupNamePrefix="/aws/lambda/honeypot"
        )

        if response["logGroups"]:
            log_group = response["logGroups"][0]
            print("✓ CloudWatch Logs: ACTIVE")
            print(f"   Log Group: {log_group['logGroupName']}")
            print(
                f"   Retention: {log_group.get('retentionInDays', 'Never expire')} days"
            )

            # Check for recent log streams
            streams = logs_client.describe_log_streams(
                logGroupName=log_group["logGroupName"],
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            )

            if streams["logStreams"]:
                last_event = streams["logStreams"][0].get("lastEventTime", 0)
                last_event_time = datetime.fromtimestamp(last_event / 1000)
                print(f"   Last Activity: {last_event_time}")

                # Get recent events
                recent_events = logs_client.filter_log_events(
                    logGroupName=log_group["logGroupName"],
                    startTime=int(
                        (datetime.now() - timedelta(hours=1)).timestamp() * 1000
                    ),
                )

                interaction_count = 0
                for event in recent_events["events"]:
                    if event["message"].startswith("{"):
                        try:
                            json.loads(event["message"])
                            interaction_count += 1
                        except:
                            pass

                print(f"   Recent Interactions (1h): {interaction_count}")
            else:
                print("   No log streams found")
        else:
            print("✗ CloudWatch Logs: NOT FOUND")
    except Exception as e:
        print(f"✗ CloudWatch Logs: ERROR - {e}")

    print("\n🔗 Test your honeypot:")
    if honeypot_api:
        print(f"   curl {honeypot_api['ApiEndpoint']}")
        print(f"   curl {honeypot_api['ApiEndpoint']}/admin")
        print(f"   curl {honeypot_api['ApiEndpoint']}/api/users")


if __name__ == "__main__":
    check_honeypot_status()
