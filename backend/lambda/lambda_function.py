import os
import re
import json
import uuid
import boto3
import logging
from datetime import datetime, timezone
from typing import List

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Environment variables
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:610251783037:PhishGuardAlerts')
TABLE_NAME = os.getenv('PHISHSCAN_TABLE_NAME', 'PhishScans')

table = dynamodb.Table(TABLE_NAME)

# --- Core Functions ---

def is_phishing_url(url: str) -> bool:
    """Simple phishing detection using keyword indicators."""
    phishing_indicators = [
        "login", "secure", "account", "verify", 
        "password", "banking", "paypal", "amazon",
        "update", "security", "confirm", "click"
    ]
    url_lower = url.lower()
    return any(indicator in url_lower for indicator in phishing_indicators)


def extract_urls_from_email(email_text: str) -> List[str]:
    """Extract URLs from email text."""
    if not email_text:
        return []

    url_pattern = re.compile(
        r'(?:(?:https?|ftp|file)://|www\.)'
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)'
        r'(?::\d+)?'
        r'(?:/[^\s]*)?',
        re.IGNORECASE
    )
    matches = re.finditer(url_pattern, email_text)
    urls = []
    for match in matches:
        url = match.group()
        urls.append('http://' + url if url.lower().startswith('www.') else url)
    return urls


def build_scan_result(url, is_phishing):
    """Create a structured scan result dictionary."""
    color = "red" if is_phishing else "green"
    reason = "URL flagged as phishing." if is_phishing else "No phishing indicators found."

    return {
        "ScanID": str(uuid.uuid4()),
        "URL": url,
        "RiskLevel": "HIGH" if is_phishing else "LOW",
        "WarningColor": color,  # 🔴🟢 Added color flag
        "Timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "Details": {
            "is_phishing": is_phishing,
            "reason": reason,
        }
    }


def save_to_dynamodb(item):
    """Save a scan result to DynamoDB."""
    try:
        table.put_item(Item=item)
        logger.info(f"Saved to DynamoDB: {item['ScanID']}")
    except Exception as e:
        logger.error(f"Error saving to DynamoDB: {e}")
        raise


def send_sns_alert(high_risk_results):
    """Send SNS alert for high-risk phishing URLs."""
    url_list = "\n".join(f"🔗 {r['URL']}" for r in high_risk_results)
    message = {
        "default": f"⚠️ {len(high_risk_results)} high-risk URLs detected!",
        "sms": f"⚠️ {len(high_risk_results)} phishing URLs found.",
        "email": f"""
🚨 High-risk phishing URLs detected:
{url_list}

🛡️ PhishGuard AI Security System 🛡️
"""
    }
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=json.dumps(message),
            MessageStructure='json',
            Subject="⚠️ PhishGuard Alert ⚠️"
        )
    except Exception as e:
        logger.error(f"Error sending SNS alert: {e}")
        raise


def subscribe_email_to_sns(email):
    """Subscribe a user's email to the SNS topic."""
    try:
        response = sns.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol='email',
            Endpoint=email
        )
        logger.info(f"Subscription initiated for {email}")
        return {"message": f"Subscription initiated for {email}. Check your inbox to confirm."}
    except Exception as e:
        logger.error(f"Error subscribing email: {e}")
        raise


# --- Lambda Handler ---

def lambda_handler(event, context):
    """Main Lambda entry point."""
    logger.info(f"Event received: {json.dumps(event)}")

    # Handle Cognito trigger
    if event.get('triggerSource') == "PostConfirmation_ConfirmSignUp":
        email = event['request']['userAttributes'].get('email', '')
        subscribe_email_to_sns(email)
        return event

    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    }

    try:
        path = event.get('path', '')
        http_method = event.get('httpMethod', '')
        body = json.loads(event.get('body', '{}'))

        # --- URL Scanning Endpoint ---
        if path == '/scan/urls' and http_method == 'POST':
            urls = body.get('urls', [])
            if not urls:
                return {
                    'statusCode': 400,
                    'headers': headers,
                    'body': json.dumps({"message": "No URLs provided."})
                }

            results = []
            high_risk = []

            for url in urls:
                is_phish = is_phishing_url(url)
                result = build_scan_result(url, is_phish)
                save_to_dynamodb(result)
                results.append(result)
                if is_phish:
                    high_risk.append(result)

            if high_risk:
                send_sns_alert(high_risk)

            return {
                'statusCode': 200,
                'headers': headers,
                'body': json.dumps(results)
            }

        # --- Default fallback ---
        return {
            'statusCode': 404,
            'headers': headers,
            'body': json.dumps({"message": "Invalid endpoint"})
        }

    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'headers': headers,
            'body': json.dumps({"message": "Invalid JSON"})
        }
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message": f"Internal server error: {str(e)}"})
        }
