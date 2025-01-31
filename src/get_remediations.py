import boto3
import json
import os

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']

# Fetch environment variables
parent_origin = os.environ.get('PARENT_ORIGIN', '*')

def lambda_handler(event, context):
    try:
        table = dynamodb.Table(table_name)
        response = table.scan()

        # Return success response
        return build_successful_response(response['Items'])
    except Exception as e:
        # Return error response
        return build_response_failed(str(e))


def build_successful_response(result):
    """
    Builds a successful HTTP response.
    """
    response = {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": parent_origin,
            "Content-Type": "application/json",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent"
        },
        "body": json.dumps(result)
    }
    print("Response: ", response)
    return response


def build_response_failed(err):
    """
    Builds a failed HTTP response.
    """
    response = {
        "statusCode": 500,
        "headers": {
            "Access-Control-Allow-Origin": parent_origin,
            "Content-Type": "application/json",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token"
        },
        "body": json.dumps({"error": err})
    }
    return response
