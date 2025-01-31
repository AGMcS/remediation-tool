import boto3
import json
import os
from datetime import datetime

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
tableName = os.environ['TABLE_NAME']
s3 = boto3.client('s3')

# Fetch environment variables
parentOrigin = os.environ.get('PARENT_ORIGIN', '*')

def lambdaHandler(event, context):
    try:
        # Parse incoming request
        body = json.loads(event.get('body', '{}'))
        bucketName = body.get('bucketName')

        if not bucketName:
            raise ValueError("Missing required parameter: bucketName")

        # Log and update DynamoDB to "Pending" status
        table = dynamodb.Table(tableName)
        table.put_item(Item={
            'BucketName': bucketName,
            'Status': 'Pending',
            'Timestamp': datetime.utcnow().isoformat(),
        })

        # Perform remediation
        s3.put_bucket_acl(Bucket=bucketName, ACL='private')
        s3.put_public_access_block(
            Bucket=bucketName,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True,
            }
        )

        # Update DynamoDB to "Resolved" status
        table.update_item(
            Key={'BucketName': bucketName},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={'#s': 'Status'},
            ExpressionAttributeValues={':s': 'Resolved'}
        )

        # Return success response
        return buildSuccessfulResponse({"message": f"Remediation for {bucketName} completed successfully."})
    except Exception as e:
        # Return error response
        return buildResponseFailed(str(e))


def buildSuccessfulResponse(result):
    """
    Builds a successful HTTP response.
    """
    response = {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": parentOrigin,
            "Content-Type": "application/json",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent"
        },
        "body": json.dumps(result)
    }
    print("Response: ", response)
    return response


def buildResponseFailed(err):
    """
    Builds a failed HTTP response.
    """
    response = {
        "statusCode": 500,
        "headers": {
            "Access-Control-Allow-Origin": parentOrigin,
            "Content-Type": "application/json",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token"
        },
        "body": json.dumps({"error": err})
    }
    return response
