# Utility class to manage AWS service clients via boto3
import boto3
import logging
import json
from typing import Dict, Any
from botocore.exceptions import ClientError

# Set up logging 
logger = logging.getLogger(__name__) 
logger.setLevel(logging.INFO)

class AWSServiceHandler:
    """Manages AWS service connections and common operations for AWS services"""
    
    def __init__(self):
        # Initialize AWS service clients
        self.s3 = boto3.client('s3')
        self.ec2 = boto3.client('ec2')
        self.rds = boto3.client('rds')
        self.kms = boto3.client('kms')
        self.iam = boto3.client('iam')
        self.dynamodb = boto3.resource('dynamodb')  # Use resource for DynamoDB
        self.sns = boto3.client('sns')

    def update_misconfiguration_status(self, table_name: str, resource_id: str, status: str) -> None:
        """
        Updates remediation status in MisconfiguredResources table
        
        Args:
            table_name: Name of the DynamoDB table
            resource_id: ID of the resource being remediated
            status: New status to set
            
        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            table = self.dynamodb.Table(table_name)
            table.update_item(
                Key={'ResourceID': resource_id},
                UpdateExpression='SET RemediationStatus = :status',
                ExpressionAttributeValues={':status': status}
            )
            logger.info(f"Successfully updated status for resource {resource_id} to {status}")
        except ClientError as e:
            logger.error(f"DynamoDB update failed for resource {resource_id}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating status: {str(e)}")
            raise

    def send_notification(self, topic_arn: str, message: Dict[str, Any]) -> None:
        """
        Sends notification via SNS
        
        Args:
            topic_arn: ARN of the SNS topic
            message: Dictionary containing the message to send
            
        Raises:
            ClientError: If SNS publish operation fails
        """
        try:
            self.sns.publish(
                TopicArn=topic_arn,  # Correct parameter name is TopicArn
                Message=json.dumps(message)  # Correct parameter name is Message
            )
            logger.info(f"Successfully sent notification to {topic_arn}")
        except ClientError as e:
            logger.error(f"SNS publish failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error sending notification: {str(e)}")
            raise