import boto3
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any
from dbHandler import DbHandler
from notificationHandler import NotificationHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DetectionHandler:
    """
    Handles the detection phase of compliance violations.
    Processes EventBridge events, records violations, and initiates remediation process.
    """

    def __init__(self):
        """
        Initialise handlers and AWS services
        """
        self.dbHandler = DbHandler()
        self.notificationHandler = NotificationHandler()
        self.resourceTaggingApi = boto3.client('resourcegroupstaggingapi')

    def processComplianceViolation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a detected compliance violation from EventBridge.
        Records the violation, schedules remediation, and notifies owners.

        Args:
            event: EventBridge event containing violation details
        
        Returns:
            Dictionary containing processing results
        """
        try:
            # get information from the event
            resourceId = self.getResourceId(event)
            complianceId = event['detail']['complianceId']
            serviceType = event['detail']['complianceId']
            riskLevel = event['detail']['riskLevel']

            # get resource owner data
            resourceOwner = self.getResourceOwner(resourceId, serviceType)

            # Write misconfiguration to DynamoDB
            logger.info(f"Recording misconfiguration for resource {resourceId}")
            self.dbHandler.recordMisconfiguration(
                resourceId=resourceId,
                complianceId=complianceId,
                serviceType=serviceType,
                severityId=riskLevel,
                details={
                    'event': event['detail'],
                    'detectedTime': datetime.now(timezone.utc).isoformat()
                }
            )

            # Calculate remediation time based on severity
            remediationTime = self.dbHandler.getRemediationTime(complianceId)

            # Schedule the remediation 
            logger.info(f"Scheduling remediation for {resourceId}")
            remediationId = self.dbHandler.scheduleRemediation(
                resourceId=resourceId,
                serviceType=serviceType,
                complianceId=complianceId,
                remediationTime=remediationTime,
                resourceOwner=resourceOwner
            )

            return {
                'statusCode': 200,
                'body': {
                    'message': 'Successfully processed compliance violation',
                    'resourceId': resourceId,
                    'remediationId': remediationId,
                    'scheduledTime': remediationTime.isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Error processing compliance violation: {str(e)}")
            raise

    def getResourceId(self, event: Dict[str, Any]) -> str:
        """
        Gets resource ID from EventBridge event based on service type.

        Args:
            event: EventBridge event details
            
        Returns:
            Resource ID string
        """

        detail = event['detail']
        eventSource = detail['eventSource']

        # Get information based on service type
        if 's3' in eventSource:
            return detail['requestParameters']['bucketName']
        elif 'ec2' in eventSource:
            return detail['responseElements'].get('volumeId') or detail['requestParameters']['groupId']
        elif 'rds' in eventSource:
            return detail['responseElements']['dBInstanceIdentifier']
        elif 'kms' in eventSource:
            return detail['requestParameters']['keyId']
        elif 'iam' in eventSource:
            return detail['responseElements']['accessKey']['accessKeyId']
        else:
            raise ValueError(f"Unsupported event source: {eventSource}")

    def getResourceOwner(self, resourceId: str, serviceType: str) -> Dict[str, str]:
        """
        Retrieves resource owner information from AWS tags.

        Args:
            resourceId: ID of the resource
            serviceType: Type of AWS service
            
        Returns:
            Dictionary containing owner email and team
        """

        region = os.environ['AWS_REGION']
        accountId = os.environ['AWS_ACCOUNT_ID']

        try:
            # Construct ARN based on service type
            if serviceType == 'S3':
                arn = f"arn:aws:s3:::{resourceId}"
            elif serviceType == 'EC2':
                arn = f"arn:aws:ec2:{region}:{accountId}:volume/{resourceId}"
            elif serviceType == 'RDS':
                arn = f"arn:aws:rds:{region}:{accountId}:db:{resourceId}"
            elif serviceType == 'KMS':
                arn = f"arn:aws:kms:{region}:{accountId}:key/{resourceId}"
            elif serviceType == 'IAM':
                arn = f"arn:aws:iam::{region}:{accountId}:role/{resourceId}"
            else:
                arn = resourceId  # Fallback to using ID directly

            # Get the resources Tags
            response = self.resourceTaggingApi.get_resources(
                ResourceARNList=[arn],
                TagsPerPage=100
            )

            # Extract owner information from tags
            tags = {}
            if response['ResourceTagMappingList']:
                for tag in response['ResourceTagMappingList'][0]['Tags']:
                    tags[tag['Key'].lower()] = tag['Value']
            
            return {
                'email': tags.get('owner'),
                'team': tags.get('team')
            }
        
        except Exception as e:
            logger.warning(f"Failed to get resource owner info: {str(e)}")
            return {'email': None, 'team': 'Unknown'}
        
def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda entry point for processing compliance violations.
    """
    try:
        handler = DetectionHandler()
        return handler.processComplianceViolation(event)
    
    except Exception as e:
        logger.error(f"Error in lambdaHandler: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e)
            }
        }