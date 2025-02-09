import boto3
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DbHandler:
    """
    Manages all interactions with the DynamoDB Database.
    """

    def __init__(self):
        """Initialize DynamoDB resources and table references"""
        self.dynamodb = boto3.resource('dynamodb')
        
        # Initialize table references using environment variables from SAM template
        self.misconfigTable = self.dynamodb.Table(os.environ['MISCONFIG_TABLE'])
        self.severityTable = self.dynamodb.Table(os.environ['SEVERITY_TABLE'])
        self.remediationTable = self.dynamodb.Table(os.environ['REMEDIATION_TABLE'])
        self.completedTable = self.dynamodb.Table(os.environ['COMPLETED_TABLE'])
        self.complianceTable = self.dynamodb.Table(os.environ['COMPLIANCE_TABLE'])

    def remediationTime(self, complianceId: str) -> datetime:
        """
        Gets the time to remediate tied to the misconfigurarution severity from the SeverityLevel Table

        Args:
        complianceId The compliane rule id to look up for severity level

        Returns:
            datetime: time window the remediation will be executed
        """
        try:
            # Get compliance rule to find severity
            complianceResponse = self.complianceTable.get_item(
                Key={
                    'ComplianceID': complianceId,
                    'ServiceType': complianceId.split('-')[0]
                }
            )

            if 'Item' not in complianceResponse:
                raise KeyError(f"Compliance rule {complianceId} not found")

            severityId = complianceResponse['Item'].get('RiskLevel', 'MEDIUM')

            # Get the remediation delay from the severityLevels Table
            severityResponse = self.severityTable.get_item(
                Key={'SeverityID': severityId}
            )

            if 'Item' not in severityResponse:
                raise KeyError(f"Severity level {severityId} not found")

            delayMinutes = severityResponse['Item'].get('RemediationTimeMinutes', 60)

            # Calculate remediation time
            return datetime.now(timezone.utc) + timedelta(minutes=delayMinutes)

        except ClientError as e:
            logger.error(f"DynamoDB error getting remediation time: {str(e)}")
            raise

    def recordMisconfiguration(self, resourceId: str, complianceId: str, serviceType: str, severityId: str, details: Dict[str, Any]) -> None:
        """
        Records a detected misconfiguration in the Misconfigured Resource Table
        """
        try:
            currentTime = datetime.now(timezone.utc).isoformat()

            item = {
                'ResourceID': resourceId,
                'DetectedTimeGenerated': currentTime,
                'ServiceType': serviceType,
                'ComplianceID': complianceId,
                'SeverityID': severityId,
                'RemediationState': 'DETECTED',
                'Details': details
            }

            self.misconfigTable.put_item(Item=item)
            logger.info(f"Recorded misconfiguration for resource {resourceId}")

        except ClientError as e:
            logger.error(f"Failed to record misconfiguration: {str(e)}")
            raise

    def scheduleRemediation(self, resourceId: str, remediationTime: datetime, complianceId: str) -> str:
        """ 
        Created a scheduled remediation entry in the ScheduledRemediation Table

        Returns:
            str: The created Remediation ID for tracking
        """
        try:
            # Create a unique ID using the current timestamp
            timeStamp = int(datetime.now(timezone.utc).timestamp())
            remediationId = (f"rem-{resourceId}-{timeStamp}")

            item = {
                'RemediationID': remediationId,
                'StartTime': remediationTime.isoformat(),
                'ResourceID': resourceId,
                'ComplianceID': complianceId,
                'RemediationStatus': 'SCHEDULED'
            }

            self.remediationTable.put_item(Item=item)

            # Update status in misconfiguration Table
            self.misconfigTable.update_item(
                Key={'ResourceID': resourceId},
                UpdateExpression='SET RemediationState = :state',
                ExpressionAttributeValues={':state': 'SCHEDULED'}
            )

            return remediationId

        except ClientError as e:
            logger.error(f"Failed to schedule remediation: {str(e)}")
            raise

    def recordCompletion(self, remediationId: str, resourceId: str, success: bool, details: Dict[str, Any]) -> None:
        """
        Records the completion of a remediation action.
        Updates status across all relevant tables.
        """
        try:
            currentTime = datetime.now(timezone.utc).isoformat()

            # Record in CompletedRemediations table
            completionItem = {
                'CompletedRemediationID': f"comp-{remediationId}",
                'CompletionTimestamp': currentTime,
                'RemediationID': remediationId,
                'ResourceID': resourceId,
                'Success': success,
                'Details': details
            }

            self.completedTable.put_item(Item=completionItem)

            # Update status in both tables
            status = 'COMPLETED' if success else 'FAILED'

            self.remediationTable.update_item(
                Key={'RemediationID': remediationId},
                UpdateExpression='SET RemediationStatus = :status',
                ExpressionAttributeValues={':status': status}
            )

            self.misconfigTable.update_item(
                Key={'RemediationID': remediationId},
                UpdateExpression='SET RemediationStatus = :status',
                ExpressionAttributeValues={':status': status}
            )

        except ClientError as e:
            logger.error(f"Failed to record completion: {str(e)}")
            raise

    def getPendingRemediations(self) -> List[Dict[str, Any]]:
        """
        Retrieves all pending remediation actions that are ready to be executed.
        """
        try:
            currentTime = datetime.now(timezone.utc).isoformat()

            response = self.remediationTable.query(
                IndexName='StatusTimeIndex',
                KeyConditionExpression='RemediationStatus = :status AND StartTime <= :now',
                ExpressionAttributeValues={
                    ':status': 'SCHEDULED',
                    ':now': currentTime
                }
            )
            return response.get('Items', [])

        except ClientError as e:
            logger.error(f"Failed to get pending remediaitons: {str(e)}")
            raise

    def getResourceHistory(self, resourceId: str) -> Dict[str, Any]:
        """
        Retrieves the complete history of a resource including misconfigurations
        and remediations.
        """
        try:
            # Get misconfigured Record
            misconfiguration = self.misconfigTable.get_item(
                Key={'ResourceID': resourceId}
            ).get('Item')

            # Get remediation history using GSI
            remediations = self.remediationTable.query(
                IndexName='ResourceRemediationIndex',
                KeyConditionExpression='ResourceID = :rid',
                ExpressionAttributeValues={':rid': resourceId}
            ).get('Items', [])

            return {
                'misconfiguration': misconfiguration,
                'remediations': remediations
            }

        except ClientError as e:
            logger.error(f"Failed to get resource history: {str(e)}")
            raise