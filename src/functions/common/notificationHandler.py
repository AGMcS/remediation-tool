import boto3
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class NotificationHandler:
    """
    Handles all notification operations for the application.
    Manages both DynamoDB records of notifications and SNS message delivery.
    """

    def __init__(self):
        # Intialise Aws services and resources 
        self.dynamodb = boto3.resource('dynamodb')
        self.sns = boto3.client('sns')

        # Initialize DynamoDB table
        self.notificationsTable = self.dynamodb.Table(os.environ['NOTIFICATIONS_TABLE'])
        
        # Initialize SNS topic from environment variable
        self.notificationTopic = os.environ['NOTIFICATION_TOPIC']

    def notifyScheduledRemediation(self, resourceId: str, serviceType: str, complianceId: str, remediationTime: datetime, resourceOwner: Dict[str, str]) -> str:
        """
        Notifies resource owner about a scheduled remediation.

        Args:
            resourceId: ID of the resource to be remediated
            serviceType: Type of AWS service (e.g., 'S3', 'EC2')
            complianceId: ID of the compliance rule violation
            remediationTime: When remediation will occur
            resourceOwner: Dict containing owner email and team
        
        Returns:
            str: The notification ID
        """
         
        try:
            notificationId = f"notif-{resourceId}-{(int(datetime.now(timezone.utc).timestamp()))}"
            subject = f"Scheduled Remediation for {serviceType} Resource: {resourceId}"

            message = {
                "subject": subject,
                "body": f"""
                    A compliance violation has been detected for your {serviceType} resource.

                    Resource ID: {resourceId}
                    Compliance Rule: {complianceId}
                    Scheduled Remediation Time: {remediationTime.strftime('%Y-%m-%d %H:%M:%S UTC')}

                    This resource will be automatically remediated at the scheduled time to 
                    ensure compliance with security policies. If you would like to remediate 
                    this issue yourself before the scheduled time, please do so.

                    Team: {resourceOwner.get('team', 'Not specified')}

                    For more information about this compliance rule and remediation process,
                    please contact the security team.
                """.strip()
            }
            self.storeNotification(
                notification_id=notificationId,
                resource_id=resourceId,
                notification_type="REMEDIATION_SCHEDULED",
                owner_info=resourceOwner,
                message=message
            )
             
            # Send SNS Notification
            self.sendNotification(message, resourceOwner)

            return notificationId
        except Exception as e:
            logger.error(f"Failed to send scheduled remediation notification: {str(e)}")
            raise

    def notifyRemediationComplete(self, resourceId: str, serviceType: str, success: bool, details: Dict[str, Any], resourceOwner: Dict[str, str]) -> str:
        """
        Notifies resource owner about completed remediation.

        Args:
            resourceId: ID of the remediated resource
            serviceType: Type of AWS service
            success: Whether remediation was successful
            details: Additional details about the remediation
            resourceOwner: Dict containing owner email and team
        
        Returns:
            str: The notification ID
        """
        try:
            notificationId = f"notif-complete-{resourceId}-{(int(datetime.now(timezone.utc).timestamp()))}"
            status = "successful" if success else "failed"
            subject = f"Remediation {status.capitalize()} for {serviceType} Resource: {resourceId}"
            
            message = {
                "subject": subject,
                "body": f"""
                    The remediation action for your {serviceType} resource has {status}.

                    Resource ID: {resourceId}
                    Status: {status.upper()}
                    Completion Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
                    
                    {details.get('message', '')}

                    Team: {resourceOwner.get('team', 'Not specified')}

                    Please review the changes and verify your resource is working as expected.
                    If you experience any issues, please contact the security team immediately.
                """.strip()
            }

            # Store notification record
            self.storeNotification(
                notification_id=notificationId,
                resource_id=resourceId,
                notification_type="REMEDIATION_COMPLETE",
                owner_info=resourceOwner,
                message=message
            )

            # Send SNS notification
            self.sendNotification(message, resourceOwner)

            return notificationId

        except Exception as e:
            logger.error(f"Failed to send completion notification: {str(e)}")
            raise

    def notifyRemediationFailed(self, resourceId: str, serviceType: str, errorDetails: Dict[str, Any], resourceOwner: Dict[str, str]) -> str:
        """
        Notifies resource owner and security team about failed remediation.

        Args:
            resourceId: ID of the resource
            serviceType: Type of AWS service
            errorDetails: Details about the failure
            resourceOwner: Dict containing owner email and team
        
        Returns:
            str: The notification ID
        """
        try:
            notificationId = f"notif-failed-{resourceId}-{(int(datetime.now(timezone.utc).timestamp()))}"
            subject = f"Remediation Failed for {serviceType} Resource: {resourceId}"

            message = {
                "subject": subject,
                "body": f"""
                    The remediation action for your {serviceType} resource has failed.

                    Resource ID: {resourceId}
                    Error Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
                    Error Type: {errorDetails.get('error_type', 'Unknown')}
                    Error Message: {errorDetails.get('error_message', 'No details available')}

                    Team: {resourceOwner.get('team', 'Not specified')}

                    The security team has been notified and will investigate this issue.
                    You may be contacted for additional information or actions required.
                """.strip()
            }

            # Store notification record
            self.storeNotification(
                notification_id=notificationId,
                resource_id=resourceId,
                notification_type="REMEDIATION_FAILED",
                owner_info=resourceOwner,
                message=message
            )

            # Send SNS notification with high priority
            self.sendNotification(
                message,
                resourceOwner,
                attributes={'Priority': {'DataType': 'String', 'StringValue': 'HIGH'}}
            )

            return notificationId
        
        except Exception as e:
            logger.error(f"Failed to send failure notification: {str(e)}")
            raise

    def storeNotification(self, notificationId: str, resourceId: str, notificationType: str, ownerInfo: Dict[str, str], message: Dict[str, str]) -> None:
        """
    Writes the notification record to the DynamoDB database.
    
    Args:
        notificationId: Unique identifier for the notification
        resourceId: ID of the affected resource
        notificationType: Type of notification being stored
        ownerInfo: Dictionary containing owner details
        message: Dictionary containing subject and body of notification
    """
        try:
            item = {
                'NotificationID': notificationId,
                'NotificationSentTime': datetime.now(timezone.utc).isoformat(),
                'ResourceID': resourceId,
                'NotificationType': notificationType,
                'OwnerEmail': ownerInfo.get('email'),
                'Team': ownerInfo.get('team'),
                'Subject': message['subject'],
                'Message': message['body']
            }

            self.notificationsTable.put_item(Item=item)

        except Exception as e:
            logger.error(f"Failed to store the notification record: {str(e)}")
            raise

    def sendNotification(self, message: Dict[str, str], ownerInfo: Dict[str, str], attributes: Dict[str, Dict[str, str]] = None) -> None:
        """
        Send notification via SNS

        Args:
        message: Dictionary containing notification subject and body
        ownerInfo: Dictionary containing owner email and team info
        attributes: Optional dictionary of additional SNS message attributes
        """
        try:
            if not ownerInfo.get('email'):
                logger.warning("No owner email provided for notification")
                return

            messageAttributes = {
                'EmailAddress': {
                    'DataType': 'String',
                    'StringValue': ownerInfo['email']
                },
                'Team': {
                    'DataType': 'String',
                    'StringValue': ownerInfo.get('team', 'Unknown')
                }
            }

            # Add any additional attributes
            if attributes:
                messageAttributes.update(attributes)

            self.sns.publish(
                TopicArn=self.notificationTopic,
                Message=message['body'],
                Subject=message['subject'],
                MessageAttributes=messageAttributes
            )

        except ClientError as e:
            logger.error(f"Failed to send SNS notification: {str(e)}")
            raise