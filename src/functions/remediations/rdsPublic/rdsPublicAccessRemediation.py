import boto3
import logging 
import os
from typing import Dict, Any
from datetime import datetime, timezone
from dbHandler import DbHandler
from notificationHandler import NotificationHandler
from awsUtils import AWSServiceHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class RDSPublicAccessRemediationHandler:
    """
    Handles remediation of publicly accessible RDS instances.
    Makes RDS instances private while maintaining proper access controls
    Implements CIS-2.3.2 compliance for RDS public accessibility
    """

    def __init__(self):
        """ Intialises AWS services, dbHandler, notificationHandler, awsHandler """
        self.rds = boto3.client('rds')
        self.awsHandler = AWSServiceHandler()
        self.dbHandler = DbHandler()
        self.notifHandler = NotificationHandler()

    def rdsPublicAccessRemediation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main remediation handler for any publicly deployed RDS databases
        Makes the instance private and updates security configuration

        Args:
            event: Event containing remediation details including:
                  - remediationId: ID of the remediation record
                  - resourceId: Id of the RDS instance
                  - complianceId: Compliance rule ID (CIS-2.3.2)

        Returns:
            Dictionary containing remediation outcome
        """

        try: 
            remediationId = event['remediationId']
            resourceId = event['resourceId']

            logger.info(f"Starting remediation for public RDS instance {resourceId}")

            # Get the resources owner information
            ownerInfo = self.retrieveResourceOwner(resourceId)

            # Update the remediation Status table attritube 
            self.dbHandler.updateRemediationStatus(
                remediationId=remediationId,
                status='IN_PROGRESS',
                details={
                    'startTime': datetime.now(timezone.utc).isoformat(),
                    'resourceId': resourceId
                }
            )

            remediationOutcome = self.awsHandler.remediateRDSPublicAccess(resourceId)

            if remediationOutcome['success']:
                # Update remediation status to completed
                self.dbHandler.updateRemediationStatus(
                    remediationId=remediationId,
                    status='COMPLETED',
                    details={
                        'completionTime': datetime.now(timezone.utc).isoformat(),
                        'changes': remediationOutcome['changes']
                    }
                )
                
                # Send completion notification with access change details
                completionMessage = (
                    f"Your RDS instance {resourceId} has been made private for security compliance. "
                    "Please ensure your applications are configured to access the database "
                    "through appropriate private endpoints or VPC connectivity."
                )
                
                self.notifHandler.notifyRemediationComplete(
                    resourceId=resourceId,
                    serviceType='RDS',
                    success=True,
                    details={
                        'message': completionMessage,
                        'changes': remediationOutcome['changes']
                    },
                    resourceOwner=ownerInfo
                )
                
                return {
                    'statusCode': 200,
                    'body': {
                        'message': 'Successfully made RDS instance private',
                        'remediationId': remediationId,
                        'changes': remediationOutcome['changes']
                    }
                }
            else:
                # Handle failed remediation
                errorDetails = {
                    'errorType': 'RemediationFailed',
                    'errorMessage': remediationOutcome['message']
                }
                
                self.dbHandler.updateRemediationStatus(
                    remediation_id=remediationId,
                    status='FAILED',
                    details={
                        'failureTime': datetime.now(timezone.utc).isoformat(),
                        'error': errorDetails
                    }
                )
                
                # Send failure notification with guidance
                failureMessage = (
                    f"Failed to modify public access settings for RDS instance {resourceId}. "
                    "The security team will investigate the issue. If you need immediate "
                    "assistance, please contact the database administration team."
                )
                
                self.notifHandler.notifyRemediationFailed(
                    resourceId=resourceId,
                    serviceType='RDS',
                    errorDetails={
                        **errorDetails,
                        'guidance': failureMessage
                    },
                    resourceOwner=ownerInfo
                )
                
                return {
                    'statusCode': 500,
                    'body': {
                        'error': 'Remediation failed',
                        'details': errorDetails
                    }
                }
                
        except Exception as e:
            logger.error(f"Error in remediation handler: {str(e)}")
            errorDetails = {
                'error_type': 'UnexpectedError',
                'error_message': str(e)
            }

            self.dbHandler.updateRemediationStatus(
                remediationId=remediationId,
                status='FAILED',
                details={
                    'failureTime': datetime.now(timezone.utc).isoformat(),
                    'error': errorDetails
                }
            )
            
            if ownerInfo:
                self.notifHandler.notifyRemediationFailed(
                    resourceId=resourceId,
                    serviceType='RDS',
                    errorDetails=errorDetails,
                    resourceOwner=ownerInfo
                )
            
            raise
    

    def constructRDSArn(self, resourceId: str) -> str:
        """
        Constructs the ARN for an RDS resource
        
        Args:
            resourceId: The id of the RDS 
            
        Returns:
            The complete ARN for the resource
        """
        return f"arn:aws:rds:{os.environ['AWS_REGION']}:{os.environ['AWS_ACCOUNT_ID']}:db:{resourceId}"

    def retrieveResourceOwner(self, resourceId: str) -> Dict[str, str]:
        """
        Retrieves owner info from RDS instance tags.
        
        Args:
            resourceId: The id of the RDS instance
            
        Returns:
            Dictionary containing owner email and team
        """
        try:
            # Get RDS instance tags
            response = self.rds.list_tags_for_resource(
                ResourceName=self.constructRDSArn(resourceId)
            )
            
            # Convert tags to dictionary with lowercase keys
            tags = {tag['Key'].lower(): tag['Value']
                   for tag in response.get('TagList', [])}
            
            return {
                'email': tags.get('owner'),
                'team': tags.get('team')
            }
            
        except Exception as e:
            logger.error(f"Error getting RDS instance owner info: {str(e)}")
            return {'email': None, 'team': 'Unknown'}
        
def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda entry point for RDS public access remediation
    Triggered by the remediation scheduler when a remediation is due
    """
    try:
        handler = RDSPublicAccessRemediationHandler()
        return handler.rdsPublicAccessRemediation(event)
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e)
            }
        }