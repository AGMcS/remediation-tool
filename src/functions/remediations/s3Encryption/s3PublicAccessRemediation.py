import boto3
import logging
from typing import Dict, Any
from datetime import datetime, timezone
from dbHandler import DbHandler
from notificationHandler import NotificationHandler
from awsUtils import AWSServiceHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class S3PublicAccessRemediationHandler:
    """
    Handles remediation of public S3 buckets.
    Implements CIS-2.1.5 compliance for S3 bucket public access controls.
    """

    def __init__(self):
        """ Intialises AWS services, dbHandler, notificationHandler, awsHandler """
        self.s3 = boto3.client('s3')
        self.s3Resource = boto3.resource('s3')
        self.awsHandler = AWSServiceHandler()
        self.dbHandler = DbHandler()
        self.notifHandler = NotificationHandler()

    def s3PublicAccessRemediation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the remediation of a publicly deployed s3 bucket
        Switches public bucket settings and ACLs to private

        Args: 
            event: Event containing remediation details including:
                - remediationId: ID of the remediation record
                - resourceId: Name of the S3 bucket
                - complianceId: Compliance rule ID (CIS-2.1.5)

        Returns: 
            Dictionary containing remediation outcome
        """ 
        try:
            remediationId = event['remediationId']
            bucketName = event['resourceId']

            logger.info(f"Starting remediaiton for public bucket {bucketName}")

            # Get the buckets resource owner information
            ownerInfo =  self.retrieveResourceOwner(bucketName)

            # Update remediaiton status to reflect that remediation is in progress
            self.dbHandler.updateRemediationStatus(
                remediation_id=remediationId,
                status='IN_PROGRESS',
                details={
                    'startTime': datetime.now(timezone.utc).isoformat(),
                    'bucketName': bucketName
                }
            )

            # Perform the s3 remediation
            remediationOutcome = self.awsHandler.remediateS3PublicAccess(bucketName)

            if remediationOutcome['success']:
                # Apply completed remediaiton status
                self.dbHandler.updateRemediationStatus(
                    remediationId=remediationId,
                    status='COMPLETED',
                    details={
                        'completionTime': datetime.now(timezone.utc).isoformat(),
                        'changes': remediationOutcome['changes']
                    }
                )

                # Send SNS completion notification
                self.notifHandler.notifyRemediationComplete(
                    resourceId=bucketName,
                    serviceType='S3',
                    success=True,
                    details={
                        'message': 'Successfully remediated S3 bucket',
                            'changes': remediationOutcome['changes']
                    },
                    resourceOwner=ownerInfo
                )

                return {
                    'statusCode': 200,
                    'body': {
                        'message': 'Successfully secured S3 bucket',
                        'remediationId': remediationId,
                        'changes': remediationOutcome['changes']
                    }
                }
            else:
                # Manage failed remediation
                errorDetails = {
                    'error_type': 'RemediationFailed',
                    'error_message': remediationOutcome['message']
                }
                
                self.dbHandler.updateRemediationStatus(
                    remediation_id=remediationId,
                    status='FAILED',
                    details={
                        'failureTime': datetime.now(timezone.utc).isoformat(),
                        'error': errorDetails
                    }
                )
                
                # Send failure notification
                self.notifHandler.notifyRemediationFailed(
                    resourceId=bucketName,
                    serviceType='S3',
                    errorDetails=errorDetails,
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
                'errorType': 'UnexpectedError',
                'errorMessage': str(e)
            }

            self.dbHandler.updateRemediationStatus(
                remediation_id=remediationId,
                status='FAILED',
                details={
                    'failureTime': datetime.now(timezone.utc).isoformat(),
                    'error': errorDetails
                }
            )
            
            if ownerInfo:
                self.notifHandler.notifyRemediationFailed(
                    resourceId=bucketName,
                    serviceType='S3',
                    errorDetails=errorDetails,
                    resourceOwner=ownerInfo
                )

            raise


    def retrieveResourceOwner(self, bucketName: str) -> Dict[str, str]:
        """
        Retrieves owner of resource from buckets tags

        Args:
            bucketName: Name of the S3 bucket

        Returns:
            Dictionary containing owner email and team
        """
        try:
            # Get bucket info using S3 client
            bucketTags = self.s3.get_bucket_tagging(Bucket=bucketName)
            
            # Convert tags to dictionary with lowercase keys
            tags = {tag['Key'].lower(): tag['Value']
                for tag in bucketTags.get('TagSet', [])}
            
            return {
                'email': tags.get('owner'),
                'team': tags.get('team')
            }
        except Exception as e:
            logger.error(f"Unexpected error getting bucket owner info: {str(e)}")
            return {'email': None, 'team': 'Unknown'}
           
def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda entry point for S3 public access remediation
    Triggered by the remediation scheduler when a remediation is due
    """
    try:
        handler = S3PublicAccessRemediationHandler()
        return handler.s3PublicAccessRemediation(event)
    except Exception as e:
        logger.error(f"Error in lambda Handler for s3 Public access Remediaton: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e)
            }
        }       
    
    