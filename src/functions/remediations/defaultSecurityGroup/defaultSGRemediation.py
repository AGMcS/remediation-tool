import boto3
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from common.dbHandler import DbHandler
from common.notificationHandler import NotificationHandler
from common.awsUtils import AWSServiceHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DefaultSGRemediationHandler:
    """
    Remediates any non compliant security groups who have been assigned default permissions.
    Remedaiton action will remove all inbound and outbound rules from sec group inline 
    with CIS-4.2.
    """

    def __init__(self):
        "Intialise AWS services, dbHandler, notificationHandler, awsHandler"
        self.ec2 = boto3.client('ec2')
        self.dbHandler = DbHandler()
        self.notifHandler = NotificationHandler()
        self.awsHandler = AWSServiceHandler()

    def defaultSGRemediation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the remediation of a default Security Group

        Args:
            event:Event containing remediation details including:
                - remediationId: ID of the remediation record
                - resourceId: ID of the VPC
                - complianceId: Compliance rule ID (CIS-4.2)
        Returns:
            Dictionary containing remediation results
        """
        try:
            remediationId = event['remediationId']
            vpcId = event['resourceId']

            logger.info(f"Running remediation for default security group located in VPC {vpcId}")

            # Retrieve resource owner infotmation
            ownerInfo = self.retrieveResourceOwner(vpcId)

            # Execute the remediation
            remediationOutcome = self.awsHandler.remediateDefaultSecurityGroup(vpcId)

            if remediationOutcome['success']:
                # Update remediation status data to completed
                self.dbHandler.updateRemediationStatus(
                    remediationId=remediationId,
                    status='COMPLETED',
                    details={
                        'completionTime': datetime.now(timezone.utc).isoformat(),
                        'changes': remediationOutcome['changes']
                    }
                )

                # Send SNS to parties to notify of completed remedaiton
                self.notifHandler.notifyRemediationComplete(
                    resourceId=vpcId,
                    serviceType='VPC',
                    success=True,
                    details={
                        'message': remediationOutcome['message'],
                        'changes': remediationOutcome['changes']
                    },
                    resourceOwner=ownerInfo
                )

                return {
                    'statusCode': 200,
                    'body': {
                        'message': 'Successfully remediated default security group',
                        'remediationId': remediationId,
                        'changes': remediationOutcome['changes']
                    }
                }
            else:
                # Deal with failed remediation
                errorDetails = {
                    'errorType': 'RemediationFailed',
                    'errorMessage': remediationOutcome['message']
                }

                self.dbHandler.updateRemediationStatus(
                    remediationId=remediationId,
                    status='Failed',
                    details={
                        'timeFailureOccured': datetime.now(timezone.utc).isoformat,
                        'error': errorDetails
                    }
                )

                # Send SNS to parties to notify of failed remedaiton
                self.notifHandler.notifyRemediationFailed(
                    resourceId=vpcId,
                    serviceType='VPC',
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
            logger.error(f"Error in defaultSGRemediaiton Lambda: {str(e)}")
            # Handle unexpected errors
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
                    resourceId=vpcId,
                    serviceType='VPC',
                    errorDetails=errorDetails,
                    resourceOwner=ownerInfo
                )
            
            raise

    def grabResourceOwner(self, vpcId: str) -> Dict[str, Any]:
        """
        Grabs the owner information from associated VPC tags assigned.

        Args:
            vpcId: The ID of the VPC

        Returns:
            Dictionary containing owner email and team information
        """
        try:
            tagResponse = self.ec2.describe_vpcs(
                vpcId-[vpcId]
            )

            if not tagResponse['Vpcs']:
                logger.warning(f"VPC {vpcId} not found")
                return {'email': None, 'team': 'Unknown'}
            
            tags = {
                tag['Key'].lower(): tag['Value']
                for tag in tagResponse['Vpcs'][0].get('Tags', [])
            }

            return {
                'email': tags.get('owner'),
                'team': tags.get('team') 
            }
        
        except Exception as e:
            logger.error(f"Error getting VPC owner info: {str(e)}")
            return {'email': None, 'team': 'Unknown'}
        
    def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Lambda entry point for default security group remediation.
        Triggered by the remediation scheduler when a remediation is due.
        """
        try: 
            handler = DefaultSGRemediationHandler()
            return handler.defaultSGRemediation(event)
        except Exception as e:
            logger.error(f"Error in the lambda handler for default security groups: {str(e)}")
            return {
                'statusCode': 500,
                'body': {
                    'error': str(e)
                }
            }
        