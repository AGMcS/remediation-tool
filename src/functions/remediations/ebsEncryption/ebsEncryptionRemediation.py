import boto3
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from awsUtils import AWSServiceHandler
from dbHandler import DbHandler
from notificationHandler import NotificationHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class EBSEncryptionRemediationHandler:
    """
    Runs remediation of unencrypted EBS volumes.
    Creates encrypted copies of volumes and keeps  data and attachments.
    Enforces CIS-2.2.1 compliance for EBS volume encryption.
    """

    def __init__(self):
        """ Intialise AWS services, dbHandler, notificationHandler, awsHandler """
        self.ec2 = boto3.client('ec2')
        self.awsHandler = AWSServiceHandler()
        self.dbHandler = DbHandler()
        self.notifHandler = NotificationHandler()

    def ebsEncryptionRemediation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the remediation of an unencrypted EBS volume
        Replicates and creates existing volume

        Args:
            event: Event containing remediation details including:
                  - remediationId: ID of the remediation record
                  - resourceId: ID of the EBS volume
                  - complianceId: Compliance rule ID (CIS-2.2.1)

        Returns: 
            Dictionary containing remediation outcome
        """
        try:
            remediationId = event['remediationId']
            volumeId = event['resourceId']

            logger.info(f"Starting remediationfor the EBS volume {volumeId}")

            # Retrieve the volume info and retrieve owner info
            volumeInfo = self.retrieveVolumeInfo(volumeId)
            ownerInfo = self.retrieveResourceOwner(volumeId)

            # Check if volume is attached to an instance
            isAttached = 'Attachments' in volumeInfo and volumeInfo['Attachments']
            instanceId = volumeId['Attachments'[0]['InstanceId']] if isAttached else None

            # Update status to in progress
            self.dbHandler.updateRemediationStatus(
                remediationId=remediationId,
                status='IN_PROGRESS',
                details={
                    'startTime': datetime.now(timezone.utc).isoformat(),
                    'volumeState': 'attached' if isAttached else 'detached',
                    'instanceId': instanceId
                }
            )

            # Perform the encryption remediation
            remediationOutcome = self.awsHandler.remediateEBSEncryption(volumeId)

            if remediationOutcome['success']:
                newVolumeId = remediationOutcome['newVolumeId']
                
                # If volume was attached, attach the new encrypted volume
                if isAttached:
                    self.attachEncryptedVolume(
                        instanceId=instanceId,
                        oldVolumeId=volumeId,
                        newVolumeId=newVolumeId,
                        deviceName=volumeInfo['Attachments'][0]['Device']
                    )
                
                # Update remediation status to completed
                self.dbHandler.updateRemediationStatus(
                    remediationId=remediationId,
                    status='COMPLETED',
                    details={
                        'completionTime': datetime.now(timezone.utc).isoformat(),
                        'changes': remediationOutcome['changes'],
                        'newVolumeId': newVolumeId
                    }
                )

                # Copy tags from old volume to new volume
                self.copyVolumeTags(volumeId, newVolumeId)

                # Send SNS completion notification
                self.notifHandler.notifyRemediationComplete(
                    resourceId=volumeId,
                    serviceType='EC2',
                    success=True,
                    details={
                        'message': 'Successfully created encrypted volume copy',
                        'newVolumeId': newVolumeId,
                        'changes': remediationOutcome['changes']
                    },
                    resourceOwner=ownerInfo
                )

                return {
                    'statusCode': 200,
                    'body': {
                        'message': 'Successfully encrypted EBS volume',
                        'remediationId': remediationId,
                        'newVolumeId': newVolumeId,
                        'changes': remediationOutcome['changes']
                    }
                }
            else:
                # Manage failed remedaition
                errorDetails = {
                    'errorType': 'Remediation failed',
                    'details': remediationOutcome['message']
                }

                self.dbHandler.updateRemediationStatus(
                    remediationId=remediationId,
                    status='FAILED',
                    details = {
                        'failureTime': datetime.now(timezone.utc).isoformat(),
                        'error': errorDetails
                    }
                )

                # Send the SNS failure notification
                self.notifHandler.notifyRemediationFailed(
                    resourceId=volumeId,
                    serviceType='EC2',
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
                remediationId=remediationId,
                status='FAILED',
                details={
                    'failureTime': datetime.now(timezone.utc).isoformat(),
                    'error': errorDetails
                }
            )

            if ownerInfo:
                self.notifHandler.notifyRemediationFailed(
                    resourceId=volumeId,
                    serviceType='EC2',
                    errorDetails=errorDetails,
                    resourceOwner=ownerInfo
                )
            raise

    def retrieveVolumeInfo(self, volumeId: str) -> Dict[str, Any]:
        """
        Retrieves info about an EBS volume.

        Args:
            volumeId: The ID of the EBS volume

        Returns:
            Dictionary containing volume details
        """
        try:
            volumeResponse = self.ec2.describe_volumes(VolumeIds=[volumeId])
            return volumeResponse['Volumes'][0]
        except Exception as e:
            logger.error(f"Error getting volume info: {str(e)}")
            raise

    def retrieveResourceOwner(self, volumeId: str) -> Dict[str, str]:
        """
        Retrieves owner info from volume tags.

        Args:
            volumeId: The ID of the EBS volume

        Returns:
            Dictionary containing owner email and team
        """
        try:
            volumeInfo = self.retrieveVolumeInfo(volumeId)
            tags = {tag['Key'].lower(): tag['Value'] 
                   for tag in volumeInfo.get('Tags', [])}
            
            return {
                'email': tags.get('owner'),
                'team': tags.get('team') 
            }
        except Exception as e:
            logger.error(f"Error getting volume owner info: {str(e)}")
            return {'email': None, 'team': 'Unknown'}
        
    def attachEncryptedVolume(self, instanceId: str, oldVolumeId: str, newVolumeId: str, deviceName: str) -> None:
        """
        Handles the process of swapping an unencrypted volume with its encrypted copy.

        Args:
            instanceId: ID of the EC2 instance
            oldVolumeId: ID of the original unencrypted volume
            newVolumeId: ID of the new encrypted volume
            deviceName: Device name 
        """
        try:
            # Detach the old Volume
            logger.info(F"Detaching volume {oldVolumeId} from instance: {instanceId}")
            self.ec2.detach_volume(
                VolumeId=newVolumeId,
                InstanceId=instanceId,
                Device=deviceName
            )

            # Wait for the volume to be attached to the instance
            waiter = self.ec2.get_waiter('volume_in_use')
            waiter.wait(VolumeIds=[newVolumeId])

        except Exception as e:
            logger.error(f"Error when attaching volume {str(e)}")
            raise

    def copyVolumeTags(self, sourceVolumeId: str, targetVolumeId: str) -> None:
        """
        Copies tags from the source volume to the target volume.

        Args:
            sourceVolumeId: ID of the source volume
            targetVolumeId: ID of the target volume
        """
        try:
            sourceVolume = self.retrieveVolumeInfo(sourceVolumeId)
            sourceTags = sourceVolume.get('Tags', [])

            if sourceTags:
                self.ec2.create_tags(
                    Resources=[targetVolumeId],
                    Tags=sourceTags
                )
                logger.info(f"Successfully copied tags to volume {targetVolumeId}")
        except Exception as e:
            logger.error(f"Error copying volume tags: {str(e)}")

def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda entry point for EBS encryption remediation.
    Triggered by the remediation scheduler when a remediation is due.
    """
    try:
        handler = EBSEncryptionRemediationHandler()
        return handler.ebsEncryptionRemediation(event)
    except Exception as e:
        logger.error(f"Error in lambda Handler for EBS encryption: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e)
            }
        }
                