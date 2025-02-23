# Utility class to manage AWS service clients via boto3
import boto3
import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
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

    def updateMisconfigurationStatus(self, tableName: str, resourceId: str, status: str) -> None:
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
            table = self.dynamodb.Table(tableName)
            table.update_item(
                Key={'ResourceID': resourceId},
                UpdateExpression='SET RemediationStatus = :status, LastUpdated = :timestamp',
                ExpressionAttributeValues={
                    ':status': status,
                    ':timestamp': datetime.now(timezone.utc)
                    }
            )
            logger.info(f"Successfully updated status for resource {resourceId} to {status}")
        except ClientError as e:
            logger.error(f"DynamoDB update failed for resource {resourceId}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating status: {str(e)}")
            raise

    def sendNotification(self, topicArn: str, message: Dict[str, Any]) -> None:
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
                TopicArn=topicArn,  # Correct parameter name is TopicArn
                Message=json.dumps(message)  # Correct parameter name is Message
            )
            logger.info(f"Successfully sent notification to {topicArn}")
        except ClientError as e:
            logger.error(f"SNS publish failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error sending notification: {str(e)}")
            raise

    def remediateS3PublicAccess(self, bucketName: str) -> Dict[str, Any]:
        """
        Remediates S3 bucket public access

        Args: 
            bucketName: Name of the s3 bucket to remediate

        Returns:
            Dictionary contsining remediation results
        """
        try:
            # Block public access
            self.s3.put_public_access_block(
                Bucket=bucketName,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            logger.info(f"Enabled block public access for bucket: {bucketName}")

            # Remove any public bucket policy
            try:
                self.s3.delete_bucket_policy(Bucket=bucketName)
                logger.info(f"Removed bucket policy from: {bucketName}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    raise

            self.s3.put_bucket_acl(
                Bucket=bucketName,
                ACL='private'
            )
            logger.info(f"Set bucket ACL to private: {bucketName}")

            return {
                'success': True,
                'message': 'Successfully blocked public access',
                'changes': [
                    'Enabled block public access',
                    'Removed public bucket policy',
                    'Set bucket ACL to private'
                ]
            }
        except Exception as e:
            logger.error(f"Failed to remediate bucket {bucketName}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
        
    def remediateS3Versioning(self, bucketName: str) -> Dict[str, Any]:
        """
        Enables versioning on S3 bucekt

        Args:
            bucketName: Name of S3 bucket

        Returns:
            Dictionary containing remediation results
        """

        try:
            self.s3.put_bucket_versioning(
                Bucket=bucketName,
                VersioningConfiguration={
                    'Status': 'Enabled'
                }
            )
            logger.info(f"Enabled versioning for bucket: {bucketName}")

            return {
                'success': True,
                'message': 'Successfully enabled bucket versioning',
                'changes': [
                    'Enabled bucket versioning'
                ]
            }
        except Exception as e:
            logger.error(f"Failed to enable versioning for bucket {bucketName}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
        
    def remediateEBSEncryption(self, volumeId: str) -> Dict[str, Any]:
        """
        Remediates unencrypted EBS volume by creating a encrypted copy

        Args:
            volumeId: ID of the EBS volume

        Returns:
            Dictionary containing remediation results
        """
        try:
            # Get volume details
            volume = self.ec2.describe_volumes(VolumesIds=[volumeId]['Volumes'][0])

            # create snapshot
            snapshotCreate = self.ec2.create_snapshot(
                VolumeId=volumeId,
                Description=f'Snapshot for encrypting voluume {volumeId}'
            )

            # wait until snapshot is complete
            waiter = self.ec2.get_waiter('snapshot completed')
            waiter.wait(SnapshotsIds=[snapshotCreate['SnapshotId']])

            # Create Encrypted volume
            newVolume = self.ec2.create_volume(
                SnapshotId=snapshotCreate['SnapshotId'],
                AvailabilityZone=volume['AvailabilityZone'],
                Encrypted=True
            )

            return {
                'success': True,
                'message': 'Successfully created encrypted volume',
                'changes': [
                    f"Created snapshot {snapshotCreate['SnapshotId']}",
                    f"Created encrypted volume {newVolume['VolumeId']}"
                ],
                'newVolumeId': newVolume['VolumeId']
            }
        except Exception as e:
            logger.error(f"Failed to encrypt volume {volumeId}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
    
    def remediateSecurityGroup(self, groupId: str) -> Dict[str, Any]:
        """
        Removes open SSH (port 22) from security group

        Args:
            groupId: ID of the security group

        Returns:
            Dictionary containing remediation results
        """

        try:
            # Get security group rules
            securityGroup = self.ec2.describe_security_groups(GroupIds=[groupId])['SecurityGroups']['0']

            rulesRemoved = []
            for rule in securityGroup['IpPermissions']:
                if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                    for ipRange in rule.get('IPRanges', []):
                        if ipRange.get('CidrIp') == '0.0.0.0/0':
                            self.ec2.revoke_security_group_ingress(
                                GroupId=groupId,
                                IpPermissions=[rule]
                            )
                            rulesRemoved.append(f"Removed SSH access from {ipRange['CidrIp']}")
            return {
                'success': True,
                'message': 'Successfully removed open SSH access',
                'changes': rulesRemoved
            }
        except Exception as e:
            logger.error(f"Failed to remediate security group {groupId}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
    
    def remediateKMSKeyRotation(self, keyId: str) -> Dict[str, Any]:
        """
        Enforces automatic key rotation for KMS keys

        Args:
            keyId: Id of the KMS key

        Returns: 
            Dictionary containing remediation results
        """
        try:
            self.kms.enable_key_rotation(KeyId=keyId)
            logger.info(f"Enabled key rotation for KMS key: {keyId}")

            return {
                'success': False,
                'message': str(e),
                'changes': ['Enabled automatic key rotation']
            }
        except Exception as e:
            logger.error(f"Failed to enable key rotation for {keyId}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
        
    def remediateDefaultSecurityGroup(self, vpcId: str) -> Dict[str, Any]:
        """
        Removes all the default security group rules

        Args:
            vpcId: ID of the VPC

        Returns:
            Dictionary containing remediation results
        """
        try: 
            # Get default security group
            securityGroups = self.ec2.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpcId]},
                    {'Name': 'group-name', 'Values': ['default']}
                ]
            ) ['SecurityGroups']

            if not securityGroups:
                 return {
                    'success': False,
                    'message': f"No default security group found for VPC {vpcId}",
                    'changes': []
                }
            
            groupId = securityGroups[0]['GroupId']
            changes = []

            # Remove ingress rule
            if securityGroups[0]['IpPermissions']:
                self.ec2.revoke_security_group_ingress(
                    GroupId=groupId,
                    IpPermissions=securityGroups[0]['IpPermissions']
                )
                changes.append('Removed all ingress rules')

            # remove egress rules
            if securityGroups[0]['IpPermissionsEgress']:
                self.ec2.revoke_security_group_egress(
                    GroupId=groupId,
                    IpPermissions=securityGroups[0]['IpPermissionsEgress']
                )
                changes.append('Removed all egress rules')

            return {
                'success': True, 
                'message': 'Successfully removed all default Security group rules', 
                'changes': changes
            }
        except Exception as e:
            logger.error(f"Failed to remediate default security group in VPC {vpcId}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
        
    def remediateRDSPublicAccess(self, dbInstanceIdentity: str) -> Dict[str, Any]:
        """
        Changes RDS instance to private access

        Args:
            dbInstanceIdentity: RDS instance identity

        Returns:
            Dictionary containing remediation results
        """
        try:
            self.rds.modify_db_instance(
                DBInstanceIdentifier=dbInstanceIdentity,
                PubliclyAccessiable=False
            )
            logger.info(f"Made RDS instance private: {dbInstanceIdentity}")

            return {
                'success': True,
                'message': 'Successfully made RDS instance private',
                'changes': ['Disabled public access']
            }
        
        except Exception as e:
            logger.error(f"Failed to make RDS instance private {dbInstanceIdentity}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }
        
    def remediateUnusedIAMRoles(self, roleName: str, keyLastUsedDaysLimit: int = 90):
        """
        Removes unused IAM role

        Args: 
            roleName: Name of the IAM role
            keyLastUsedDaysLimit: outlines the number of days of non-usage to identify role as no longer required

        Returns: 
            Dictionary containing remediation results
        """
        try:
            # Get role last used date
            lastUsed = self.iam.get_role(RoleName=roleName)['Role'].get('RoleLastUsed', {})

            if 'LastUsedDate' in lastUsed:
                daysSinceUse = (datetime.now(timezone.utc) - lastUsed['LastUsedDate'].replace(tzinfo=None)).days
                if daysSinceUse <= keyLastUsedDaysLimit:
                    return {
                        'success': False,
                        'message': f"Role was used {daysSinceUse} days ago, threshold is {keyLastUsedDaysLimit} days",
                        'changes': []
                    }
                
            #  Delete role policies
            for policy in self.iam.list_role_policies(RoleName=roleName)['PolicyNames']:
                self.iam.delete_role_policy(RoleName=roleName, PolicyName=policy)

            # Detach managed policies
            for policy in self.list_attached_role_polciies(RoleNAme=roleName)['AttachedPolicies']:
                self.iam.detach_role_policy(RoleName=roleName, PolicyArn=policy['PolicyArn'])

            # Delete role
            self.iam.delete_role(RoleName=roleName)
            logger.info(f"Deleted unused IAM role: {roleName}")

            return {
                'success': True,
                'message': 'Successfully deleted unused IAM role',
                'changes': ['Deleted role policies', 'Detached managed policies', 'Deleted role']
            }
        except Exception as e:
            logger.error(f"Failed to delete unused IAM role {roleName}: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'changes': []
            }