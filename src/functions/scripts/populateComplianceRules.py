import boto3
import json
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceRulePopulator:
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table('ComplianceDefinitions')

    def populateRules(self):
        """Populate the compliance rules table with predefined CIS rules"""
        # Define the compliance rules
        complianceRules = [
            # 1) S3 Encryption Rule
            {
                "ServiceType": "S3",
                "ComplianceID": "CIS-2.1.5",
                "Title": "S3 Bucket Public Access",
                "Description": "Block public access to S3 buckets",
                "RiskLevel": "CRITICAL",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Storage",
                    "SubCategory": "Access Control",
                },
                "DetectionPattern": {
                    "EventSource": "s3.amazonaws.com",
                    "EventName": ["CreateBucket", "PutBucketPolicy"],
                    "EvaluationCriteria": {
                        "Parameter": "PublicAccess",
                        "ExpectedValue": False,
                        "EvaluationType": "BOOLEAN"
                    }
                },
                "RemediationSteps": [
                    "Enable block public access settings",
                    "Remove public bucket policies",
                    "Remove public ACLs"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": False
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },
            # 2) S3 Versioning Rule
            {
                "ServiceType": "S3",
                "ComplianceID": "CIS-2.1.6",
                "Title": "S3 Versioning",
                "Description": "Ensure S3 bucket versioning is enabled",
                "RiskLevel": "HIGH",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Storage",
                    "SubCategory": "Data Protection"
                },
                "DetectionPattern": {
                    "EventSource": "s3.amazonaws.com",
                    "EventName": ["CreateBucket", "PutBucketVersioning"],
                    "EvaluationCriteria": {
                        "Parameter": "VersioningConfiguration.Status",
                        "ExpectedValue": "Enabled"
                    }
                },
                "RemediationSteps": [
                    "Check current versioning status",
                    "Enable versioning on the bucket",
                    "Verify versioning status after update"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": False,
                    "RequiresApproval": False
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },
            # 3) EBS Encryption Rule
            {
                "ServiceType": "EC2",
                "ComplianceID": "CIS-2.2.1",
                "Title": "EBS Volume Encryption",
                "Description": "Ensure EBS volumes are encrypted at rest using AWS KMS keys",
                "RiskLevel": "HIGH",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Storage",
                    "SubCategory": "Encryption"
                },
                "DetectionPattern": {
                    "EventSource": "ec2.amazonaws.com",
                    "EventName": "CreateVolume",
                    "EvaluationCriteria": {
                        "Parameter": "Encrypted",
                        "ExpectedValue": True,
                        "EvaluationType": "BOOLEAN"
                    }
                },
                "RemediationSteps": [
                    "Create snapshot of unencrypted volume",
                    "Create new encrypted volume from snapshot",
                    "Attach encrypted volume to instance",
                    "Delete original unencrypted volume"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": ["KmsKeyAvailable"],
                    "RollbackSupported": True,
                    "RequiresApproval": False
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },
            # 4) Security Group Rule
            {
                "ServiceType": "EC2",
                "ComplianceID": "CIS-4.1",
                "Title": "Security Group Ingress",
                "Description": "Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
                "RiskLevel": "CRITICAL",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Network Security",
                    "SubCategory": "Access Control"
                },
                "DetectionPattern": {
                    "EventSource": "ec2.amazonaws.com",
                    "EventName": ["AuthorizeSecurityGroupIngress"],
                    "EvaluationCriteria": {
                        "Parameter": "IpRanges",
                        "ExpectedValue": "NOT_0.0.0.0/0",
                        "Ports": [22]
                    }
                },
                "RemediationSteps": [
                    "Identify security group with open SSH access",
                    "Document existing rules for rollback if needed",
                    "Remove 0.0.0.0/0 ingress rule for port 22",
                    "Verify rule removal and security group update"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": True
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },
            # 5) KMS Key Rotation Rule
            {
                "ServiceType": "KMS",
                "ComplianceID": "CIS-2.8",
                "Title": "KMS Key Rotation",
                "Description": "Ensure rotation for customer created CMKs is enabled",
                "RiskLevel": "MEDIUM",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Encryption",
                    "SubCategory": "Key Management"
                },
                "DetectionPattern": {
                    "EventSource": "kms.amazonaws.com",
                    "EventName": ["CreateKey", "DisableKeyRotation"],
                    "EvaluationCriteria": {
                        "Parameter": "KeyRotationEnabled",
                        "ExpectedValue": True
                    }
                },
                "RemediationSteps": [
                    "Identify KMS key without rotation enabled",
                    "Enable automatic key rotation",
                    "Verify rotation setting is active"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": False
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },
            # 5) Restrict traffic to default security group Rule
           {
                "ServiceType": "EC2",
                "ComplianceID": "CIS-4.2",
                "Title": "Default VPC Security Group",
                "Description": "Ensure the default security group restricts all traffic",
                "RiskLevel": "HIGH",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Network Security",
                    "SubCategory": "Default Configuration"
                },
                "DetectionPattern": {
                    "EventSource": "ec2.amazonaws.com",
                    "EventName": ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"],
                    "EvaluationCriteria": {
                        "Parameter": "GroupName",
                        "ExpectedValue": "default",
                        "AdditionalCheck": "HasPermissions"
                    }
                },
                "RemediationSteps": [
                    "Identify default security group rules",
                    "Remove all inbound and outbound rules",
                    "Verify no traffic is allowed",
                    "Document changes for compliance"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": False
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },

            # 6) Block Public RDS Rule
            {
                "ServiceType": "RDS",
                "ComplianceID": "CIS-2.3.2",
                "Title": "RDS Public Access",
                "Description": "Ensure RDS instances are not publicly accessible",
                "RiskLevel": "CRITICAL",
                "Framework": {
                    "Name": "CIS",
                    "Version": "1.4.0",
                    "Category": "Database Security",
                    "SubCategory": "Access Control"
                },
                "DetectionPattern": {
                    "EventSource": "rds.amazonaws.com",
                    "EventName": ["CreateDBInstance", "ModifyDBInstance"],
                    "EvaluationCriteria": {
                        "Parameter": "PubliclyAccessible",
                        "ExpectedValue": False
                    }
                },
                "RemediationSteps": [
                    "Identify publicly accessible RDS instance",
                    "Modify instance to disable public access",
                    "Update security group rules if needed",
                    "Verify instance is no longer publicly accessible"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": True
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },
            # 7) Remove unused IAM roles Rule
            {
                "ServiceType": "IAM",
                "ComplianceID": "SEC-1.8",
                "Title": "IAM Role Last Used",
                "Description": "Ensure unused IAM roles are identified and removed",
                "RiskLevel": "MEDIUM",
                "Framework": {
                    "Name": "Security Best Practices",
                    "Version": "1.0.0",
                    "Category": "Access Management",
                    "SubCategory": "Role Cleanup"
                },
                "DetectionPattern": {
                    "EventSource": "iam.amazonaws.com",
                    "EventName": ["GenerateServiceLastAccessedDetails"],
                    "EvaluationCriteria": {
                        "Parameter": "LastUsedDate",
                        "ExpectedValue": "90",
                        "Comparison": "DaysNotUsed"
                    }
                },
                "RemediationSteps": [
                    "Identify unused roles",
                    "Document role configurations",
                    "Remove unused roles",
                    "Update dependencies"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": False,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": True
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            },

            # 8) Remove unused Security Groups Rule
            {
                "ServiceType": "EC2",
                "ComplianceID": "SEC-2.4",
                "Title": "Security Group Unused",
                "Description": "Ensure unused security groups are identified and removed",
                "RiskLevel": "LOW",
                "Framework": {
                    "Name": "Security Best Practices",
                    "Version": "1.0.0",
                    "Category": "Network Security",
                    "SubCategory": "Resource Cleanup"
                },
                "DetectionPattern": {
                    "EventSource": "ec2.amazonaws.com",
                    "EventName": ["DescribeSecurityGroups"],
                    "EvaluationCriteria": {
                        "Parameter": "References",
                        "ExpectedValue": "0",
                        "Comparison": "Equals"
                    }
                },
                "RemediationSteps": [
                    "Identify security groups with no references",
                    "Document group configurations",
                    "Remove unused groups",
                    "Verify no impacts"
                ],
                "AutomationConfig": {
                    "CanAutoRemediate": True,
                    "PreRequisites": [],
                    "RollbackSupported": True,
                    "RequiresApproval": False
                },
                "LastUpdated": datetime.now(timezone.utc).isoformat()
            }
        ]

        #Write rules to DynamoDB
        for rule in complianceRules:
            try:
                self.table.put_item(Item=rule)
                logger.info(f"Successfully added compliance rule: {rule['ComplianceID']}")
            except ClientError as e:
                logger.error(f"Error adding compliance rule {rule['ComplianceID']}: {str(e)}")
                raise

    def verifyRules(self):
        """Verify that rules were properly written to the table"""
        try:
            response = self.table.scan()
            rules = response['Items']
            logger.info(f"Found {len(rules)} compliance rules in the table")

            # print summary of each Rule
            for rule in rules:
                logger.info(f"Rule {rule['ComplianceID']}: {rule['Title']} - {rule['RiskLevel']}")

            return rules
        except ClientError as e:
            logger.error(f"Error verifying rules: {str(e)}")
            raise
    
def main():
    try:
        populator = ComplianceRulePopulator()

        # Populate the rules
        logger.info("Starting compliance rule population...")
        populator.populateRules()

        # Check rules were written
        logger.info("Verifying compliance rules...")
        populator.verifyRules()

        logger.info("Compliance rule population completed successfully!")
    except Exception as e:
            logger.error(f"Aws error occurred: {str(e)}")
            raise

if __name__ == "__main__":
     main()