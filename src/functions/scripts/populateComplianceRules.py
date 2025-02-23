import boto3
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
        """Populate the compliance rules table with the four core CIS rules we're implementing"""
        complianceRules = [
            # 1) S3 Public Access Rule (CIS-2.1.5)
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
            
            # 2) EBS Encryption Rule (CIS-2.2.1)
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

            # 3) Default VPC Security Group Rule (CIS-4.2)
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

            # 4) Block Public RDS Rule (CIS-2.3.2)
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
            }
        ]

        # Write rules to DynamoDB
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

            # Print summary of each rule
            for rule in rules:
                logger.info(f"Rule {rule['ComplianceID']}: {rule['Title']} - {rule['RiskLevel']}")
            return rules
        except ClientError as e:
            logger.error(f"Error verifying rules: {str(e)}")
            raise

def main():
    """
    This function is used for direct execution (e.g., python populateComplianceRules.py).
    """
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
        logger.error(f"AWS error occurred: {str(e)}")
        raise

def lambdaHandler(event, context):
    """
    AWS Lambda entry point.
    If your SAM template references `populateComplianceRules.lambdaHandler`,
    Lambda calls this function.
    """
    main()

if __name__ == "__main__":
    main()
