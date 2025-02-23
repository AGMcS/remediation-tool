import os
import json
import logging
import boto3
from typing import Dict, Any, List
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class EventBridgeRuleCreation:

    """
    Creates and manages EventBridge rules based on compliance definitions stored in DynamoDB.
    Each rule monitors specific AWS API calls that might indicate compliance violations and
    triggers the appropriate remediation Lambda function.
    """

    def __init__(self):
        """ Initalise AWS service clients and load configuration """
        self.dynamodb = boto3.resource('dynamodb')
        self.events = boto3.client('events')
        self.lambdaClient = boto3.client('lambda')

        # Get environment Variables
        self.complianceTableName = os.environ['COMPLIANCE_TABLE_NAME']
        self.lambdaMapping = json.loads(os.environ['LAMBDA_MAPPING'])

        #Intialise DynamoDb table reference
        self.complianceTable = self.dynamodb.Table(self.complianceTableName)

    def getComplianceRules(self) -> List[Dict[str, Any]]:
        """
        Retrieves all compliance rules from DynamoDB.
        
        Returns:
            List of compliance rule definitions
            
        Raises:
            ClientError: If DynamoDB operation fails
        """

        try:
            response = self.complianceTable.scan()
            rules = response.get('Items', [])
            logger.info(f"Retrieved {len(rules)} compliance rules from DynamoDB")
            return rules
        except ClientError as e:
            logger.error(f"Failed to retrieve compliance rules: {str(e)}")
            raise

    def createEventPattern(self, detectionPattern: Dict[str, Any]) -> Dict[str, Any]:
        """
         Converts a compliance rule detection pattern into an EventBridge rule pattern.
        
        Args:
            detectionPattern: The detection pattern from compliance rule
            
        Returns:
            EventBridge compatible event pattern
        """

        # build base pattern structure
        pattern = {
            "source": [f"aws.{detectionPattern['EventSource'].split('.')[0]}"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": [detectionPattern["EventSource"]],
                "eventName": detectionPattern["EventName"] if isinstance(detectionPattern["EventName"], list)
                else [detectionPattern["EventName"]]
            }
        }

        # Add Evaluation criteria if present !!!!!! MAY BE ABLE TO REMOVE!!!!!!!
        if "EvaluationCriteria" in detectionPattern:
            criteria = detectionPattern["EvaluationCriteria"]

            # Handle different types of criteria
            if criteria.get("Parameter"):
                if criteria.get("ExpectedValue") == "NOT_NULL":
                    pattern["detail"]["requestParameters"] = {
                        criteria["Parameter"]: [{"exists": True}]
                    }
                elif criteria.get("ExpectedValue") == "NOT_*":
                    pattern["detail"]["requestParameters"] = {
                        criteria["Parameter"]: [{"anything-but": "*"}]
                    }
                elif isinstance(criteria.get("ExpectedValue"), bool):
                    pattern["detail"]["requestParameters"] = {
                        criteria["Parameter"]: [criteria["ExpectedValue"]]
                    }
                else:
                    pattern["detail"]["requestParameters"] = {
                        criteria["Parameter"]: [criteria["ExpectedValue"]]
                    }

            # Handle port-specific criteria (for security group rules)
            if criteria.get("Ports"):
                pattern["detail"]["requestParameters"]["fromPort"] = criteria["Ports"]

        return pattern
    
    def createOrUpdateRules(self, compilanceRule: Dict[str, Any]) -> None:
        """
        Creates or updates an EventBridge rule for a compliance rule.
        
        Args:
            complianceRule: The compliance rule definition
            
        Raises:
            ClientError: If EventBridge or Lambda operations fail
        """
        try:
            complianceID = compilanceRule['ComplianceID']
            serviceType = compilanceRule['ServiceType']

            # Get associated Lambda Arn
            lambdaArn = self.lambdaMapping.get(complianceID)
            if not lambdaArn:
                logger.warning(f"No Lambda ARN mapped for ComplianceID '{complianceID}'. Skipping.")
                return
            
            # Create rule name
            ruleName = f"Compliance-{serviceType}-{complianceID}"

            # Create event pattern
            eventPattern = self.createEventPattern(compilanceRule['DetectionPattern'])

            # Create or update the rule
            logger.info(f"Creating/updating EventBridge rule: {ruleName}")
            self.events.put_rule(
                Name =ruleName,
                Description=f"Compliance rule for {compilanceRule.get('Title', 'N/A')}",
                EventPattern=json.dumps(eventPattern),
                State='ENABLED'
            )

            # Create Target input template
            targetInput = {
                'complianceId': complianceID,
                'serviceType': serviceType,
                'riskLevel': compilanceRule.get('RiskLevel'),
                'title': compilanceRule.get('Title'),
                'description': compilanceRule.get('Description')
            }

            #Add lambda target
            logger.info(f"Setting Lambda target for rule: {ruleName}")
            self.events.put_targets(
                Rule=ruleName,
                Targets=[{
                    'Id': f"{ruleName}-target",
                    'Arn': lambdaArn,
                    'Input': json.dumps(targetInput)
                }]
            )

            # Add Lambda permissions for EventBridge
            try:
                region = lambdaArn.split(":")[3]
                accountId = lambdaArn.split(":")[4]

                self.lambdaClient.add_permission(
                    FunctionName=lambdaArn,
                    StatementId=f"{ruleName}-permission",
                    Action='lambda:InvokeFunction',
                    Principal='events.amazonaws.com',
                    SourceArn=f"arn:aws:events:{region}:{accountId}:rule/{ruleName}"
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceConflictException':
                    raise

            logger.info(f"Successfully created/updated rule and target for {complianceID}")
            
        except ClientError as e:
            logger.error(f"Failed to create/update rule for {complianceID} : {str(e)}")
            raise

    def processAllRules(self) -> None:
        """
        Process all compliance rules and create corresponding EventBridge rules.
        """  
        rules = self.getComplianceRules()
        for rule in rules:
            try:
                self.createOrUpdateRules(rule)
            except Exception as e:
                logger.error(f"Error processing rule {rule.get('ComplianceID')}: {str(e)}")
                continue
    
def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda entry point for creating EventBridge rules.
    """
    try:
        creator = EventBridgeRuleCreation()
        creator.processAllRules()

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully created/updated EventBridge rules'
            })
        }
    except Exception as e:
        logger.error(f"Error in lambdaHandler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }              