# interface to react with AWS DynamoDB
from typing import List, Dict, Any
import logging
from ..common.awsUtils import AWSServiceHandler

# set up logger
logger = logging.getLogger(__name__)

class DynamoDBService:
    # Creates an instance of AWSServiceManager to access AWS services.
    # Retrieves a DynamoDB resource using aws_manager.get_dynamodb_resource()
    # Accesses the ComplianceDefinitions table using self.dynamodb.Table()
    def __init__(self):
        awsHandler = AWSServiceHandler()
        self.dynamodb = awsHandler.getDynamoDBResources()
        self.complianceTable = self.dynamodb.Table('ComplianceDefinitions')

    def getComplianceRules(self) -> List[Dict[str, Any]]:
        """Retrieve compliance rules from DynamoDB"""
        try:
            response = self.complianceTable.scan()
            return response.get('Items', [])
        except Exception as e:
            logger.error(f"Error retrieving compliance rules: {str(e)}")
            raise