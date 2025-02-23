import json
import logging
from typing import Dict, Any, List
from dbHandler import DbHandler
from awsUtils import AWSServiceHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class ScheduledRemediationsHandler:
    """
    Handles retrieval of scheduled remediation data.
    Provides search functionality and detailed finding information.
    """
    
    def __init__(self):
        self.dbHandler = DbHandler()
        self.awsHandler = AWSServiceHandler()

    def getScheduledRemediations(self, searchParams: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Gets all scheduled remediations with optional search filtering.
        Combines data from RemediationActions and MisconfiguredResources tables
        to provide complete information for the frontend.
        """
        try:
            # Get scheduled remediations
            response = self.dbHandler.remediationTable.query(
                IndexName='StatusTimeIndex',
                KeyConditionExpression='RemediationStatus = :status',
                ExpressionAttributeValues={
                    ':status': 'SCHEDULED'
                }
            )
            
            scheduledItems = response.get('Items', [])
            enhancedItems = []

            # Enhance each remediation with additional details
            for item in scheduledItems:
                # Get associated misconfiguration details
                misconfigResponse = self.dbHandler.misconfigTable.get_item(
                    Key={'ResourceID': item['ResourceID']}
                )
                misconfigDetails = misconfigResponse.get('Item', {})

                # Create enhanced item with all needed frontend information
                enhancedItem = {
                    'cloudType': misconfigDetails.get('ServiceType'),
                    'instanceName': item['ResourceID'],
                    'originators': misconfigDetails.get('DetectedBy'),
                    'findingSeverity': misconfigDetails.get('SeverityID'),
                    'timeToRemediate': item['StartTime'],
                    'complianceId': item['ComplianceID'],
                    'findingDetails': misconfigDetails
                }

                # Apply search filtering if params provided
                if self.matchesSearchCriteria(enhancedItem, searchParams):
                    enhancedItems.append(enhancedItem)

            return enhancedItems

        except Exception as e:
            logger.error(f"Error retrieving scheduled remediations: {str(e)}")
            raise

    def matchesSearchCriteria(self, item: Dict[str, Any], searchParams: Dict[str, str]) -> bool:
        """
        Checks if an item matches the provided search criteria.
        """
        if not searchParams:
            return True

        searchTerm = searchParams.get('searchTerm', '').lower()
        if not searchTerm:
            return True

        # Search across relevant fields
        searchableFields = [
            str(item.get('instanceName', '')),
            str(item.get('cloudType', '')),
            str(item.get('findingSeverity', '')),
            str(item.get('originators', ''))
        ]

        return any(searchTerm in field.lower() for field in searchableFields)
    
def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for retrieving scheduled remediations data.
    Supports search functionality through query parameters.
    """
    try:
        # Extract search parameters from the event
        searchParams = event.get('queryStringParameters', {})
        
        handler = ScheduledRemediationsHandler()
        scheduledRemediations = handler.getScheduledRemediations(searchParams)

        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': 'http://localhost:3000',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'GET'
            },
            'body': json.dumps(scheduledRemediations)
        }
        
    except Exception as e:
        logger.error(f"Scheduled remediations API error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }