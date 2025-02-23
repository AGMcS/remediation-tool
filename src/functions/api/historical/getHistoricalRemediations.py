import json
import logging
from typing import Dict, Any, List
from dbHandler import DbHandler
from awsUtils import AWSServiceHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class HistoricalRemediationsHandler:
    """
    Handles retrieval of historical remediation data.
    Combines information from multiple tables to provide complete remediation history.
    """
    
    def __init__(self):
        self.dbHandler = DbHandler()
        self.awsHandler = AWSServiceHandler()

    def getHistoricalRemediations(self) -> List[Dict[str, Any]]:
        """
        Retrieves completed remediation history with full details about each remediation.
        Combines data from CompletedRemediations, RemediationActions, and MisconfiguredResources tables.
        """
        try:
            # Get all completed remediations
            response = self.dbHandler.completedTable.scan()
            completedItems = response.get('Items', [])
            historicalData = []

            for item in completedItems:
                # Get original remediation details
                remediationResponse = self.dbHandler.remediationTable.get_item(
                    Key={'RemediationID': item['RemediationID']}
                )
                remediationDetails = remediationResponse.get('Item', {})

                # Get resource details from misconfiguration
                resourceId = remediationDetails.get('ResourceID')
                if resourceId:
                    misconfigResponse = self.dbHandler.misconfigTable.get_item(
                        Key={'ResourceID': resourceId}
                    )
                    misconfigDetails = misconfigResponse.get('Item', {})

                    # Create comprehensive historical record
                    historicalRecord = {
                        'instanceName': resourceId,
                        'originators': misconfigDetails.get('DetectedBy'),
                        'owner': misconfigDetails.get('ResourceOwner'),
                        'remediationDate': item['CompletionTimestamp'],
                        'status': 'Success' if item.get('Success') else 'Failed',
                        'serviceType': misconfigDetails.get('ServiceType'),
                        'complianceId': remediationDetails.get('ComplianceID'),
                        'details': item.get('Details', {}),
                        'severity': misconfigDetails.get('SeverityID')
                    }

                    historicalData.append(historicalRecord)

            return historicalData

        except Exception as e:
            logger.error(f"Error retrieving historical remediations: {str(e)}")
            raise

def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for retrieving historical remediation data.
    Provides comprehensive history of completed remediations.
    """
    try:
        handler = HistoricalRemediationsHandler()
        historicalRemediations = handler.getHistoricalRemediations()

        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': 'http://localhost:3000',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'GET'
            },
            'body': json.dumps(historicalRemediations)
        }
        
    except Exception as e:
        logger.error(f"Historical remediations API error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }