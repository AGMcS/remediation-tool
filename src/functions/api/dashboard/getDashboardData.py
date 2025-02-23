import json
import logging
from typing import Dict, Any
from dbHandler import DbHandler
from awsUtils import AWSServiceHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DashboardDataHandler:
    """
    Handles retrieval and formatting of dashboard data.
    Uses existing DbHandler methods for database operations.
    """
    
    def __init__(self):
        self.dbHandler = DbHandler()
        self.awsHandler = AWSServiceHandler()

    def getOpenFindings(self) -> Dict[str, Any]:
        """
        Gets current open findings from MisconfiguredResources table
        """
        try:
            # Using your existing table structure
            response = self.dbHandler.misconfigTable.query(
                IndexName='StatusTimeIndex',
                KeyConditionExpression='RemediationState = :state',
                ExpressionAttributeValues={
                    ':state': 'DETECTED'
                }
            )
            
            openFindings = response.get('Items', [])
            
            # Group by severity
            severityCounts = {}
            for finding in openFindings:
                severity = finding.get('SeverityID', 'UNKNOWN')
                severityCounts[severity] = severityCounts.get(severity, 0) + 1

            return {
                'totalOpen': len(openFindings),
                'bySeverity': severityCounts,
                'findings': openFindings
            }
        except Exception as e:
            logger.error(f"Error getting open findings: {str(e)}")
            raise

    def getCompletedRemediations(self) -> Dict[str, Any]:
        """
        Gets completed remediation data from CompletedRemediations table
        """
        try:
            response = self.dbHandler.completedTable.scan()
            completedRemediations = response.get('Items', [])

            return {
                'total': len(completedRemediations),
                'remediations': completedRemediations
            }
        except Exception as e:
            logger.error(f"Error getting completed remediations: {str(e)}")
            raise

def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for dashboard data API endpoint
    """
    try:
        handler = DashboardDataHandler()
        
        dashboardData = {
            'openFindings': handler.getOpenFindings(),
            'completedRemediations': handler.getCompletedRemediations()
        }

        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': 'http://localhost:3000',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'GET'
            },
            'body': json.dumps(dashboardData)
        }
        
    except Exception as e:
        logger.error(f"Dashboard API error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }