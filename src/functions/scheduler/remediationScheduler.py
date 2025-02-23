import boto3
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any
from dbHandler import DbHandler
from notificationHandler import NotificationHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class RemediationScheduler:
    """
    A scheduler to schedule remediation actions depending on severity.
    Performs a check any remediations due and then executes appropiate remediaiton lambda.
    """

    def __init__(self):
        """ Intialises handlers and AWS services"""
        self.dbHandler = DbHandler()
        self.notificationHandler = NotificationHandler()
        self.LambdaClient = boto3.client('lambda')

        # Map all compliances IDs to their associated Lambda ARN
        self.remediationMap = {
            'CIS-2.1.5': os.environ['REMEDIATION_LAMBDA_S3_ENCRYPTION'],
            'CIS-2.1.6': os.environ['REMEDIATION_LAMBDA_S3_VERSIONING'],
            'CIS-2.2.1': os.environ['REMEDIATION_LAMBDA_EBS_ENCRYPTION'],
            'CIS-4.1': os.environ['REMEDIATION_LAMBDA_SECURITY_GROUP'],
            'CIS-2.8': os.environ['REMEDIATION_LAMBDA_KMS_ROTATION'],
            'CIS-4.2': os.environ['REMEDIATION_LAMBDA_DEFAULT_SG'],
            'CIS-2.3.2': os.environ['REMEDIATION_LAMBDA_RDS_PUBLIC'],
            'SEC-1.8': os.environ['REMEDIATION_LAMBDA_UNUSED_IAM']
        }
        
    def processScheduledRemediatiom(self) -> Dict[str, Any]:
        """
        Calls to remediation actions to execute remediaiton.
        Checks db for remediations that are due and trigger associated lambda
        """
        try:
            # Retrieve pending remediations
            pendingRemediations = self.dbHandler.getPendingRemediations()

            successfulCount = 0
            failedCount = 0
            results = []

            for remediation in pendingRemediations:
                try:
                    # Get remediaiton details
                    remediationId = remediation['RemediationID']
                    resourceId = remediation['ResourceID']
                    complianceId = remediation['ComplianceID']

                    # update the status attritbute in the table
                    self.dbHandler.updateRemediationStatus(
                        remediation_id = remediationId,
                        status='IN_PROGRESS',
                        details={'startTime': datetime.now(timezone.utc).isoformat()}
                    )

                    # Get the appropriate Lambda ARN
                    remediationLambda = self.remediationMap.get(complianceId)
                    if not remediationLambda:
                        raise ValueError(f"No remediation Lambda found for compliance ID: {complianceId}")

                    # Prepare the event for the remediation Lambda
                    event = {
                        'remediationId': remediationId,
                        'resourceId': resourceId,
                        'complianceId': complianceId,
                        'scheduledTime': remediation['StartTime']
                    }

                    # Invoke the remediation Lambda
                    logger.info(f"Invoking remediation Lambda for {remediationId}")
                    response = self.lambda_client.invoke(
                        FunctionName=remediationLambda,
                        InvocationType='Event',  # Asynchronous invocation
                        Payload=json.dumps(event)
                    )

                    if response['StatusCode'] == 202:  # Successfully queued
                        processed_count += 1
                        results.append({
                            'remediationId': remediationId,
                            'status': 'TRIGGERED',
                            'lambda': remediationLambda
                        })
                    else:
                        failed_count += 1
                        logger.error(f"Failed to trigger remediation {remediationId}: Code {response['StatusCode']}")
                
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error processing remediation {remediationId}: {str(e)}")
                    # Update status to FAILED
                    self.dbHandler.updateRemediationStatus(
                        remediation_id=remediationId,
                        status='FAILED',
                        details={
                            'error': str(e),
                            'failureTime': datetime.now(timezone.utc).isoformat()
                        }
                    )
            return {
                'statusCode': 200,
                'body': {
                    'message': 'Completed remediation scheduling',
                    'processed': successfulCount,
                    'failed': failedCount,
                    'results': results
                }
            }
        except Exception as e:
            logger.error(f"Error in remediation scheduler: {str(e)}")
            return {
                'statusCode': 500,
                'body': {
                    'error': str(e)
                }
            }
        
def lambdaHandler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda will be triggered by EventBridge rule every 5 minutes
    """
    try:
        remediationScheduler = RemediationScheduler()
        return remediationScheduler.processScheduledRemediatiom()
    except Exception as e:
        logger.error(f"Error in lambdaHandler: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e)
            }
        }