import json
import os
import time
from datetime import datetime
from distutils.util import strtobool

import boto3
import cfnresponse
import jmespath
from aws_lambda_powertools import Logger

logger = Logger()

PERMISSION_CHECK = strtobool(os.getenv("PERMISSION_CHECK", "True"))

AWS_ACCOUNT_ID = boto3.client("sts").get_caller_identity()["Account"]


def error_handler(func):
    """Ensure that unexpected error handling returns a FAILED to CloudFormation
    and does not timeout"""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(e)
            cfnresponse.send(args[0], args[1], cfnresponse.FAILED, {}, reason=e)
            return None

    return wrapper


def invoke_api(action: str, service: str, region: str, parameters: dict, query: str):
    """
    This function invokes an AWS API, filter results using JMESPath expression
    and return the filtered results
    Parameters:
        action (str):  API Operation to invoke
        service(str) : AWS Service
        region (str) : AWS Region where the call should be made
        parameters (dict): Optional parameters to the API call
        query (str): JMESPath compatible query to filter results out.
    Returns:
        JMESPath filtered result. If the result is a string then it is a dict with a key
        named Result: string else it keeps its format
    """
    client = boto3.client(service, region_name=region)
    _response = client._make_api_call(action, parameters)
    logger.info(_response)
    if query:
        _temp = jmespath.search(query, _response)
        logger.info(_temp)
        if type(_temp) == dict or type(_temp) == list:
            return _temp
        else:
            return {"Result": _temp}
    else:
        return _response


def eval_permission_status(caller_arn: str, service: str, action: str) -> bool:
    """
    This function invoke IAM policy simulator to check if a specific IAM Role is allowed
     to perform the API call
    Parameters:
        caller_arn (str): ROLE ARN to test
        service (str): AWS Service
        action (str): Operation on the AWS service
    Returns:
        True if the role ARN is allowed else False

    """
    logger.info("Using policy simulator to validate user has the right to call the API")
    iam_client = boto3.client("iam")
    response = iam_client.simulate_principal_policy(
        PolicySourceArn=caller_arn, ActionNames=[f"{service}:{action}"]
    )
    logger.info(response)
    if response["EvaluationResults"][0]["EvalDecision"] == "allowed":
        logger.info(f"Access granted for api {service}:{action}")
        return True
    logger.info(f"Access denied for api {service}:{action}")
    return False


def get_caller_arn(
    event_name: str, resource_name: str, timestamp: datetime = datetime(2023, 1, 1)
):
    """
    This function looks up CloudTrail events to find who triggered a CloudFormation change
    Parameters:
        event_name (str): Name of the event to lookup based on the payload from CloudFormation
        resource_name (str): Name of the CloudFormation Stack to filter CloudTrail results
        timestamp (str): Beginning time of the lookup
    Returns:
        ARN (str) who triggered the CloudFormation action
    """
    logger.info("Searching the CloudFormation initiator ARN.")
    client = boto3.client("cloudtrail")
    _response = client.lookup_events(
        LookupAttributes=[
            {"AttributeKey": "ResourceName", "AttributeValue": resource_name},
        ],
        StartTime=timestamp,
    )
    if event_name == "Create":
        jmespath_query = (
            "Events[?EventName=='CreateStack'||EventName=='ExecuteChangeSet']"
        )
    elif event_name == "Update":
        jmespath_query = (
            "Events[?EventName=='UpdateStack'||EventName=='ExecuteChangeSet']"
        )
    events = jmespath.search(jmespath_query, _response)
    if events:
        cloudtrail_event = json.loads(events[0]["CloudTrailEvent"])
        return cloudtrail_event["userIdentity"]["sessionContext"]["sessionIssuer"][
            "arn"
        ]
    return None


def get_stack_infos(
    stack_id: str, request_type: str
) -> tuple[str, str, datetime | None]:
    """
    This function invokes CloudFormation API to retrieve stack details
    Parameters:
        stack_id (str): Name or ID of the CloudFormation Stack
        request_type (str): CloudFormation Event which invoked Lambda

    Returns:
        The role ARN (str) associated with the Stack, the changeset Id (str) and the timestamp (datetime)
    """
    logger.info("getting stackset role, changeset and timestamp")
    event_name = (
        "CREATE_IN_PROGRESS" if request_type == "Create" else "UPDATE_IN_PROGRESS"
    )
    event_timestamp = None
    cfn = boto3.resource("cloudformation")
    stack = cfn.Stack(stack_id)
    for event in stack.events.all():
        if (
            event.logical_resource_id == stack_id.split("/")[1]
            and event.resource_status_reason == "User Initiated"
            and event.resource_status == event_name
        ):
            event_timestamp = event.timestamp
    return stack.role_arn, stack.change_set_id, event_timestamp


@logger.inject_lambda_context(log_event=True)
@error_handler
def lambda_handler(event: dict, context):
    response = {}
    if (
        "Action" not in event["ResourceProperties"]
        or "Service" not in event["ResourceProperties"]
    ):
        logger.error("Missing mandatory properties Action or Service")
        cfnresponse.send(event, context, cfnresponse.FAILED, response)
        return
    if event["RequestType"] in ["Create", "Update"]:
        action = event["ResourceProperties"]["Action"]
        service = event["ResourceProperties"]["Service"]
        region = event["ResourceProperties"].get("Region", os.getenv("AWS_REGION"))
        parameters = event["ResourceProperties"].get("Parameters")
        query = event["ResourceProperties"].get("Query")

        # Handles the logic if the Lambda must check the permissions of the role 
        # deploying the CloudFormation template.
        if PERMISSION_CHECK:
            caller_arn, changeset_id, event_timestamp = get_stack_infos(
                event["StackId"], event["RequestType"]
            )
            stack_id = event["StackId"]
            # we don't want an infinite loop...
            counter = 10
            if not caller_arn and changeset_id:
                stack_id = event["StackId"].split("/")[1]

            while not caller_arn and counter > 0:
                caller_arn = get_caller_arn(
                    event["RequestType"], stack_id, event_timestamp
                )
                counter += -1
                time.sleep(15)

            if not caller_arn:
                logger.error("Unable to find calling user from CloudTrail")
                cfnresponse.send(event, context, cfnresponse.FAILED, response)
                return
            if eval_permission_status(caller_arn, service, action):
                response = invoke_api(action, service, region, parameters, query)
                cfnresponse.send(event, context, cfnresponse.SUCCESS, response)
                return
            else:
                logger.error(
                    "User is not allowed to perform the action or the CloudTrail did not yet return an event"
                )
                cfnresponse.send(event, context, cfnresponse.FAILED, response)
                return
        else:
            response = invoke_api(action, service, region, parameters, query)
            cfnresponse.send(event, context, cfnresponse.SUCCESS, response)
            return

    # If the request is DELETE then do nothing and return SUCCESS
    elif event["RequestType"] == "Delete":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, response)
        return

    # If the request type is not known, then FAILED
    else:
        logger.error(f"Unknown request type {event['RequestType']}")
        cfnresponse.send(event, context, cfnresponse.FAILED, response)
        return
