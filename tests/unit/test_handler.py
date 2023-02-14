import json

import boto3
import pytest
from pytest_mock import MockerFixture
from dataclasses import dataclass
import cloudformation_data_source
import cfnresponse
from unittest import mock
import botocore.session
from botocore.stub import Stubber
from datetime import datetime

with mock.patch("boto3.client"):
    from cloudformation_data_source import app


@pytest.fixture
def lambda_context():
    @dataclass
    class LambdaContext:
        function_name: str = "test"
        memory_limit_in_mb: int = 128
        invoked_function_arn: str = "arn:aws:lambda:eu-west-1:012345678901:function:test"
        aws_request_id: str = "52fdfc07-2182-154f-163f-5f0f9a621d72"

    return LambdaContext()


@pytest.fixture
def cfn_event_create():
    """Generates Cfn GW Event"""

    return {
        "RequestType": "Create",
        "ServiceToken": "arn:aws:lambda:us-west-2:012345678901:function:serverlessrepo-CloudFormation-DataSo-CfnDataSource-fAfHlyeq6jUp",
        "ResponseURL": "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aus-west-2%3A012345678901%3Astack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f%7CrGetVpcId%7Cff3ffe50-a932-40e9-adaf-b0c854196c39",
        "StackId": "arn:aws:cloudformation:us-west-2:012345678901:stack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f",
        "RequestId": "ff3ffe50-a932-40e9-adaf-b0c854196c39",
        "LogicalResourceId": "rGetVpcId",
        "ResourceType": "Custom::GetVpcId",
        "ResourceProperties": {
            "ServiceToken": "arn:aws:lambda:us-west-2:012345678901:function:serverlessrepo-CloudFormation-DataSo-CfnDataSource-fAfHlyeq6jUp",
            "Parameters": {"Filters": [{"Values": ["Production"], "Name": "tag:Environment"}]},
            "Query": "Vpcs[0].{VpcId:VpcId}",
            "Service": "ec2",
            "Region": "us-west-2",
            "Action": "DescribeVpcs",
        },
    }


@pytest.fixture
def cfn_event_update():
    """Generates Cfn GW Event"""

    return {
        "RequestType": "Update",
        "ServiceToken": "arn:aws:lambda:us-west-2:012345678901:function:serverlessrepo-CloudFormation-DataSo-CfnDataSource-fAfHlyeq6jUp",
        "ResponseURL": "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aus-west-2%3A012345678901%3Astack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f%7CrGetVpcId%7Cff3ffe50-a932-40e9-adaf-b0c854196c39",
        "StackId": "arn:aws:cloudformation:us-west-2:012345678901:stack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f",
        "RequestId": "ff3ffe50-a932-40e9-adaf-b0c854196c39",
        "LogicalResourceId": "rGetVpcId",
        "ResourceType": "Custom::GetVpcId",
        "ResourceProperties": {
            "ServiceToken": "arn:aws:lambda:us-west-2:012345678901:function:serverlessrepo-CloudFormation-DataSo-CfnDataSource-fAfHlyeq6jUp",
            "Parameters": {"Filters": [{"Values": ["Production"], "Name": "tag:Environment"}]},
            "Query": "Vpcs[0].{VpcId:VpcId}",
            "Service": "ec2",
            "Region": "us-west-2",
            "Action": "DescribeVpcs",
        },
    }


@pytest.fixture
def cfn_event_delete():
    """Generates Cfn GW Event"""

    return {
        "RequestType": "Delete",
        "ServiceToken": "arn:aws:lambda:us-west-2:012345678901:function:serverlessrepo-CloudFormation-DataSo-CfnDataSource-fAfHlyeq6jUp",
        "ResponseURL": "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aus-west-2%3A012345678901%3Astack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f%7CrGetVpcId%7Cff3ffe50-a932-40e9-adaf-b0c854196c39",
        "StackId": "arn:aws:cloudformation:us-west-2:012345678901:stack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f",
        "RequestId": "ff3ffe50-a932-40e9-adaf-b0c854196c39",
        "LogicalResourceId": "rGetVpcId",
        "ResourceType": "Custom::GetVpcId",
        "ResourceProperties": {
            "ServiceToken": "arn:aws:lambda:us-west-2:012345678901:function:serverlessrepo-CloudFormation-DataSo-CfnDataSource-fAfHlyeq6jUp",
            "Parameters": {"Filters": [{"Values": ["Production"], "Name": "tag:Environment"}]},
            "Query": "Vpcs[0].{VpcId:VpcId}",
            "Service": "ec2",
            "Region": "us-west-2",
            "Action": "DescribeVpcs",
        },
    }


@pytest.mark.parametrize(argnames="allowed", argvalues=[True, False])
def test_lambda_handler_with_eval(cfn_event_create, lambda_context, mocker: MockerFixture, allowed):
    """
    GIVEN Cloudformation CREATE invocation
    WHEN The caller is known and allowed
    THEN return successfully the API call made
    """
    mocker.patch("cloudformation_data_source.app.PERMISSION_CHECK", True)

    mocker.patch("cloudformation_data_source.app.get_stack_infos", return_value=(None, None, None))
    mocker.patch(
        "cloudformation_data_source.app.get_caller_arn",
        return_value="arn:aws:iam::123456789012:role/demo_role",
    )
    mocker.patch("cloudformation_data_source.app.eval_permission_status", return_value=allowed)
    mocker.patch("cloudformation_data_source.app.invoke_api", return_value={"Id": "some-id"})
    mocker.patch("cfnresponse.send")

    mocker.patch("time.sleep")

    ret = app.lambda_handler(cfn_event_create, lambda_context)

    app.get_stack_infos.assert_called_once()
    app.get_caller_arn.assert_called_once()
    app.eval_permission_status.assert_called_once()
    cfnresponse.send.assert_called_once()
    if allowed:
        app.invoke_api.assert_called_once()
        cfnresponse.send.assert_called_with(
            cfn_event_create, lambda_context, cfnresponse.SUCCESS, {"Id": "some-id"}
        )
    else:
        app.invoke_api.assert_not_called()
        cfnresponse.send.assert_called_with(
            cfn_event_create, lambda_context, cfnresponse.FAILED, {}
        )

    assert ret is None


def test_lambda_handler_without_eval(cfn_event_create, lambda_context, mocker):
    """
    GIVEN Cloudformation CREATE invocation
    WHEN The permission check flag is disabled
    THEN return successfully the API call made
    """
    mocker.patch("cloudformation_data_source.app.PERMISSION_CHECK", False)

    mocker.patch(
        "cloudformation_data_source.app.get_stack_infos",
        return_value=("arn:aws:iam::123456789012:role/demo_role", None, None),
    )
    mocker.patch(
        "cloudformation_data_source.app.get_caller_arn",
        return_value="arn:aws:iam::123456789012:role/demo_role",
    )
    mocker.patch("cloudformation_data_source.app.eval_permission_status", return_value=True)
    mocker.patch("cloudformation_data_source.app.invoke_api", return_value={"Id": "some-id"})
    mocker.patch("cfnresponse.send")

    ret = app.lambda_handler(cfn_event_create, lambda_context)

    cfnresponse.send.assert_called_once()
    cfnresponse.send.assert_called_with(
        cfn_event_create, lambda_context, cfnresponse.SUCCESS, {"Id": "some-id"}
    )
    # assert "location" in data.dict_keys()


def test_lambda_handler_update_without_eval(cfn_event_update, lambda_context, mocker):
    """
    GIVEN Cloudformation UPDATE invocation
    WHEN The permission check flag is disabled
    THEN return successfully the API call made
    """
    mocker.patch("cloudformation_data_source.app.PERMISSION_CHECK", False)

    mocker.patch(
        "cloudformation_data_source.app.get_stack_infos",
        return_value=("arn:aws:iam::123456789012:role/demo_role", None, None),
    )
    mocker.patch(
        "cloudformation_data_source.app.get_caller_arn",
        return_value="arn:aws:iam::123456789012:role/demo_role",
    )
    mocker.patch("cloudformation_data_source.app.eval_permission_status", return_value=True)
    mocker.patch("cloudformation_data_source.app.invoke_api", return_value={"Id": "some-id"})
    mocker.patch("cfnresponse.send")

    ret = app.lambda_handler(cfn_event_update, lambda_context)
    app.invoke_api.assert_called_once()
    cfnresponse.send.assert_called_once()
    cfnresponse.send.assert_called_with(
        cfn_event_update, lambda_context, cfnresponse.SUCCESS, {"Id": "some-id"}
    )


def test_lambda_handler_delete(cfn_event_delete, lambda_context, mocker):
    """
    GIVEN Cloudformation DELETE invocation
    WHEN The permission check flag is disabled
    THEN return successfully the API call made
    """
    mocker.patch("cloudformation_data_source.app.PERMISSION_CHECK", False)

    mocker.patch(
        "cloudformation_data_source.app.get_stack_infos",
        return_value=("arn:aws:iam::123456789012:role/demo_role", None, None),
    )
    mocker.patch(
        "cloudformation_data_source.app.get_caller_arn",
        return_value="arn:aws:iam::123456789012:role/demo_role",
    )
    mocker.patch("cloudformation_data_source.app.eval_permission_status", return_value=True)
    mocker.patch("cloudformation_data_source.app.invoke_api", return_value={"Id": "some-id"})
    mocker.patch("cfnresponse.send")

    ret = app.lambda_handler(cfn_event_delete, lambda_context)
    cfnresponse.send.assert_called_once()
    cfnresponse.send.assert_called_with(cfn_event_delete, lambda_context, cfnresponse.SUCCESS, {})


def test_lambda_handler_no_caller_arn(cfn_event_create, lambda_context, mocker: MockerFixture):
    """
    GIVEN Cloudformation UPDATE invocation
    WHEN The permission check flag is enabled and the lambda is unable to retrieve the caller ARN
    THEN the application returns a failure event
    """
    mocker.patch("cloudformation_data_source.app.PERMISSION_CHECK", True)

    mocker.patch("cloudformation_data_source.app.get_stack_infos", return_value=(None, None, None))
    mocker.patch("cloudformation_data_source.app.get_caller_arn", return_value=None)
    mocker.patch("cloudformation_data_source.app.eval_permission_status", return_value=True)
    mocker.patch("cloudformation_data_source.app.invoke_api", return_value={"Id": "some-id"})

    mocker.patch("time.sleep")

    mp = mocker.patch("cfnresponse.send")
    ret = app.lambda_handler(cfn_event_create, lambda_context)
    cloudformation_data_source.app.invoke_api.assert_not_called()
    cfnresponse.send.assert_called_once()
    assert mp.mock_calls[0][1][2] == cfnresponse.FAILED


@pytest.mark.parametrize(
    "payload",
    [
        {"ResourceProperties": {}},
        {"RequestType": "Invalid", "ResourceProperties": {"Action": "Any", "Service": "Any"}},
    ],
)
def test_lambda_handler_invalid_request(lambda_context, mocker: MockerFixture, payload: dict):
    """
    GIVEN an invalid payload
    WHEN The permission check flag is disabled
    THEN return FAILURE to CloudFormation
    """
    mp = mocker.patch("cfnresponse.send")
    ret = app.lambda_handler(payload, lambda_context)
    cfnresponse.send.assert_called_once()
    assert mp.mock_calls[0][1][2] == cfnresponse.FAILED


def test_lambda_handler_invoke_api(cfn_event_create, lambda_context, mocker: MockerFixture):
    """
    GIVEN a valid CREATE payload
    WHEN invoke api function is called
    THEN return expected value
    """
    mocker.patch("cloudformation_data_source.app.PERMISSION_CHECK", False)

    mocker.patch("cloudformation_data_source.app.get_stack_infos", return_value=(None, None, None))
    mocker.patch(
        "cloudformation_data_source.app.get_caller_arn",
        return_value="arn:aws:iam::123456789012:role/demo_role",
    )
    mocker.patch("cloudformation_data_source.app.eval_permission_status", return_value=True)

    describe_vpc_response = {
        "Vpcs": [
            {
                "CidrBlock": "172.31.0.0/16",
                "DhcpOptionsId": "dopt-38c03d5e",
                "State": "available",
                "VpcId": "vpc-389d155e",
                "OwnerId": "315890322502",
                "InstanceTenancy": "default",
                "CidrBlockAssociationSet": [
                    {
                        "AssociationId": "vpc-cidr-assoc-d2d57ab9",
                        "CidrBlock": "172.31.0.0/16",
                        "CidrBlockState": {"State": "associated"},
                    }
                ],
                "IsDefault": True,
                "Tags": [{"Key": "Name", "Value": "default"}],
            }
        ]
    }
    mocker.patch("botocore.client.BaseClient._make_api_call", return_value=describe_vpc_response)
    mocker.patch("cfnresponse.send")
    mocker.patch("time.sleep")

    app.lambda_handler(cfn_event_create, lambda_context)

    cfnresponse.send.assert_called_once()
    cfnresponse.send.assert_called_with(
        cfn_event_create, lambda_context, cfnresponse.SUCCESS, {"VpcId": "vpc-389d155e"}
    )

    del cfn_event_create["ResourceProperties"]["Query"]
    app.lambda_handler(cfn_event_create, lambda_context)
    cfnresponse.send.assert_called_with(
        cfn_event_create, lambda_context, cfnresponse.SUCCESS, describe_vpc_response
    )
    cfn_event_create["ResourceProperties"]["Query"] = "Vpcs[0].VpcId"
    app.lambda_handler(cfn_event_create, lambda_context)
    cfnresponse.send.assert_called_with(
        cfn_event_create, lambda_context, cfnresponse.SUCCESS, {"Result": "vpc-389d155e"}
    )
    # cfnresponse.send.assert_called_once()
    # ret = app.lambda_handler(cfn_event_create, lambda_context)
    # cfnresponse.send.assert_called_once()


@pytest.mark.parametrize(
    "event_name, ct_event_name", [("Create", "CreateStack"), ("Update", "UpdateStack")]
)
def test_lambda_handler_get_caller_arn(event_name, ct_event_name, mocker: MockerFixture):
    """
    GIVEN a Cloudformation Stack
    WHEN looking up the Caller ARN through CloudTrail events
    THEN returns the ARN
    """
    role_arn = "arn:aws:iam::123456789012:role/demo_role"
    cloudtrail_response = {
        "Events": [
            {
                "EventName": ct_event_name,
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"sessionContext": {"sessionIssuer": {"arn": role_arn}}}}
                ),
            }
        ]
    }

    cloudtrail = botocore.session.get_session().create_client("cloudtrail", region_name="us-west-2")
    stub = Stubber(cloudtrail)
    stub.add_response("lookup_events", cloudtrail_response)
    stub.add_response("lookup_events", {})
    stub.activate()
    mocker.patch("boto3.client", return_value=cloudtrail)
    response = app.get_caller_arn(
        event_name,
        "arn:aws:cloudformation:us-west-2:012345678901:stack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f",
    )
    assert response == role_arn
    response = app.get_caller_arn(
        event_name,
        "arn:aws:cloudformation:us-west-2:012345678901:stack/test-vpc/2c633a60-901b-11ec-8909-0618ead2e63f",
    )
    assert not response
    stub.assert_no_pending_responses()
    stub.deactivate()
    print(response)


def test_get_stack_infos(mocker: MockerFixture, cfn_event_create: dict):
    """
    GIVEN a create in progress stack instance
    WHEN trying to get stack infos
    THEN return the role_arn invoking the stack, the changeset id and the timestamp of the event
    """
    now = datetime.now()
    role_arn = "arn:aws:iam::123456789012:role/demo_role"
    cfnresponse = [
        {
            "Stacks": [
                {
                    "StackId": cfn_event_create["StackId"],
                    "StackName": cfn_event_create["StackId"].split("/")[-2],
                    "ChangeSetId": "string",
                    "Description": "string",
                    "Parameters": [],
                    "CreationTime": datetime(2015, 1, 1),
                    "DeletionTime": datetime(2015, 1, 1),
                    "LastUpdatedTime": datetime(2015, 1, 1),
                    "StackStatus": "CREATE_IN_PROGRESS",
                    "StackStatusReason": "string",
                    "RoleARN": role_arn,
                },
            ],
        },
        {
            "StackEvents": [
                {
                    "StackId": cfn_event_create["StackId"],
                    "EventId": "string",
                    "StackName": cfn_event_create["StackId"].split("/")[-2],
                    "LogicalResourceId": cfn_event_create["StackId"].split("/")[1],
                    "Timestamp": now,
                    "ResourceStatus": "CREATE_IN_PROGRESS",
                    "ResourceStatusReason": "User Initiated",
                },
            ]
        },
    ]
    # cfn = botocore.session.get_session().create_client('cloudformation', region_name="us-west-2")
    cfn = boto3.resource("cloudformation", region_name="us-west-2")
    stub = Stubber(cfn.meta.client)

    stub.add_response("describe_stack_events", cfnresponse[1])
    stub.add_response("describe_stacks", cfnresponse[0])
    stub.activate()
    mocker.patch("boto3.resource", return_value=cfn)
    r1, r2, r3 = app.get_stack_infos(
        cfn_event_create["StackId"], request_type=cfn_event_create["RequestType"]
    )
    assert r1 == role_arn
    assert r2 == "string"
    assert r3 == now
    stub.assert_no_pending_responses()
    stub.deactivate()


def test_error_handler(mocker, lambda_context):
    """
    GIVEN a Lambda function invocation
    WHEN the handler fails
    THEN it should return to CloudFormation a failed status

    """
    mocker.patch("cfnresponse.send")
    app.lambda_handler({}, lambda_context)
    cfnresponse.send.assert_called_once()


@pytest.mark.parametrize("simulator_response,effect", [("allowed", True), ("denied", False)])
def test_eval_permission_status(mocker: MockerFixture, simulator_response, effect):
    """
    GIVEN a user invoking the Lambda function
    WHEN the Lambda is configured to check the effective permissions
    THEN the function should return true or false if the user is allowed or not
    """
    iamresponse = {
        "EvaluationResults": [{"EvalDecision": simulator_response, "EvalActionName": "string"}]
    }
    iam = boto3.client("iam", region_name="us-west-2")
    stub = Stubber(iam)

    stub.add_response("simulate_principal_policy", iamresponse)
    stub.activate()
    mocker.patch("boto3.client", return_value=iam)
    assert (
        app.eval_permission_status(
            caller_arn="arn:aws:iam::123456789012:role/iam_role", service="ec2", action="DescribeVpcs"
        )
        == effect
    )
    stub.assert_no_pending_responses()
    stub.deactivate()
