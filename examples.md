# Some query examples by service
## EC2
### Retrieve the Id of a VPC based on its tag
```yaml
Resources:
  rGetVpcId:
    Type: Custom::GetVpcId
    Properties:
      ServiceToken: !ImportValue CFNDATASOURCE
      Action: DescribeVpcs
      Service: ec2
      Region: !Ref AWS::Region
      Parameters:
        Filters: 
          - Name: tag:Environment
            Values: 
              - Production
      Query: "Vpcs[0].{VpcId:VpcId}"

Outputs:
  Output0:
    Description: VpcId
    Value: !GetAtt rGetVpcId.VpcId
```

### Get the least used subnet
```yaml
Resources:
  rExample:
    Type: Custom::Example
    Properties:
      ServiceToken: !ImportValue CFNDATASOURCE
      Action: DescribeSubnets
      Service: ec2
      Region: !Ref AWS::Region
      Parameters: AWS::NoValue
      Query: "max_by(Subnets, &AvailableIpAddressCount).{SubnetId:SubnetId}"
Outputs:
  Output0:
    Value: !GetAtt rExample.SubnetId
```
### Get latest AMI Id
```yaml
Resources:
  rExample:
    Type: Custom::Example
    Properties:
      ServiceToken: !ImportValue CFNDATASOURCE
      Action: DescribeImages
      Service: ec2
      Region: !Ref AWS::Region
      Parameters: 
        Filters:
          - Name: 'name'
            Values: ["AmazonLinux"]
      Query: "sort_by(Images, &CreationDate)[-1].{ImageId:ImageId}"
Outputs:
  Output0:
    Value: !GetAtt rExample.ImageId
```
## AWS IAM
### Retrieve AWS SSO Role Arn
```yaml
Resources:
  rExample:
    Type: Custom::Example
    Properties:
      ServiceToken: !ImportValue CFNDATASOURCE
      Action: ListRoles
      Service: iam
      Region: !Ref AWS::Region
      Parameters: 
        MaxItem: 1000
      Query: "Roles[contains(RoleName, 'AWSReservedSSO_AWSPowerUserAccess').{Arn:Arn}[0]"
Outputs:
  Output0:
    Value: !GetAtt rExample.Arn
```

## AWS Organizations
### AWS Organizations Organization Id
```yaml
Resources:
  rGetOrgId:
    Type: Custom::GetOrgId
    Properties:
      ServiceToken: !ImportValue CFNDATASOURCE # ARN of the Lambda Function
      Action: DescribeOrganization
      Service: organizations
      Region: !Ref AWS::Region
      Parameters: AWS::NoValue
      Query: "Organization.{Id:Id}"
Outputs:
  Output0:
    Description: OrganizationId
    Value: !GetAtt rGetOrgId.Id
```