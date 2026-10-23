import boto3
import json

def create_aws_resources():
    region = 'us-east-1'
    s3_client = boto3.client('s3', region_name=region)
    ec2_resource = boto3.resource('ec2', region_name=region)
    rds_client = boto3.client('rds', region_name=region)
    iam_client = boto3.client('iam', region_name=region)

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["ec2.amazonaws.com", "rds.amazonaws.com"]},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    role = iam_client.create_role(
        RoleName='CodeSentryAuthRole',
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    iam_client.create_instance_profile(InstanceProfileName='CodeSentryEC2Profile')
    iam_client.add_role_to_instance_profile(
        InstanceProfileName='CodeSentryEC2Profile',
        RoleName='CodeSentryAuthRole'
    )

    s3_client.create_bucket(Bucket='codesentry-unique-bucket-987654321')

    ec2_resource.create_instances(
        ImageId='ami-0c55b159cbfafe1f0',
        InstanceType='t2.micro',
        MinCount=1,
        MaxCount=1,
        IamInstanceProfile={'Name': 'CodeSentryEC2Profile'}
    )

    rds_client.create_db_instance(
        DBInstanceIdentifier='codesentry-rds-db',
        DBInstanceClass='db.t3.micro',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='SuperSecretPassword123!',
        AllocatedStorage=20
    )

if __name__ == '__main__':
    create_aws_resources()
