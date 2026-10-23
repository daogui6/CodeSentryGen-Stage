import boto3
from botocore.exceptions import ClientError


REGION = "us-east-1"


def create_s3_bucket(bucket_name):
    s3 = boto3.client("s3", region_name=REGION)
    try:
        if REGION == "us-east-1":
            return s3.create_bucket(Bucket=bucket_name)
        return s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": REGION}
        )
    except ClientError as e:
        print(f"Failed to create S3 bucket: {e}")
        return None


def create_ec2_instance(image_id, instance_type="t2.micro"):
    ec2 = boto3.resource("ec2", region_name=REGION)
    instances = ec2.create_instances(
        ImageId=image_id,
        MinCount=1,
        MaxCount=1,
        InstanceType=instance_type
    )
    return instances[0]


def create_rds_instance(db_identifier, username, password):
    rds = boto3.client("rds", region_name=REGION)
    try:
        return rds.create_db_instance(
            DBInstanceIdentifier=db_identifier,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername=username,
            MasterUserPassword=password,
            AllocatedStorage=20
        )
    except ClientError as e:
        print(f"Failed to create RDS instance: {e}")
        return None


def create_iam_role(role_name):
    iam = boto3.client("iam")
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    return iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=str(assume_role_policy)
    )


if __name__ == "__main__":
    print("This script defines AWS resource creation functions using boto3.")
