import argparse
import cmd

import boto3
from botocore.exceptions import ClientError


class AWSCommandEnvironment(cmd.Cmd):
    intro = "Welcome to the AWS command environment. Type help or ? to list commands."
    prompt = "aws> "

    def __init__(self, region_name="us-east-1"):
        super().__init__()
        self.region_name = region_name
        self.ec2 = boto3.client("ec2", region_name=region_name)
        self.s3 = boto3.client("s3", region_name=region_name)
        self.iam = boto3.client("iam")

    def do_list_buckets(self, arg):
        try:
            response = self.s3.list_buckets()
            for bucket in response.get("Buckets", []):
                print(bucket.get("Name"))
        except ClientError as e:
            print(f"Failed to list buckets: {e}")

    def do_create_bucket(self, bucket_name):
        bucket_name = bucket_name.strip()
        if not bucket_name:
            print("Usage: create_bucket <bucket-name>")
            return

        try:
            if self.region_name == "us-east-1":
                self.s3.create_bucket(Bucket=bucket_name)
            else:
                self.s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region_name}
                )
            print(f"Created bucket: {bucket_name}")
        except ClientError as e:
            print(f"Failed to create bucket: {e}")

    def do_list_instances(self, arg):
        try:
            response = self.ec2.describe_instances()
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    print(instance.get("InstanceId"), instance.get("State", {}).get("Name"))
        except ClientError as e:
            print(f"Failed to list instances: {e}")

    def do_create_user(self, user_name):
        user_name = user_name.strip()
        if not user_name:
            print("Usage: create_user <user-name>")
            return

        try:
            self.iam.create_user(UserName=user_name)
            print(f"Created IAM user: {user_name}")
        except ClientError as e:
            print(f"Failed to create IAM user: {e}")

    def do_exit(self, arg):
        print("Goodbye")
        return True


def main():
    parser = argparse.ArgumentParser(description="Interactive AWS command environment")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    shell = AWSCommandEnvironment(region_name=args.region)
    shell.cmdloop()


if __name__ == "__main__":
    main()
