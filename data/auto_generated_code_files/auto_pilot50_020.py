import cmd
import sys
import boto3
from botocore.exceptions import ClientError

class AWSInteractiveCLI(cmd.Cmd):
    intro = 'Welcome to the Universal AWS CLI. Type help or ? to list commands.\n'
    prompt = '(aws-cli) '

    def __init__(self):
        super().__init__()
        self.ec2 = boto3.client('ec2')
        self.s3 = boto3.client('s3')
        self.iam = boto3.client('iam')

    def do_list_instances(self, arg):
        """List all EC2 instances."""
        try:
            response = self.ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    print(f"Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}")
        except ClientError as e:
            print(f"Error: {e}")

    def do_list_buckets(self, arg):
        """List all S3 buckets."""
        try:
            response = self.s3.list_buckets()
            for bucket in response['Buckets']:
                print(f"Bucket Name: {bucket['Name']}")
        except ClientError as e:
            print(f"Error: {e}")

    def do_create_bucket(self, arg):
        """Create an S3 bucket. Usage: create_bucket <bucket_name>"""
        if not arg:
            print("Please provide a bucket name.")
            return
        try:
            self.s3.create_bucket(Bucket=arg)
            print(f"Bucket {arg} created successfully.")
        except ClientError as e:
            print(f"Error: {e}")

    def do_list_users(self, arg):
        """List all IAM users."""
        try:
            response = self.iam.list_users()
            for user in response['Users']:
                print(f"User Name: {user['UserName']}")
        except ClientError as e:
            print(f"Error: {e}")

    def do_exit(self, arg):
        """Exit the CLI."""
        print('Exiting...')
        return True

    def do_quit(self, arg):
        """Exit the CLI."""
        return self.do_exit(arg)

if __name__ == '__main__':
    try:
        AWSInteractiveCLI().cmdloop()
    except KeyboardInterrupt:
        print('\nExiting...')
        sys.exit(0)
