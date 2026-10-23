import boto3
from boto3.s3.transfer import TransferConfig, S3Transfer
from botocore.exceptions import ClientError


class S3TransferManager:
    def __init__(self, bucket_name, region_name="us-east-1"):
        self.bucket_name = bucket_name
        self.s3_client = boto3.client("s3", region_name=region_name)
        self.config = TransferConfig(
            multipart_threshold=8 * 1024 * 1024,
            max_concurrency=4,
            multipart_chunksize=8 * 1024 * 1024,
            use_threads=True
        )
        self.transfer = S3Transfer(self.s3_client, self.config)

    def upload_file(self, local_path, s3_key):
        try:
            self.transfer.upload_file(local_path, self.bucket_name, s3_key)
            print(f"Uploaded {local_path} to s3://{self.bucket_name}/{s3_key}")
        except ClientError as e:
            print(f"Upload failed: {e}")

    def download_file(self, s3_key, local_path):
        try:
            self.transfer.download_file(self.bucket_name, s3_key, local_path)
            print(f"Downloaded s3://{self.bucket_name}/{s3_key} to {local_path}")
        except ClientError as e:
            print(f"Download failed: {e}")


if __name__ == "__main__":
    manager = S3TransferManager("my-example-bucket")
    print("S3 transfer manager initialized")
