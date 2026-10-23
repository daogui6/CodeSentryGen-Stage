import boto3
from boto3.s3.transfer import TransferConfig

class S3TransferManager:
    def __init__(self, bucket_name, region_name='us-east-1'):
        self.bucket_name = bucket_name
        self.s3_client = boto3.client('s3', region_name=region_name)
        
        self.config = TransferConfig(
            multipart_threshold=8 * 1024 * 1024,
            max_concurrency=10,
            multipart_chunksize=8 * 1024 * 1024,
            use_threads=True
        )

    def upload_file(self, file_path, object_name):
        self.s3_client.upload_file(
            file_path, 
            self.bucket_name, 
            object_name,
            Config=self.config
        )
        print(f'Successfully uploaded {file_path} to {self.bucket_name}/{object_name}')

    def download_file(self, object_name, file_path):
        self.s3_client.download_file(
            self.bucket_name, 
            object_name, 
            file_path,
            Config=self.config
        )
        print(f'Successfully downloaded {self.bucket_name}/{object_name} to {file_path}')

if __name__ == '__main__':
    # Example usage:
    # manager = S3TransferManager('my-bucket-name')
    # manager.upload_file('local_file.txt', 's3_object_name.txt')
    # manager.download_file('s3_object_name.txt', 'downloaded_file.txt')
    pass
