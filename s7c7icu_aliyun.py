import warnings
import oss2
from s7c7icu import UploadConfig, UploadMethod, run_upload_program

# Aliyun OSS 实现
class AliyunOSSUpload(UploadMethod):
    def __init__(self, access_key_id: str, access_key_secret: str, endpoint: str, bucket_name_meta: str, bucket_name_data: str):
        """
        初始化 Aliyun OSS 上传类
        :param access_key_id: 阿里云 AccessKey ID
        :param access_key_secret: 阿里云 AccessKey Secret
        :param bucket_name: OSS 存储桶名称
        :param endpoint: OSS 区域节点
        """
        auth = oss2.Auth(access_key_id, access_key_secret)
        self.buckets = (
            oss2.Bucket(auth, endpoint, bucket_name_meta),
            oss2.Bucket(auth, endpoint, bucket_name_data),
        )
    
    @staticmethod
    def from_config(config: UploadConfig) -> 'AliyunOSSUpload':
        config_dict = config.custom.get('oss2')
        if not isinstance(config_dict, dict):
            raise ValueError('Missing `oss2` object in custom settings')
        
        # 提取 Aliyun OSS 配置
        access_key_id = config_dict.get('access_key_id')
        access_key_secret = config_dict.get('access_key_secret')
        bucket_name = config_dict.get('bucket_name', {})
        endpoint = config_dict.get('endpoint')

        if (not all([access_key_id, access_key_secret, bucket_name, endpoint]) or
            (not all((bucket_name.get('meta'), bucket_name.get('data'))))):
            raise ValueError("Missing required Aliyun OSS configuration fields")

        return AliyunOSSUpload(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            bucket_name_meta=bucket_name['meta'],
            bucket_name_data=bucket_name['data'],
            endpoint=endpoint
        )

    def upload_file(self, type, uri: str, content: bytes) -> bool:
        """
        上传文件到 Aliyun OSS
        :param uri: 文件在 OSS 中的 URI
        :param content: 文件内容的字节流
        :return: 上传是否成功
        """
        try:
            self.buckets[type].put_object(uri, content)
            return True
        except Exception as e:
            warnings.warn(f"Error during uploading to Aliyun OSS: {e}")
            return False

    def check_existence(self, type, uri: str) -> bool:
        """
        检查文件是否已存在于 Aliyun OSS
        :param uri: 文件在 OSS 中的 URI
        :return: 文件是否存在
        """
        try:
            exists = self.buckets[type].object_exists(uri)
            # if exists:
            #     print(f"File {uri} exists in Aliyun OSS")
            # else:
            #     print(f"File {uri} does not exist in Aliyun OSS")
            return exists
        except Exception as e:
            warnings.warn(f"Error during checking existence in Aliyun OSS: {e}")
            return False

run_upload_program(__name__, AliyunOSSUpload.from_config)
