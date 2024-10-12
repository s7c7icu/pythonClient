import warnings
from s7c7icu import UploadMethod, run_upload_program, UploadConfig
import requests
import base64


class GHRepoAccess:
    auth_token: str
    committer: dict
    repo: str

    def __init__(self, auth_token: str, _committer: dict, repo: str):
        self.auth_token = auth_token
        self.committer = _committer
        self.repo = repo

    def check_existence(self, path: str) -> bool:
        url = f"https://api.github.com/repos/{self.repo}/contents/{path}"
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        response = requests.head(url, headers=headers)
        return response.status_code == 200

    def create_file(self, path: str, file_content: bytes) -> None | dict:
        url = f"https://api.github.com/repos/{self.repo}/contents/{path}"
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        # 对文件内容进行base64编码
        encoded_content = base64.b64encode(file_content).decode('ascii')

        # 构造请求体
        payload = {
            "message": f"Create file {path}",
            "content": encoded_content
        }
        if self.committer:
            payload['committer'] = self.committer

        # 发送请求
        response = requests.put(url, json=payload, headers=headers)

        # 检查响应状态码
        if response.status_code == 201:
            return None  # 文件创建成功
        else:
            # 文件创建失败，返回错误信息
            return response.json()


class GitHubUpload(UploadMethod):
    def __init__(self, auth_token: str, committer: dict, meta_repo: str, data_repo: str):
        self.gh_repo_access = (
            GHRepoAccess(auth_token, committer, meta_repo),
            GHRepoAccess(auth_token, committer, data_repo)
        )
    
    @staticmethod
    def from_config(config: UploadConfig) -> 'GitHubUpload':
        d = config.custom.get('github')
        if not isinstance(d, dict):
            raise ValueError('Missing `github` object in custom settings')
        
        return GitHubUpload(
            auth_token=d.get('auth_token', ''),
            repo=d.get('repo', '')
        )
    
    def upload_file(self, type, uri: str, content: bytes) -> bool:
        response = self.gh_repo_access[type].create_file(uri, content)
        if response:
            warnings.warn(f"Error while uploading data to GitHub: {response}")
            return False
        # print(f"Successfully uploaded to GitHub: {uri}")
        return True

    def check_existence(self, type, uri: str) -> bool:
        return self.gh_repo_access[type].check_existence(uri)


run_upload_program(GitHubUpload.from_config)
