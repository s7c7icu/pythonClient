import argparse
import base64
import io
import hashlib
import json
import os
import secrets
import string
import typing
import requests
import urllib.parse
import warnings
import zlib
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError


# 自定义异常类
class MetaDataError(ValueError):
    """Exceptions of the `meta` JSON."""


class FetchError(Exception):
    """Exceptions when fetching meta, data, etc., usually are network errors."""


class InvalidFileException(Exception):
    """Base exception for all errors related to malformed encrypted data."""


class AESDecryptionError(InvalidFileException):
    """An AES decryption failure."""


class HashMismatchError(InvalidFileException):
    """File hash does not match as provided."""


class SizeMismatchError(InvalidFileException):
    """File size does not match as provided."""


class InvalidAlgorithmError(MetaDataError):
    """Invalid or unrecognized encoding algorithm."""


class InvalidZipIndexError(ValueError):
    """Invalid zip index."""


SUPPORTED_MAX_SCHEMA = 4


# info 对象类
class FileInfo:
    def __init__(self, meta: str, slug: str, password: str):
        self.meta = meta
        self.slug = slug
        self.password = password

    def validate(self):
        if not isinstance(self.meta, str) or not isinstance(self.slug, str) or not isinstance(self.password, str):
            raise ValueError("FileInfo fields must be strings")


def fetch(url: str, exception_message: str = 'Failed to fetch meta') -> requests.Response:
    response = requests.get(url)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise FetchError(exception_message, e)
    return response


# 获取META数据
def get_meta(info: FileInfo):
    meta_url = f"{info.meta}/{info.slug[0]}/{info.slug}.json"
    response = fetch(meta_url)
    meta = response.json()

    # 类型检查
    if not isinstance(meta, dict):
        raise MetaDataError("Meta must be a dictionary")
    if 'schema' not in meta or not isinstance(meta['schema'], int):
        raise MetaDataError("Invalid or missing schema in meta")
    if 'alg' not in meta or not isinstance(meta['alg'], str):
        raise MetaDataError("Invalid or missing algorithm in meta")
    if 'hash' not in meta or not isinstance(meta['hash'], dict):
        raise MetaDataError("Invalid or missing hash in meta")

    return meta


# 校验 META 数据的合法性
def validate_meta(meta):
    if meta['schema'] <= 0 or meta['schema'] > SUPPORTED_MAX_SCHEMA:
        raise MetaDataError("Unsupported schema version")
    if 'aes' not in meta['alg']:
        raise MetaDataError("Meta data does not contain AES encryption")
    if not meta['hash']:
        raise MetaDataError("Meta hash data is missing")
    if meta['schema'] >= 4 and meta.get('flags') and (not isinstance(meta['flags'], list)):
        raise MetaDataError("Flags isn't an array")


def base64_encode(b: bytes, urlsafe=False):
    return (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(b)


# AES 解密
def decrypt(buffer, password):
    password += '=' * (-len(password) % 4)
    raw_password = base64.b64decode(password, altchars=b'-_')
    nonce = raw_password[:24]
    key = raw_password[24:]
    box = SecretBox(key)
    try:
        return box.decrypt(buffer, nonce)
    except CryptoError as e:
        raise AESDecryptionError(e)


# 比较哈希值
def compare_hash(file_data, hash_object):
    known_hash_algorithms = {
        "sha512": hashlib.sha512,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha3_256": hashlib.sha3_256,
        "sha3_384": hashlib.sha3_384,
    }
    algorithm_alias = {
        'sha512': ['sha-512', 'sha_512'],
        'sha256': ['sha-256', 'sha_256'],
        'sha384': ['sha-384', 'sha_384'],
        'sha3': ['sha3-512', 'sha3_512'],
        'sha3_256': ['sha3-256'],
        'sha3_384': ['sha3-384']
    }
    for alg, aliases in algorithm_alias.items():
        for alias in aliases:
            if alias in hash_object and alg not in hash_object:
                hash_object[alg] = hash_object[alias]

    for alg, expected_hash in hash_object.items():
        if alg not in known_hash_algorithms:
            raise InvalidAlgorithmError(f"Unknown algorithm: {alg}")
        calculated_hash = known_hash_algorithms[alg](file_data).hexdigest()
        if expected_hash != calculated_hash:
            raise HashMismatchError(f"{alg} hash mismatch: expected {expected_hash}, got {calculated_hash}")


def _salters() -> typing.Dict[str, typing.Callable[[dict], typing.Callable[[bytes, dict], None]]]:
    ret = {'none': (lambda _: compare_hash)}

    def _post_append(salt_conf: dict) -> typing.Callable[[bytes, dict], None]:
        salt = base64.b64decode(salt_conf['salt'])
        return lambda file_data, hash_object: compare_hash(file_data + salt, hash_object)

    ret['s7c7icu:postappend-v0'] = _post_append

    return ret


salters = _salters()


def compare_hash_salted(file_data: bytes, hash_object: dict, salter_object: dict | None):
    if (not salter_object) or salter_object.get('name', None) not in salters:
        salter = salters['none']
    else:
        salter = salters[salter_object.get('name', 'none')]
    return salter(salter_object)(file_data, hash_object)


def _has_nil(*args):
    for item in args:
        if not item:
            return True
    return False


def parse_url_to_fileinfo(url: str, default_meta: str = None) -> FileInfo:
    # 处理 s7c7icu://<slug>/<password>/<meta> 格式的 URL
    if url.startswith("s7c7icu://"):
        try:
            # 去掉 scheme 部分
            stripped_url = url[len("s7c7icu://"):]
            # 分割 slug, password, meta
            split_result = stripped_url.split('/', 2)
            if len(split_result) == 2 and default_meta:
                slug, password = split_result
                encoded_meta = default_meta
            else:
                slug, password, encoded_meta = split_result
            # 还原 URL 编码的 meta
            meta = urllib.parse.unquote(encoded_meta)
            return FileInfo(meta=meta, slug=slug, password=password)
        except ValueError:
            raise ValueError("Invalid s7c7icu URL format")

    # 处理 https: 开头的 URL
    elif url.startswith("https:"):
        try:
            parsed_url = urllib.parse.urlparse(url)
            # 检查 pathname 和 hash 是否为空
            if not parsed_url.path.strip('/') or not parsed_url.fragment:
                raise ValueError("Invalid HTTPS URL format: missing pathname or hash")

            # 发起 HEAD 请求获取 header 信息
            response = requests.head(url)
            if response.status_code != 200:
                raise FetchError("Failed to fetch metadata from the URL")

            # 从响应头中获取 meta 信息
            meta_url = response.headers.get("x-s7c7icu-meta-url")
            if not meta_url:
                raise FetchError("x-s7c7icu-meta-url header is missing")

            # pathname 作为 slug，hash 作为 password
            slug = parsed_url.path.strip('/')
            password = parsed_url.fragment

            warnings.warn(
                f"HTTP URL is not recommended. Replace it with `s7c7icu://{slug}/{password}/{urllib.parse.quote(meta_url)}`.")
            return FileInfo(meta=meta_url, slug=slug, password=password)

        except requests.RequestException as e:
            raise FetchError("Network error during metadata fetch", e)
        except ValueError:
            raise ValueError("Invalid HTTPS URL format")

    # 如果都不满足，抛出 ValueError
    else:
        raise ValueError("Unsupported URL format")


def add_file_to_zip(zf: zipfile.ZipFile, filename: str, data: dict, default_meta: str, feedback: typing.Callable[[dict], None]):
    if filename.endswith('/'):
        zf.mkdir(filename)
    else:
        if 'fetch' in data:
            if data['fetch'].startswith('s7c7icu://'):
                file_info = parse_url_to_fileinfo(data['fetch'], default_meta)
                contents = download_to_bytes(file_info, feedback)
            else:
                contents = fetch(data['fetch'], 'Failed to fetch remote resource')
            zf.writestr(filename, contents)
        elif 'base64' in data:
            zf.writestr(filename, base64.b64decode(data['base64']))
        elif 'raw' in data:
            zf.writestr(filename, data['raw'])
        else:
            zf.writestr(filename, b'')


def parse_zip_info(file_data: bytes, feedback: typing.Callable[[dict], None], default_meta: str) -> bytes:
    entries = json.loads(file_data)
    if not isinstance(entries, dict):
        raise InvalidZipIndexError("Zip index is not an object")
    with io.BytesIO() as res_data:
        with zipfile.ZipFile(res_data, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=5) as zf:
            for name, info in entries.items():
                feedback({'name': 'Adding file to zip', 'detail': name})
                add_file_to_zip(zf, name, info, default_meta, feedback)


# 主函数
def download(info: FileInfo | str,
             file_receiver: typing.Callable[[bytes, str], None] | None = None,
             feedback: typing.Callable[[dict], None] | None = None):
    # 如果 feedback 是 None，定义一个空的 feedback 函数
    feedback = feedback or (lambda _: None)

    if isinstance(info, FileInfo):
        pass
    elif isinstance(info, str):
        info = parse_url_to_fileinfo(info)
    else:
        raise ValueError(f'Invalid info: {info}')

    try:
        info.validate()

        feedback({"name": "Acquiring Meta"})

        # 获取 META 数据
        meta = get_meta(info)

        feedback({"name": "Checking Meta"})

        # 检查 META 数据的合法性
        validate_meta(meta)

        feedback({"name": "Acquiring Data"})

        # 获取文件数据
        file_data: bytes
        if "fetch" in meta["data"]:
            response = requests.get(meta["data"]["fetch"])
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                raise FetchError("Failed to fetch file data", e)
            file_data = response.content
        elif "base64" in meta["data"]:
            file_data = base64.b64decode(meta["data"]["base64"])
        elif "raw" in meta["data"]:
            file_data = meta["data"]["raw"].encode('ascii')
        else:
            file_data = b""

        feedback({"name": "Decrypting"})

        # 逆向解码
        algorithms = meta["alg"].split('+')[::-1]
        for algorithm in algorithms:
            if algorithm == "deflate":
                file_data = zlib.decompress(file_data)
            elif algorithm == "aes":
                if meta.get("schema") == 1:
                    file_data = file_data[24:]
                file_data = decrypt(file_data, info.password)
            elif algorithm == "base64":
                file_data = base64.b64decode(file_data)
            else:
                raise InvalidAlgorithmError(f"Unknown algorithm: {algorithm}")

        # Schema 4: filename-preappend
        if meta['schema'] >= 4 and 'flags' in meta and 'filename-preappend' in meta['flags']:
            filename_length = int.from_bytes(file_data[:2]) # unsigned, big endian
            meta['filename'] = base64_encode(file_data[2 : filename_length + 2])
            file_data = file_data[filename_length + 2:]

        feedback({"name": "Verifying"})

        # 验证文件大小
        if "size" in meta and meta["size"] >= 0:
            if len(file_data) != meta["size"]:
                raise SizeMismatchError("File size mismatch")

        # 验证哈希值
        compare_hash_salted(
            file_data,
            meta["hash"],
            meta.get('salter') if meta.get('schema') >= 3 else None
        )

        feedback({"name": "Downloading"})

        filename = base64.b64decode(meta.get("filename", f"{info.slug}.bin")).decode()

        # Schema 4: zipindex
        if meta['schema'] >= 4 and 'flags' in meta and 'zipindex' in meta['flags']:
            file_data = parse_zip_info(file_data, feedback, info.meta)

        if file_receiver:
            file_receiver(file_data, filename)
        else:
            return {"blob": file_data, "filename": filename}

    except (InvalidFileException, ValueError) as e:
        feedback({"name": "Error", "detail": {"error_type": str(type(e)), "message": str(e)}})
        raise


def download_to_bytes(info: FileInfo | str,
                      feedback: typing.Callable[[dict], None] | None = None):
    return download(info, feedback=feedback)['blob']


class UploadMethod(ABC):
    META = 0
    DATA = 1

    def upload_meta(self, _json, slug_factory: typing.Callable[[], str]) -> str:
        """
        :return: The slug.
        """
        # Upload meta
        meta_dump = json.dumps(_json)
        while True:
            meta_slug = slug_factory()
            uri = f'{meta_slug[0]}/{meta_slug}.json'
            if self.check_existence(UploadMethod.META, uri):
                continue
            break

        if not self.upload_file(UploadMethod.META, uri, meta_dump.encode('utf8')):
            raise FetchError(f'Failed to upload meta: {meta_slug}')
        return meta_slug

    def upload_data(self, uri: str, content: bytes):
        if self.check_existence(UploadMethod.DATA, uri):
            # feedback(f'File {uri} already exists')
            pass
        else:
            # feedback(f'Uploading {uri}')
            if not self.upload_file(UploadMethod.DATA, uri, content):
                raise FetchError(f"Failed to upload data: {uri}")

    @abstractmethod
    def upload_file(self, type: typing.Literal[0, 1], uri: str, content: bytes) -> bool:
        """
        上传文件到特定的存储服务
        :param uri: 远程存储服务中的目标 URI
        :param content: 文件内容的字节
        :return: 上传是否成功
        """
        pass

    @abstractmethod
    def check_existence(self, type: typing.Literal[0, 1], uri: str) -> bool:
        """
        检查文件是否已经存在
        :param uri: 远程存储服务中的目标 URI
        :return: 文件是否存在
        """
        pass


@dataclass
class UploadConfig:
    encrypt_algorithms: str
    meta_slug_len: int
    meta_url: str
    data_url: str
    download_url: str
    custom: dict = field(default_factory=dict)  # 自定义字段，可能包含额外信息

    @staticmethod
    def from_dict(config_dict: dict) -> 'UploadConfig':
        """
        从字典创建 UploadConfig 实例
        """
        return UploadConfig(
            encrypt_algorithms=config_dict.get('encrypt_algorithms', ''),
            meta_slug_len=config_dict.get('meta_slug_len', 6),
            meta_url=config_dict.get('meta_url', ''),
            data_url=config_dict.get('data_url', ''),
            download_url=config_dict.get('download_url', ''),
            custom=config_dict.get('custom', {})
        )

    def to_dict(self) -> dict:
        """
        将 UploadConfig 实例转换为字典
        """
        return {
            'encrypt_algorithms': self.encrypt_algorithms,
            'meta_slug_len': self.meta_slug_len,
            'meta_url': self.meta_url,
            'data_url': self.data_url,
            'download_url': self.download_url,
            'custom': self.custom
        }


def _gen_code(length: int, characters: str) -> str:
    # 使用secrets模块生成指定长度的密码
    return ''.join(secrets.choice(characters) for _ in range(length))


def gen_meta_slug(length: int) -> str:
    characters = string.ascii_letters + string.digits
    return _gen_code(length, characters)


def aes_encrypt(data: bytes, password: str) -> bytes:
    raw_pass = base64.urlsafe_b64decode(password.encode('latin1'))
    key, nonce = (raw_pass[24:], raw_pass[:24])
    return _aes_encrypt(data, key, nonce)[24:]  # Schema 2: 去除前导nonce部分


def _aes_encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    return SecretBox(key).encrypt(data, nonce)


# 文件加密函数
def encrypt_file(file_content: bytes, password: str, operations: str = "deflate+aes+base64") -> bytes:
    # 默认操作为 "deflate+aes+base64"

    # 根据操作执行文件加密操作
    encrypted_data = file_content
    operations_arr = operations.split("+")
    for operation in operations_arr:
        match operation:
            case "deflate":
                encrypted_data = zlib.compress(encrypted_data)
            case "aes":
                encrypted_data = aes_encrypt(encrypted_data, password)
            case "base64":
                encrypted_data = base64_encode(encrypted_data)
            case _:
                raise ValueError(f"Unsupported operation: {operation}")

    return encrypted_data


def upload(filename: str,
           file_content: bytes,
           config: UploadConfig,
           upload_method: UploadMethod,
           feedback: typing.Callable[[str], None] | None = None) -> str:
    password: str = base64_encode(os.urandom(24 + 32), urlsafe=True).decode('ascii')
    encrypted_content: bytes = encrypt_file(file_content, password, config.encrypt_algorithms)
    salt: bytes = os.urandom(32)
    salted_original_content = file_content + salt

    size = len(file_content)
    meta = {
        'schema': SUPPORTED_MAX_SCHEMA,
        'alg': config.encrypt_algorithms,
        'size': size,
        'filename': base64_encode(filename.encode('utf-8')).decode('ascii'),
        'hash': {
            'sha256': hashlib.sha256(salted_original_content).hexdigest(),
            'sha512': hashlib.sha512(salted_original_content).hexdigest(),
        },
        'salter': {
            'name': 's7c7icu:postappend-v0',
            'salt': base64.b64encode(salt).decode('latin1'),
        },
    }
    feedback('Generated meta')

    if size <= 4096:
        meta['data'] = {'raw': encrypted_content.decode('ascii')} if encrypted_content.isascii() else {
            'base64': base64_encode(encrypted_content).decode('ascii')}
    else:
        data_slug = hashlib.sha512(encrypted_content).hexdigest()
        uri = data_slug[:2] + "/" + data_slug[2:10] + "/" + data_slug[10:] + ".bin"

        upload_method.upload_data(uri, encrypted_content)

        meta['data'] = {'fetch': f'{config.data_url}/{uri}'}

    # Upload meta
    meta_slug = upload_method.upload_meta(meta, lambda: gen_meta_slug(config.meta_slug_len))

    link = f'{config.download_url}/{meta_slug}#{password}'

    feedback(f'Successfully created meta. Download link: {link}')
    return link


def run_upload_program(p_name: str, upload_method_from_config: typing.Callable[[UploadConfig], UploadMethod]):
    try:
        import qrcode
        def print_as_qr(link: str):
            qr = qrcode.QRCode()
            qr.add_data(link)
            qr.make()
            qr.print_ascii()
    except ImportError:
        print_as_qr = lambda _: None

    def show_url(url: str):
        print(f'Download link: {url}')
        print_as_qr(url)

    def main(path_to_file: str, path_to_config: str, filename: str,
             _file_callback: typing.Callable[[str, str], None] | None = None):
        config = UploadConfig.from_dict({})
        try:
            with open(path_to_config) as f:
                config = UploadConfig.from_dict(json.load(f))
        except FileNotFoundError:
            pass
        if _has_nil(config.encrypt_algorithms, config.meta_slug_len, config.meta_url, config.data_url,
                    config.download_url):
            print(f'Config file {path_to_config} is uninitialized')
            with open(path_to_config, 'w') as f:
                json.dump(config.to_dict(), f, indent=4)
            print('Please complete the config')
            return 1
        with open(path_to_file, 'rb') as f:
            content = f.read()
        url_callback = (lambda url: _file_callback(path_to_file, url)) if _file_callback else show_url
        # return upload(filename, content, config, url_callback)
        url_callback(upload(filename, content, config, upload_method_from_config(config), print))
        return None

    if p_name == '__main__':
        parser = argparse.ArgumentParser(description="s7c7icu uploadClient")
        parser.add_argument('path_to_file', type=str, help="Must be provided.")
        parser.add_argument('-c', '--config', type=str, help="Path of the config file, defaulting to './config'")
        parser.add_argument('-n', '--filename', type=str, help="Override the filename, defaulting to the"
                                                               "substring of the file path after the very last '/'.")
        parser.add_argument('-p', '--dumplist', type=str, help="Optionally, you can append filename and uploaded URLs"
                                                               "to a file specified here. Useful for batches.")
        args = parser.parse_args()

        def file_lister(dump_file: str) -> typing.Callable[[str, str], None]:
            def _internal_file_lister(filename: str, url: str):
                with open(dump_file, 'a') as f:
                    f.write(f'{filename}\t{url}\n')

            return _internal_file_lister

        file_callback = file_lister(args.dumplist) if args.dumplist else None

        exit(main(
            args.path_to_file,
            args.config or './config.json',
            args.filename or args.path_to_file[args.path_to_file.replace('\\', '/').rfind('/') + 1:],
            file_callback
        ) or 0)


if __name__ == '__main__':
    import os.path

    parser = argparse.ArgumentParser(description='s7c7icu downloadClient')
    parser.add_argument('uri', type=str)
    parser.add_argument('-o', '--outputdir', type=str, default='.')
    parser.add_argument('-f', '--filename', type=str, required=False)

    args = parser.parse_args()


    def feedback(_d: dict):
        d = dict(_d)
        ret = d.get('name', '')
        if not ret:
            return
        del d['name']
        if d:
            ret += '...' + json.dumps(d)
        print(ret)
        return


    def file_receiver(content: bytes, filename: str):
        if args.filename:
            filename = args.filename
        pathname = os.path.join(args.outputdir, filename)
        print(f'Saved file content to {pathname}')
        with open(pathname, 'wb') as f:
            f.write(content)


    download(
        info=args.uri,
        feedback=feedback,
        file_receiver=file_receiver
    )
