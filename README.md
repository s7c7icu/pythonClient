# s7c7icu/pythonClient

This is a python client (and SDK) to download files from `s7c7icu`-like sites
or upload files onto them.

Basically, `s7c7icu` sites share the same schema, so the download process is
same among sites. However, different servers may use different approaches to
store their files (OSS services, repositories, etc), which makes the upload
script diverse (and customizable).

## Installation

It is recommended to generate a virtual environment for this program:
```bash
python3 -m venv .venv
# Activate the virtual environment
source .venv/bin/activate
# Google "install venv windows" if you're on Windows
```
Basically, install the dependencies for download and upload API, as well as
download and GitHub-specified upload scripts:
```bash
pip install -r requirements.txt
```
If you're going to use the Aliyun OSS upload script:
```bash
pip install -r requirements-aliyun.txt
```

## Usage

### Download script

`s7c7icu.py` serves as the download script.
```
usage: s7c7icu.py [-h] [-o OUTPUTDIR] [-f FILENAME] uri

s7c7icu downloadClient

positional arguments:
  uri

options:
  -h, --help            show this help message and exit
  -o OUTPUTDIR, --outputdir OUTPUTDIR
  -f FILENAME, --filename FILENAME
```

### Upload script

`s7c7icu_gh.py` and `s7c7icu_aliyun.py` are the upload scripts respectively
for GitHub repository and Aliyun OSS storages.
```
usage: s7c7icu_<platform>.py [-h] [-c CONFIG] [-n FILENAME] [-p DUMPLIST] path_to_file

s7c7icu uploadClient

positional arguments:
  path_to_file          Must be provided.

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path of the config file, defaulting to './config'
  -n FILENAME, --filename FILENAME
                        Override the filename, defaulting to thesubstring of the file path
                        after the very last '/'.
  -p DUMPLIST, --dumplist DUMPLIST
                        Optionally, you can append filename and uploaded URLsto a file
                        specified here. Useful for batches.
```
Note that different uploading scripts requires different config files.
Here's an example for Aliyun OSS2:
```json
{
    "encrypt_algorithms": "deflate+aes",
    "meta_slug_len": 6,
    "meta_url": "https://meta.example.org",
    "data_url": "https://data.example.org",
    "download_url": "https://example.org",
    "custom": {
        "oss2": {
            "access_key_id": "********",
            "access_key_secret": "********",
            "bucket_name": {
                "meta": "*****",
                "data": "*****"
            },
            "endpoint": "https://oss-cn-<region>.aliyuncs.com"
        }
    }
}
```
An example for GitHub repo:
```json
{
    "encrypt_algorithms": "deflate+aes",
    "meta_slug_len": 6,
    "meta_url": "https://meta.example.org",
    "data_url": "https://data.example.org",
    "download_url": "https://example.org",
    "custom": {
        "github": {
        	"auth_token": "ghp_********",
        	"meta_repo": "<Owner>/<Name>",
        	"data_repo": "<Owner>/<Name>",
        	"committer": {
        		"name": "Monalisa Octocat",
        		"email": "octocat@github.com"
        	}
        }
    }
}
```

### SDK

See `s7c7icu.py` for details -- especially the `download()` and `upload()` endpoints.

(Documentation WIP)

## Technical details

### Site schema

The URL of the downloading page of `s7c7icu` sites should be like this:
`https://YourOwnSite.net/<slug>#<password>`.

Basically, when `HEAD`ing this page, you can get a `x-s7c7icu-meta-url` header pointing
to another URL like this: `https://meta.YourOwnSite.net` (Can be CORS-accessed by the
downloading page), which serves as the `<meta>` field.

The corresponding meta file is on `<meta>/<slug[0]>/<slug>.json`. For instance, for the
file downloaded through
`https://s.7c7.icu/dqmu4C#P2vhcmEg3X0KQ2UiubE3NT78eFz4Ckb3pUzDTd0Nzn8ar+mTUlTb6Z/R+rQNJ6ZJm7ZhLeVKSZM=`,
you'll find its `<meta>` site on `https://meta.s.7c7.icu`, so the meta file is on
`https://meta.s.7c7.icu/d/dqmu4C.json`.

### Meta File Format

The meta file is a JSON object that stores metadata for an uploaded file. This metadata
includes information such as encryption algorithms, size, hash values, and the method
used to retrieve the encrypted file data. Below is an explanation of the format and its fields.

#### Example Meta File

```json
{
    "schema": 2,
    "alg": "deflate+aes+base64",
    "size": 12345,
    "filename": "c29tZUZpbGVuYW1l",
    "hash": {
        "sha256": "abc123...",
        "sha512": "def456..."
    },
    "data": {
        "fetch": "https://example.com/data/12/abcdef1234.bin"
        // OR
        "base64": "base64-encoded-content",
        // OR
        "raw": "raw file content"
    }
}
```

#### Field Descriptions

- **`schema`**:  
  Indicates the schema version of the meta file. The current version is `2`.

- **`alg`** (Algorithms):  
  Specifies the encryption and encoding algorithms applied to the file.  
  For example, `"deflate+aes+base64"` means the file has been:
  1. Compressed using the `deflate` algorithm,
  2. Encrypted with `AES` (Salsa20),
  3. Encoded in Base64.

- **`size`**:  
  Represents the size of the original file in bytes before compression or encryption.

- **`filename`**:  
  The name of the original file, Base64 encoded.

- **`hash`**:  
  Contains the cryptographic hash values of the original file for
  integrity verification. This ensures the file's integrity after decryption and
  decompression.
  Supported algorithms are: `sha512`, `sha256`, `sha384`, `sha3_256`, `sha3_384`.

- **`data`**:  
  Describes the method to retrieve the encrypted file content. It can contain one of the following:
  - **`fetch`**: A URL where the file can be downloaded.
  - **`base64`**: The file content encoded as a Base64 string (used for smaller files).
  - **`raw`**: The raw file content (for very small files, stored as plain text).

#### Example Usage in Download Process

1. The **`schema`** field is checked to ensure the meta file format is compatible with the client processing it.
2. The **`alg`** field determines the steps needed to decode, decrypt, and decompress the file (supported: `deflate`, `aes`, `base64`).
3. The **`size`** field allows the client to verify that the decrypted and decompressed file has the correct size.
4. The **`hash`** values are used to verify the integrity of the retrieved file content.
5. The **`data`** field provides the method to retrieve the file, whether through a URL (`fetch`), directly as Base64-encoded content (`base64`), or as raw content (`raw`).

