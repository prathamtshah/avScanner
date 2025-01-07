import base64
import json
import os
from distutils.util import strtobool

import boto3

import clamav
from common import AV_DEFINITION_S3_BUCKET
from common import AV_DEFINITION_S3_PREFIX
from common import AV_QUARANTINE_S3_BUCKET
from common import S3_ENDPOINT
from common import create_dir
from common import get_timestamp


def get_local_path(s3_object, local_prefix):
    return os.path.join(local_prefix, s3_object.bucket_name, s3_object.key)



# Define allowed content types and their corresponding magic bytes
ALLOWED_CONTENT_TYPES = {
    "image/jpeg": [0xFF, 0xD8, 0xFF],
    "image/png": [0x89, 0x50, 0x4E, 0x47],
    "application/pdf": [0x25, 0x50, 0x44, 0x46],
}

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

def validate_content_type_and_magic_bytes(file_path, content_type):
    """
    Validate file content type by comparing magic bytes.
    """
    expected_magic_bytes = ALLOWED_CONTENT_TYPES.get(content_type.lower())
    if not expected_magic_bytes:
        return False

    # Read the file's magic bytes
    with open(file_path, "rb") as f:
        file_magic_bytes = list(f.read(len(expected_magic_bytes)))

    # Compare the file's magic bytes with the expected magic bytes
    return file_magic_bytes == expected_magic_bytes

def lambda_handler(event, context):
    try:
        # Initialize S3 resource and client
        s3 = boto3.resource("s3", endpoint_url=S3_ENDPOINT)
        s3_client = boto3.client("s3", endpoint_url=S3_ENDPOINT)

        start_time = get_timestamp()
        print("Script starting at %s\n" % (start_time))
        print("Event:", event)

        # Check if the event contains s3_key
        if "s3_key" in event and "filename" in event and "content_type" in event:
            print("Processing file from S3 bucket.")
            
            # Retrieve file details
            s3_key = event["s3_key"]
            file_path = os.path.join("/tmp", event["filename"])
            create_dir(os.path.dirname(file_path))

            # Download the file from S3
            print(f"Downloading file from s3://{AV_QUARANTINE_S3_BUCKET}/{s3_key} to {file_path}")
            s3.Bucket(AV_QUARANTINE_S3_BUCKET).download_file(s3_key, file_path)
            print(f"File downloaded to {file_path}")

            # Validate file size
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                return {
                    "statusCode": 400,
                    "headers": {
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type",
                    },
                    "body": json.dumps({"error": "File size exceeds maximum limit"}),
                }

            # Validate content type and magic bytes
            content_type = event["content_type"]
            if content_type not in ALLOWED_CONTENT_TYPES:
                return {
                    "statusCode": 400,
                    "headers": {
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type",
                    },
                    "body": json.dumps({"error": "Invalid content type"}),
                }

            if not validate_content_type_and_magic_bytes(file_path, content_type):
                return {
                    "statusCode": 400,
                    "headers": {
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type",
                    },
                    "body": json.dumps({"error": "Content type and magic bytes do not match"}),
                }

            # Update ClamAV definitions
            to_download = clamav.update_defs_from_s3(
                s3_client, AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX
            )

            for download in to_download.values():
                s3_path = download["s3_path"]
                local_path = download["local_path"]
                print("Downloading definition file %s from s3://%s" % (local_path, s3_path))
                s3.Bucket(os.getenv("AV_DEFINITION_S3_BUCKET", "")).download_file(s3_path, local_path)
                print("Downloading definition file %s complete!" % (local_path))

            # Scan the file
            scan_result, scan_signature = clamav.scan_file(file_path)
            print("Scan of file %s resulted in %s\n" % (file_path, scan_result))

            # Delete the file to free up space in /tmp
            try:
                os.remove(file_path)
            except OSError as e:
                print(f"Error deleting file {file_path}: {e}")

            stop_scan_time = get_timestamp()
            print("Script finished at %s\n" % stop_scan_time)

            # Response with CORS headers
            return {
                "statusCode": 200,
                "headers": {
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                },
                "body": json.dumps(
                    {
                        "scan_result": scan_result,
                        "scan_signature": scan_signature,
                        "timestamp": stop_scan_time,
                    }
                ),
            }
        else:
            print(f"Error occurred: Missing required fields in the request payload.")
            return {
                "statusCode": 400,
                "headers": {
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                },
                "body": json.dumps({"error": "Invalid request payload"}),
            }
    except Exception as e:
        print(f"Error occurred: {e}")
        return {
            "statusCode": 500,
            "headers": {
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
            },
            "body": json.dumps({"error": str(e)}),
        }
    finally:
          # Remove the file from the quarantine bucket
        if "s3_key" in event:
            s3_key = event["s3_key"]
            try:
                print(f"Removing file s3://{AV_QUARANTINE_S3_BUCKET}/{s3_key} from quarantine bucket.")
                s3.Object(AV_QUARANTINE_S3_BUCKET, s3_key).delete()
                print(f"File {s3_key} successfully removed from quarantine bucket.")
            except Exception as e:
                print(f"Error removing file {s3_key} from quarantine bucket: {e}")

def get_timestamp():
    # You can use any method to get the timestamp, e.g., time module
    from time import time
    return time()

def create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)



def str_to_bool(s):
    return bool(strtobool(str(s)))
