# -*- coding: utf-8 -*-
# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import unittest

import boto3
import botocore.session
from botocore.stub import Stubber

from scan import event_object
from scan import get_local_path
from scan import verify_s3_object_version


class TestScan(unittest.TestCase):
    def setUp(self):
        # Common data
        self.s3_bucket_name = "test_bucket"
        self.s3_key_name = "test_key"

        # Clients and Resources
        self.s3 = boto3.resource("s3")
        self.s3_client = botocore.session.get_session().create_client("s3")


    def test_s3_event_object(self):
        event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": self.s3_bucket_name},
                        "object": {"key": self.s3_key_name},
                    }
                }
            ]
        }
        s3_obj = event_object(event)
        expected_s3_object = self.s3.Object(self.s3_bucket_name, self.s3_key_name)
        self.assertEquals(s3_obj, expected_s3_object)

    def test_s3_event_object_missing_bucket(self):
        event = {"Records": [{"s3": {"object": {"key": self.s3_key_name}}}]}
        with self.assertRaises(Exception) as cm:
            event_object(event)
            self.assertEquals(cm.exception.message, "No bucket found in event!")

    def test_s3_event_object_missing_key(self):
        event = {"Records": [{"s3": {"bucket": {"name": self.s3_bucket_name}}}]}
        with self.assertRaises(Exception) as cm:
            event_object(event)
            self.assertEquals(cm.exception.message, "No key found in event!")

    def test_s3_event_object_bucket_key_missing(self):
        event = {"Records": [{"s3": {"bucket": {}, "object": {}}}]}
        with self.assertRaises(Exception) as cm:
            event_object(event)
            self.assertEquals(
                cm.exception.message,
                "Unable to retrieve object from event.\n{}".format(event),
            )

    def test_s3_event_object_no_records(self):
        event = {"Records": []}
        with self.assertRaises(Exception) as cm:
            event_object(event)
            self.assertEquals(cm.exception.message, "No records found in event!")

    def test_verify_s3_object_version(self):
        s3_obj = self.s3.Object(self.s3_bucket_name, self.s3_key_name)

        # Set up responses
        get_bucket_versioning_response = {"Status": "Enabled"}
        get_bucket_versioning_expected_params = {"Bucket": self.s3_bucket_name}
        s3_stubber_resource = Stubber(self.s3.meta.client)
        s3_stubber_resource.add_response(
            "get_bucket_versioning",
            get_bucket_versioning_response,
            get_bucket_versioning_expected_params,
        )
        list_object_versions_response = {
            "Versions": [
                {
                    "ETag": "string",
                    "Size": 123,
                    "StorageClass": "STANDARD",
                    "Key": "string",
                    "VersionId": "string",
                    "IsLatest": True,
                    "LastModified": datetime.datetime(2015, 1, 1),
                    "Owner": {"DisplayName": "string", "ID": "string"},
                }
            ]
        }
        list_object_versions_expected_params = {
            "Bucket": self.s3_bucket_name,
            "Prefix": self.s3_key_name,
        }
        s3_stubber_resource.add_response(
            "list_object_versions",
            list_object_versions_response,
            list_object_versions_expected_params,
        )
        try:
            with s3_stubber_resource:
                verify_s3_object_version(self.s3, s3_obj)
        except Exception as e:
            self.fail("verify_s3_object_version() raised Exception unexpectedly!")
            raise e

    def test_verify_s3_object_versioning_not_enabled(self):
        s3_obj = self.s3.Object(self.s3_bucket_name, self.s3_key_name)

        # Set up responses
        get_bucket_versioning_response = {"Status": "Disabled"}
        get_bucket_versioning_expected_params = {"Bucket": self.s3_bucket_name}
        s3_stubber_resource = Stubber(self.s3.meta.client)
        s3_stubber_resource.add_response(
            "get_bucket_versioning",
            get_bucket_versioning_response,
            get_bucket_versioning_expected_params,
        )
        with self.assertRaises(Exception) as cm:
            with s3_stubber_resource:
                verify_s3_object_version(self.s3, s3_obj)
            self.assertEquals(
                cm.exception.message,
                "Object versioning is not enabled in bucket {}".format(
                    self.s3_bucket_name
                ),
            )

    def test_verify_s3_object_version_multiple_versions(self):
        s3_obj = self.s3.Object(self.s3_bucket_name, self.s3_key_name)

        # Set up responses
        get_bucket_versioning_response = {"Status": "Enabled"}
        get_bucket_versioning_expected_params = {"Bucket": self.s3_bucket_name}
        s3_stubber_resource = Stubber(self.s3.meta.client)
        s3_stubber_resource.add_response(
            "get_bucket_versioning",
            get_bucket_versioning_response,
            get_bucket_versioning_expected_params,
        )
        list_object_versions_response = {
            "Versions": [
                {
                    "ETag": "string",
                    "Size": 123,
                    "StorageClass": "STANDARD",
                    "Key": "string",
                    "VersionId": "string",
                    "IsLatest": True,
                    "LastModified": datetime.datetime(2015, 1, 1),
                    "Owner": {"DisplayName": "string", "ID": "string"},
                },
                {
                    "ETag": "string",
                    "Size": 123,
                    "StorageClass": "STANDARD",
                    "Key": "string",
                    "VersionId": "string",
                    "IsLatest": True,
                    "LastModified": datetime.datetime(2015, 1, 1),
                    "Owner": {"DisplayName": "string", "ID": "string"},
                },
            ]
        }
        list_object_versions_expected_params = {
            "Bucket": self.s3_bucket_name,
            "Prefix": self.s3_key_name,
        }
        s3_stubber_resource.add_response(
            "list_object_versions",
            list_object_versions_response,
            list_object_versions_expected_params,
        )
        with self.assertRaises(Exception) as cm:
            with s3_stubber_resource:
                verify_s3_object_version(self.s3, s3_obj)
            self.assertEquals(
                cm.exception.message,
                "Detected multiple object versions in {}.{}, aborting processing".format(
                    self.s3_bucket_name, self.s3_key_name
                ),
            )

    def test_get_local_path(self):
        local_prefix = "/tmp"

        s3_obj = self.s3.Object(self.s3_bucket_name, self.s3_key_name)
        file_path = get_local_path(s3_obj, local_prefix)
        expected_file_path = "/tmp/test_bucket/test_key"
        self.assertEquals(file_path, expected_file_path)
