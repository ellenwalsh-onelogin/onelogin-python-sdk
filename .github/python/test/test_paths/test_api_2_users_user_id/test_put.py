# coding: utf-8

"""


    Generated by: https://openapi-generator.tech
"""

import unittest
from unittest.mock import patch

import urllib3

import onelogin
from onelogin.paths.api_2_users_user_id import put  # noqa: E501
from onelogin import configuration, schemas, api_client

from .. import ApiTestMixin


class TestApi2UsersUserId(ApiTestMixin, unittest.TestCase):
    """
    Api2UsersUserId unit test stubs
        Update User  # noqa: E501
    """
    _configuration = configuration.Configuration()

    def setUp(self):
        used_api_client = api_client.ApiClient(configuration=self._configuration)
        self.api = put.ApiForput(api_client=used_api_client)  # noqa: E501

    def tearDown(self):
        pass

    response_status = 200




if __name__ == '__main__':
    unittest.main()
