# coding: utf-8

"""
    OneLogin API

    OpenAPI Specification for OneLogin  # noqa: E501

    The version of the OpenAPI document: 3.1.1
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""


import unittest
import datetime

import onelogin
from onelogin.models.list_privilege_roles200_response import ListPrivilegeRoles200Response  # noqa: E501
from onelogin.rest import ApiException

class TestListPrivilegeRoles200Response(unittest.TestCase):
    """ListPrivilegeRoles200Response unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test ListPrivilegeRoles200Response
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `ListPrivilegeRoles200Response`
        """
        model = onelogin.models.list_privilege_roles200_response.ListPrivilegeRoles200Response()  # noqa: E501
        if include_optional :
            return ListPrivilegeRoles200Response(
                total = 56, 
                roles = [
                    56
                    ], 
                before_cursor = 56, 
                previous_link = '', 
                after_cursor = 56, 
                next_link = ''
            )
        else :
            return ListPrivilegeRoles200Response(
        )
        """

    def testListPrivilegeRoles200Response(self):
        """Test ListPrivilegeRoles200Response"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
