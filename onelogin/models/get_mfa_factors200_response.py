# coding: utf-8

"""
    OneLogin API

    OpenAPI Specification for OneLogin  # noqa: E501

    The version of the OpenAPI document: 3.1.1
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""


from __future__ import annotations
import pprint
import re  # noqa: F401
import json


from typing import Optional
from pydantic import BaseModel
from onelogin.models.error import Error
from onelogin.models.get_mfa_factors200_response_data import GetMFAFactors200ResponseData

class GetMFAFactors200Response(BaseModel):
    """
    GetMFAFactors200Response
    """
    status: Optional[Error] = None
    data: Optional[GetMFAFactors200ResponseData] = None
    __properties = ["status", "data"]

    class Config:
        """Pydantic configuration"""
        allow_population_by_field_name = True
        validate_assignment = True

    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.dict(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> GetMFAFactors200Response:
        """Create an instance of GetMFAFactors200Response from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self):
        """Returns the dictionary representation of the model using alias"""
        _dict = self.dict(by_alias=True,
                          exclude={
                          },
                          exclude_none=True)
        # override the default output from pydantic by calling `to_dict()` of status
        if self.status:
            _dict['status'] = self.status.to_dict()
        # override the default output from pydantic by calling `to_dict()` of data
        if self.data:
            _dict['data'] = self.data.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: dict) -> GetMFAFactors200Response:
        """Create an instance of GetMFAFactors200Response from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return GetMFAFactors200Response.parse_obj(obj)

        _obj = GetMFAFactors200Response.parse_obj({
            "status": Error.from_dict(obj.get("status")) if obj.get("status") is not None else None,
            "data": GetMFAFactors200ResponseData.from_dict(obj.get("data")) if obj.get("data") is not None else None
        })
        return _obj

