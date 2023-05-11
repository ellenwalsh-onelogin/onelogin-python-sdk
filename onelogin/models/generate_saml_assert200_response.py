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


from typing import Any, Dict, List, Optional
from pydantic import BaseModel, conlist
from onelogin.models.error import Error

class GenerateSamlAssert200Response(BaseModel):
    """
    GenerateSamlAssert200Response
    """
    status: Optional[Error] = None
    data: Optional[conlist(Dict[str, Any])] = None
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
    def from_json(cls, json_str: str) -> GenerateSamlAssert200Response:
        """Create an instance of GenerateSamlAssert200Response from a JSON string"""
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
        return _dict

    @classmethod
    def from_dict(cls, obj: dict) -> GenerateSamlAssert200Response:
        """Create an instance of GenerateSamlAssert200Response from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return GenerateSamlAssert200Response.parse_obj(obj)

        _obj = GenerateSamlAssert200Response.parse_obj({
            "status": Error.from_dict(obj.get("status")) if obj.get("status") is not None else None,
            "data": obj.get("data")
        })
        return _obj

