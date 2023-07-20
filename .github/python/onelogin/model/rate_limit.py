# coding: utf-8

"""
    OneLogin API

    OpenAPI Specification for OneLogin  # noqa: E501

    The version of the OpenAPI document: 3.1.1
    Generated by: https://openapi-generator.tech
"""

from datetime import date, datetime  # noqa: F401
import decimal  # noqa: F401
import functools  # noqa: F401
import io  # noqa: F401
import re  # noqa: F401
import typing  # noqa: F401
import typing_extensions  # noqa: F401
import uuid  # noqa: F401

import frozendict  # noqa: F401

from onelogin import schemas  # noqa: F401


class RateLimit(
    schemas.DictSchema
):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """


    class MetaOapg:
        
        class properties:
            x_rate_limit_limit = schemas.IntSchema
            x_rate_limit_remaining = schemas.IntSchema
            x_rate_limit_reset = schemas.IntSchema
            __annotations__ = {
                "X-RateLimit-Limit": x_rate_limit_limit,
                "X-RateLimit-Remaining": x_rate_limit_remaining,
                "X-RateLimit-Reset": x_rate_limit_reset,
            }
    
    @typing.overload
    def __getitem__(self, name: typing_extensions.Literal["X-RateLimit-Limit"]) -> MetaOapg.properties.x_rate_limit_limit: ...
    
    @typing.overload
    def __getitem__(self, name: typing_extensions.Literal["X-RateLimit-Remaining"]) -> MetaOapg.properties.x_rate_limit_remaining: ...
    
    @typing.overload
    def __getitem__(self, name: typing_extensions.Literal["X-RateLimit-Reset"]) -> MetaOapg.properties.x_rate_limit_reset: ...
    
    @typing.overload
    def __getitem__(self, name: str) -> schemas.UnsetAnyTypeSchema: ...
    
    def __getitem__(self, name: typing.Union[typing_extensions.Literal["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", ], str]):
        # dict_instance[name] accessor
        return super().__getitem__(name)
    
    
    @typing.overload
    def get_item_oapg(self, name: typing_extensions.Literal["X-RateLimit-Limit"]) -> typing.Union[MetaOapg.properties.x_rate_limit_limit, schemas.Unset]: ...
    
    @typing.overload
    def get_item_oapg(self, name: typing_extensions.Literal["X-RateLimit-Remaining"]) -> typing.Union[MetaOapg.properties.x_rate_limit_remaining, schemas.Unset]: ...
    
    @typing.overload
    def get_item_oapg(self, name: typing_extensions.Literal["X-RateLimit-Reset"]) -> typing.Union[MetaOapg.properties.x_rate_limit_reset, schemas.Unset]: ...
    
    @typing.overload
    def get_item_oapg(self, name: str) -> typing.Union[schemas.UnsetAnyTypeSchema, schemas.Unset]: ...
    
    def get_item_oapg(self, name: typing.Union[typing_extensions.Literal["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", ], str]):
        return super().get_item_oapg(name)
    

    def __new__(
        cls,
        *_args: typing.Union[dict, frozendict.frozendict, ],
        _configuration: typing.Optional[schemas.Configuration] = None,
        **kwargs: typing.Union[schemas.AnyTypeSchema, dict, frozendict.frozendict, str, date, datetime, uuid.UUID, int, float, decimal.Decimal, None, list, tuple, bytes],
    ) -> 'RateLimit':
        return super().__new__(
            cls,
            *_args,
            _configuration=_configuration,
            **kwargs,
        )
