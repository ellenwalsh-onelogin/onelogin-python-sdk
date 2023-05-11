# coding: utf-8

"""
    OneLogin API

    OpenAPI Specification for OneLogin  # noqa: E501

    The version of the OpenAPI document: 3.1.1
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""


import re  # noqa: F401
import io
import warnings

from pydantic import validate_arguments, ValidationError
from typing_extensions import Annotated

from pydantic import StrictInt, StrictStr

from typing import Optional

from onelogin.models.add_client_app201_response import AddClientApp201Response
from onelogin.models.add_client_app_request import AddClientAppRequest
from onelogin.models.client_app_full import ClientAppFull
from onelogin.models.update_client_app_request import UpdateClientAppRequest

from onelogin.api_client import ApiClient
from onelogin.api_response import ApiResponse
from onelogin.exceptions import (  # noqa: F401
    ApiTypeError,
    ApiValueError
)


class APIAuthClientAppsApi(object):
    """NOTE: This class is auto generated by OpenAPI Generator
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient.get_default()
        self.api_client = api_client

    @validate_arguments
    def add_client_app(self, api_auth_id : StrictStr, content_type : Optional[StrictStr] = None, add_client_app_request : Optional[AddClientAppRequest] = None, **kwargs) -> AddClientApp201Response:  # noqa: E501
        """Add Client App  # noqa: E501

        Add Client App  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_client_app(api_auth_id, content_type, add_client_app_request, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param content_type:
        :type content_type: str
        :param add_client_app_request:
        :type add_client_app_request: AddClientAppRequest
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: AddClientApp201Response
        """
        kwargs['_return_http_data_only'] = True
        if '_preload_content' in kwargs:
            raise ValueError("Error! Please call the add_client_app_with_http_info method with `_preload_content` instead and obtain raw data from ApiResponse.raw_data")
        return self.add_client_app_with_http_info(api_auth_id, content_type, add_client_app_request, **kwargs)  # noqa: E501

    @validate_arguments
    def add_client_app_with_http_info(self, api_auth_id : StrictStr, content_type : Optional[StrictStr] = None, add_client_app_request : Optional[AddClientAppRequest] = None, **kwargs) -> ApiResponse:  # noqa: E501
        """Add Client App  # noqa: E501

        Add Client App  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_client_app_with_http_info(api_auth_id, content_type, add_client_app_request, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param content_type:
        :type content_type: str
        :param add_client_app_request:
        :type add_client_app_request: AddClientAppRequest
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _preload_content: if False, the ApiResponse.data will
                                 be set to none and raw_data will store the 
                                 HTTP response body without reading/decoding.
                                 Default is True.
        :type _preload_content: bool, optional
        :param _return_http_data_only: response data instead of ApiResponse
                                       object with status code, headers, etc
        :type _return_http_data_only: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :param _request_auth: set to override the auth_settings for an a single
                              request; this effectively ignores the authentication
                              in the spec for a single request.
        :type _request_auth: dict, optional
        :type _content_type: string, optional: force content-type for the request
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: tuple(AddClientApp201Response, status_code(int), headers(HTTPHeaderDict))
        """

        _params = locals()

        _all_params = [
            'api_auth_id',
            'content_type',
            'add_client_app_request'
        ]
        _all_params.extend(
            [
                'async_req',
                '_return_http_data_only',
                '_preload_content',
                '_request_timeout',
                '_request_auth',
                '_content_type',
                '_headers'
            ]
        )

        # validate the arguments
        for _key, _val in _params['kwargs'].items():
            if _key not in _all_params:
                raise ApiTypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method add_client_app" % _key
                )
            _params[_key] = _val
        del _params['kwargs']

        _collection_formats = {}

        # process the path parameters
        _path_params = {}
        if _params['api_auth_id']:
            _path_params['api_auth_id'] = _params['api_auth_id']


        # process the query parameters
        _query_params = []
        # process the header parameters
        _header_params = dict(_params.get('_headers', {}))
        if _params['content_type']:
            _header_params['Content-Type'] = _params['content_type']

        # process the form parameters
        _form_params = []
        _files = {}
        # process the body parameter
        _body_params = None
        if _params['add_client_app_request'] is not None:
            _body_params = _params['add_client_app_request']

        # set the HTTP header `Accept`
        _header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # set the HTTP header `Content-Type`
        _content_types_list = _params.get('_content_type',
            self.api_client.select_header_content_type(
                ['application/json']))
        if _content_types_list:
                _header_params['Content-Type'] = _content_types_list

        # authentication setting
        _auth_settings = ['OAuth2']  # noqa: E501

        _response_types_map = {
            '201': "AddClientApp201Response",
            '401': "AltErr",
            '404': "AltErr",
            '422': "AltErr",
        }

        return self.api_client.call_api(
            '/api/2/api_authorizations/{api_auth_id}/clients', 'POST',
            _path_params,
            _query_params,
            _header_params,
            body=_body_params,
            post_params=_form_params,
            files=_files,
            response_types_map=_response_types_map,
            auth_settings=_auth_settings,
            async_req=_params.get('async_req'),
            _return_http_data_only=_params.get('_return_http_data_only'),  # noqa: E501
            _preload_content=_params.get('_preload_content', True),
            _request_timeout=_params.get('_request_timeout'),
            collection_formats=_collection_formats,
            _request_auth=_params.get('_request_auth'))

    @validate_arguments
    def delete_client_app(self, api_auth_id : StrictStr, client_app_id : StrictInt, content_type : Optional[StrictStr] = None, **kwargs) -> AddClientApp201Response:  # noqa: E501
        """Remove Client App  # noqa: E501

        Delete Client App  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_client_app(api_auth_id, client_app_id, content_type, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param client_app_id: (required)
        :type client_app_id: int
        :param content_type:
        :type content_type: str
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: AddClientApp201Response
        """
        kwargs['_return_http_data_only'] = True
        if '_preload_content' in kwargs:
            raise ValueError("Error! Please call the delete_client_app_with_http_info method with `_preload_content` instead and obtain raw data from ApiResponse.raw_data")
        return self.delete_client_app_with_http_info(api_auth_id, client_app_id, content_type, **kwargs)  # noqa: E501

    @validate_arguments
    def delete_client_app_with_http_info(self, api_auth_id : StrictStr, client_app_id : StrictInt, content_type : Optional[StrictStr] = None, **kwargs) -> ApiResponse:  # noqa: E501
        """Remove Client App  # noqa: E501

        Delete Client App  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_client_app_with_http_info(api_auth_id, client_app_id, content_type, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param client_app_id: (required)
        :type client_app_id: int
        :param content_type:
        :type content_type: str
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _preload_content: if False, the ApiResponse.data will
                                 be set to none and raw_data will store the 
                                 HTTP response body without reading/decoding.
                                 Default is True.
        :type _preload_content: bool, optional
        :param _return_http_data_only: response data instead of ApiResponse
                                       object with status code, headers, etc
        :type _return_http_data_only: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :param _request_auth: set to override the auth_settings for an a single
                              request; this effectively ignores the authentication
                              in the spec for a single request.
        :type _request_auth: dict, optional
        :type _content_type: string, optional: force content-type for the request
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: tuple(AddClientApp201Response, status_code(int), headers(HTTPHeaderDict))
        """

        _params = locals()

        _all_params = [
            'api_auth_id',
            'client_app_id',
            'content_type'
        ]
        _all_params.extend(
            [
                'async_req',
                '_return_http_data_only',
                '_preload_content',
                '_request_timeout',
                '_request_auth',
                '_content_type',
                '_headers'
            ]
        )

        # validate the arguments
        for _key, _val in _params['kwargs'].items():
            if _key not in _all_params:
                raise ApiTypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_client_app" % _key
                )
            _params[_key] = _val
        del _params['kwargs']

        _collection_formats = {}

        # process the path parameters
        _path_params = {}
        if _params['api_auth_id']:
            _path_params['api_auth_id'] = _params['api_auth_id']

        if _params['client_app_id']:
            _path_params['client_app_id'] = _params['client_app_id']


        # process the query parameters
        _query_params = []
        # process the header parameters
        _header_params = dict(_params.get('_headers', {}))
        if _params['content_type']:
            _header_params['Content-Type'] = _params['content_type']

        # process the form parameters
        _form_params = []
        _files = {}
        # process the body parameter
        _body_params = None
        # set the HTTP header `Accept`
        _header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # authentication setting
        _auth_settings = ['OAuth2']  # noqa: E501

        _response_types_map = {
            '200': "AddClientApp201Response",
            '401': "AltErr",
            '404': "AltErr",
            '422': "AltErr",
        }

        return self.api_client.call_api(
            '/api/2/api_authorizations/{api_auth_id}/clients/{client_app_id}', 'DELETE',
            _path_params,
            _query_params,
            _header_params,
            body=_body_params,
            post_params=_form_params,
            files=_files,
            response_types_map=_response_types_map,
            auth_settings=_auth_settings,
            async_req=_params.get('async_req'),
            _return_http_data_only=_params.get('_return_http_data_only'),  # noqa: E501
            _preload_content=_params.get('_preload_content', True),
            _request_timeout=_params.get('_request_timeout'),
            collection_formats=_collection_formats,
            _request_auth=_params.get('_request_auth'))

    @validate_arguments
    def list_client_apps(self, api_auth_id : StrictStr, content_type : Optional[StrictStr] = None, **kwargs) -> ClientAppFull:  # noqa: E501
        """List Clients Apps  # noqa: E501

        List Client Apps  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_client_apps(api_auth_id, content_type, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param content_type:
        :type content_type: str
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: ClientAppFull
        """
        kwargs['_return_http_data_only'] = True
        if '_preload_content' in kwargs:
            raise ValueError("Error! Please call the list_client_apps_with_http_info method with `_preload_content` instead and obtain raw data from ApiResponse.raw_data")
        return self.list_client_apps_with_http_info(api_auth_id, content_type, **kwargs)  # noqa: E501

    @validate_arguments
    def list_client_apps_with_http_info(self, api_auth_id : StrictStr, content_type : Optional[StrictStr] = None, **kwargs) -> ApiResponse:  # noqa: E501
        """List Clients Apps  # noqa: E501

        List Client Apps  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_client_apps_with_http_info(api_auth_id, content_type, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param content_type:
        :type content_type: str
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _preload_content: if False, the ApiResponse.data will
                                 be set to none and raw_data will store the 
                                 HTTP response body without reading/decoding.
                                 Default is True.
        :type _preload_content: bool, optional
        :param _return_http_data_only: response data instead of ApiResponse
                                       object with status code, headers, etc
        :type _return_http_data_only: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :param _request_auth: set to override the auth_settings for an a single
                              request; this effectively ignores the authentication
                              in the spec for a single request.
        :type _request_auth: dict, optional
        :type _content_type: string, optional: force content-type for the request
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: tuple(ClientAppFull, status_code(int), headers(HTTPHeaderDict))
        """

        _params = locals()

        _all_params = [
            'api_auth_id',
            'content_type'
        ]
        _all_params.extend(
            [
                'async_req',
                '_return_http_data_only',
                '_preload_content',
                '_request_timeout',
                '_request_auth',
                '_content_type',
                '_headers'
            ]
        )

        # validate the arguments
        for _key, _val in _params['kwargs'].items():
            if _key not in _all_params:
                raise ApiTypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_client_apps" % _key
                )
            _params[_key] = _val
        del _params['kwargs']

        _collection_formats = {}

        # process the path parameters
        _path_params = {}
        if _params['api_auth_id']:
            _path_params['api_auth_id'] = _params['api_auth_id']


        # process the query parameters
        _query_params = []
        # process the header parameters
        _header_params = dict(_params.get('_headers', {}))
        if _params['content_type']:
            _header_params['Content-Type'] = _params['content_type']

        # process the form parameters
        _form_params = []
        _files = {}
        # process the body parameter
        _body_params = None
        # set the HTTP header `Accept`
        _header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # authentication setting
        _auth_settings = ['OAuth2']  # noqa: E501

        _response_types_map = {
            '200': "ClientAppFull",
            '401': "AltErr",
            '404': "AltErr",
        }

        return self.api_client.call_api(
            '/api/2/api_authorizations/{api_auth_id}/clients', 'GET',
            _path_params,
            _query_params,
            _header_params,
            body=_body_params,
            post_params=_form_params,
            files=_files,
            response_types_map=_response_types_map,
            auth_settings=_auth_settings,
            async_req=_params.get('async_req'),
            _return_http_data_only=_params.get('_return_http_data_only'),  # noqa: E501
            _preload_content=_params.get('_preload_content', True),
            _request_timeout=_params.get('_request_timeout'),
            collection_formats=_collection_formats,
            _request_auth=_params.get('_request_auth'))

    @validate_arguments
    def update_client_app(self, api_auth_id : StrictStr, client_app_id : StrictInt, content_type : Optional[StrictStr] = None, update_client_app_request : Optional[UpdateClientAppRequest] = None, **kwargs) -> AddClientApp201Response:  # noqa: E501
        """Update Client App  # noqa: E501

        Update Client App  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_client_app(api_auth_id, client_app_id, content_type, update_client_app_request, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param client_app_id: (required)
        :type client_app_id: int
        :param content_type:
        :type content_type: str
        :param update_client_app_request:
        :type update_client_app_request: UpdateClientAppRequest
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: AddClientApp201Response
        """
        kwargs['_return_http_data_only'] = True
        if '_preload_content' in kwargs:
            raise ValueError("Error! Please call the update_client_app_with_http_info method with `_preload_content` instead and obtain raw data from ApiResponse.raw_data")
        return self.update_client_app_with_http_info(api_auth_id, client_app_id, content_type, update_client_app_request, **kwargs)  # noqa: E501

    @validate_arguments
    def update_client_app_with_http_info(self, api_auth_id : StrictStr, client_app_id : StrictInt, content_type : Optional[StrictStr] = None, update_client_app_request : Optional[UpdateClientAppRequest] = None, **kwargs) -> ApiResponse:  # noqa: E501
        """Update Client App  # noqa: E501

        Update Client App  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_client_app_with_http_info(api_auth_id, client_app_id, content_type, update_client_app_request, async_req=True)
        >>> result = thread.get()

        :param api_auth_id: (required)
        :type api_auth_id: str
        :param client_app_id: (required)
        :type client_app_id: int
        :param content_type:
        :type content_type: str
        :param update_client_app_request:
        :type update_client_app_request: UpdateClientAppRequest
        :param async_req: Whether to execute the request asynchronously.
        :type async_req: bool, optional
        :param _preload_content: if False, the ApiResponse.data will
                                 be set to none and raw_data will store the 
                                 HTTP response body without reading/decoding.
                                 Default is True.
        :type _preload_content: bool, optional
        :param _return_http_data_only: response data instead of ApiResponse
                                       object with status code, headers, etc
        :type _return_http_data_only: bool, optional
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :param _request_auth: set to override the auth_settings for an a single
                              request; this effectively ignores the authentication
                              in the spec for a single request.
        :type _request_auth: dict, optional
        :type _content_type: string, optional: force content-type for the request
        :return: Returns the result object.
                 If the method is called asynchronously,
                 returns the request thread.
        :rtype: tuple(AddClientApp201Response, status_code(int), headers(HTTPHeaderDict))
        """

        _params = locals()

        _all_params = [
            'api_auth_id',
            'client_app_id',
            'content_type',
            'update_client_app_request'
        ]
        _all_params.extend(
            [
                'async_req',
                '_return_http_data_only',
                '_preload_content',
                '_request_timeout',
                '_request_auth',
                '_content_type',
                '_headers'
            ]
        )

        # validate the arguments
        for _key, _val in _params['kwargs'].items():
            if _key not in _all_params:
                raise ApiTypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method update_client_app" % _key
                )
            _params[_key] = _val
        del _params['kwargs']

        _collection_formats = {}

        # process the path parameters
        _path_params = {}
        if _params['api_auth_id']:
            _path_params['api_auth_id'] = _params['api_auth_id']

        if _params['client_app_id']:
            _path_params['client_app_id'] = _params['client_app_id']


        # process the query parameters
        _query_params = []
        # process the header parameters
        _header_params = dict(_params.get('_headers', {}))
        if _params['content_type']:
            _header_params['Content-Type'] = _params['content_type']

        # process the form parameters
        _form_params = []
        _files = {}
        # process the body parameter
        _body_params = None
        if _params['update_client_app_request'] is not None:
            _body_params = _params['update_client_app_request']

        # set the HTTP header `Accept`
        _header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # set the HTTP header `Content-Type`
        _content_types_list = _params.get('_content_type',
            self.api_client.select_header_content_type(
                ['application/json']))
        if _content_types_list:
                _header_params['Content-Type'] = _content_types_list

        # authentication setting
        _auth_settings = ['OAuth2']  # noqa: E501

        _response_types_map = {
            '200': "AddClientApp201Response",
            '401': "AltErr",
            '404': "AltErr",
            '422': "AltErr",
        }

        return self.api_client.call_api(
            '/api/2/api_authorizations/{api_auth_id}/clients/{client_app_id}', 'PUT',
            _path_params,
            _query_params,
            _header_params,
            body=_body_params,
            post_params=_form_params,
            files=_files,
            response_types_map=_response_types_map,
            auth_settings=_auth_settings,
            async_req=_params.get('async_req'),
            _return_http_data_only=_params.get('_return_http_data_only'),  # noqa: E501
            _preload_content=_params.get('_preload_content', True),
            _request_timeout=_params.get('_request_timeout'),
            collection_formats=_collection_formats,
            _request_auth=_params.get('_request_auth'))
