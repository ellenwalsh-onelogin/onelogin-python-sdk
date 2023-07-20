# coding: utf-8

"""
    OneLogin API

    OpenAPI Specification for OneLogin  # noqa: E501

    The version of the OpenAPI document: 3.1.1
    Generated by: https://openapi-generator.tech
"""

from onelogin.paths.api_2_mappings.post import CreateMapping
from onelogin.paths.api_2_mappings_mapping_id.delete import DeleteMapping
from onelogin.paths.api_2_mappings_mapping_id.get import GetMapping
from onelogin.paths.api_2_mappings_actions_mapping_action_value_values.get import ListMappingActionValues
from onelogin.paths.api_2_mappings_conditions.get import ListMappingConditions
from onelogin.paths.api_2_mappings_conditions_mapping_condition_value_operators.get import ListMappingConditionsOperators
from onelogin.paths.api_2_mappings_conditions_mapping_condition_value_values.get import ListMappingContionValues
from onelogin.paths.api_2_mappings.get import ListMappings
from onelogin.paths.api_2_mappings_actions.get import ListMappingsActions
from onelogin.paths.api_2_mappings_sort.put import SortMappings
from onelogin.paths.api_2_mappings_mapping_id.put import UpdateMapping


class UserMappingsApi(
    CreateMapping,
    DeleteMapping,
    GetMapping,
    ListMappingActionValues,
    ListMappingConditions,
    ListMappingConditionsOperators,
    ListMappingContionValues,
    ListMappings,
    ListMappingsActions,
    SortMappings,
    UpdateMapping,
):
    """NOTE: This class is auto generated by OpenAPI Generator
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """
    pass
