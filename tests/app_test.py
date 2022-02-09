#!/usr/bin/python

#import os

from onelogin.api.client import OneLoginClient
from onelogin.api.models.statement import Statement

#current_dir_path = os.path.dirname(os.path.abspath(__file__))
#client = OneLoginClient(current_dir_path)

#client_id = 'TODO'
#client_secret = 'TODO'
client_id = 'TODO'
client_secret = 'TODO'
region = 'us'
subdomain = "TODO"

#api_configuration = { "user": 1 }
api_configuration = { "app": 2 }
#api_configuration = {"user": 2}

subdomain = "TODO"
client = OneLoginClient(client_id, client_secret, region, api_configuration=api_configuration)
#client = OneLoginClient(client_id, client_secret, region, api_configuration=api_configuration, subdomain=subdomain)
#client = OneLoginClient(client_id, client_secret, region)

import pdb; pdb.set_trace()
#events = client.get_events({'non_exist': 1})
events = client.get_events({'user_id': 2147483646})


apps = client.get_app(1101579)

saml_endpoint_response = client.get_saml_assertion('testlogin@example.com', 'testlogin@example.com', '1068583', 'TODO')

new_role_id = client.create_role({"name": "New Role", 'apps': [], 'admins':[], 'users': [59305875, 60308064]})

userx = client.get_user(60308064)

api_configuration = {"user": 1}

client = OneLoginClient(client_id, client_secret, region, api_configuration=api_configuration)
auth_factors2 = client.get_user(60308064)

client = OneLoginClient(client_id, client_secret, region, api_configuration=api_configuration, subdomain=subdomain)
#client = OneLoginClient(client_id, client_secret, region)

auth_factors3 = client.get_factors(59305875)

client = OneLoginClient(client_id, client_secret, region, api_configuration=api_configuration)
auth_factors4 = client.get_factors(59305875)

import pdb; pdb.set_trace()


#saml_endpoint_response = client.get_saml_assertion('testlogin@example.com', 'testlogin@example.com', '1068583', 'TODO')
#mfa = saml_endpoint_response.mfa
#saml_endpoint_response_after_verify = client.get_saml_assertion_verifying('1068583', mfa.devices[0].id, mfa.state_token, None)


#client.get_event_types()
#client.get_smart_hooks({'type':'pre-authentication'}, 2)

def print_errors_if_none(client, result):
    if result is None:    
        print(client.error)
        print(client.error_description)

def print_errors_if_none_or_false(client, result):
    if result is None or result is False:
        print(client.error)
        print(client.error_description)

# groups = client.get_groups()
# print_errors_if_none(client, groups)

# group = client.get_group(groups[0].id)
# print_errors_if_none(client, group)

#apps = client.get_apps()
#print_errors_if_none(client, apps)

connectors = client.get_connectors()

# Get all Apps in a OneLogin account
#apps = client.get_apps()

# Create app
 
#app_params = {
#    "connector_id": 43753,
#    "name": "Test app",
#    "description": "Test app desc"
#} 

#app = client.create_app(app_params)

#app = client.get_app(app.id)

#parameter_id = ""
#app = client.delete_app_parameter(app.id, parameter_id)

client = OneLoginClient(client_id, client_secret, region, api_configuration=api_configuration)
rules = client.get_app_rules(937391)
rule = client.get_app_rule(937391, rules[0].id)

#brand_params = { "name": "Brand example", "enabled": False, "custom_support_enabled": False }
#brand = client.create_brand(brand_params)
#brand_apps = client.get_brand_apps(brand.id)

risk_rule = client.get_risk_rule(233)

track_info = {"ip" : "1.2.3.4","verb" : "log-in","user_agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3)","user": {"id" : "US_112233", "name" : "Eve Smith"},"source" : {"id" : "1234","name" : "ABC Inc"},"session" : {"id" : "xxxx-xxxxx-xxxxx-xxxxx"},"device" : {"id" :"xxx-xxx-xxx"}}
result = client.track_event(track_info)

new_role_id = 434127
not_assigned_apps = client.get_role_apps(new_role_id, assigned=False)

email_settings = client.get_email_settings()
new_email_settings = { "address": "smtp.sendgrid.net", "use_tls": True, "from": "email@example.com", "domain": "example.com", "user_name": "user-name", "password": "password", "port": 587 }
result = client.update_email_settings(new_email_settings)
email_settings = client.get_email_settings()


rule_params = {
    "name": "AppRule Example",
    "enabled": True,
    "match": "all",
    "position": 1,
    "actions": [{"action": "set_nameidvalue",
                  "value": ["email"]}
    ],
    "conditions": [{"source": "last_login",
                    "operator": ">",
                    "value": "90"}
    ]
}
rule = client.create_app_rule(937391, rule_params)

actions = client.get_app_actions(937391)

action_values = client.get_app_action_values(937391, actions[0]["value"])

conditions = client.get_app_conditions(937391)

condition_ops = client.get_app_condition_operators(937391, conditions[0]["value"])

condition_values = client.get_app_condition_values(937391, conditions[0]["value"])

rule_params['name'] = "AppRule Example Updated"
rule = client.create_app_rule(937391, rule_params)

result = client.delete_app_rule(937391, rule.id)

op = client.delete_app_parameter(1452853, 75932)

#app = client.update_app(1452648, {"description": "ZZZ"})
#app_parameter_id = app.parameters.items()[0][1]['id']
#op = client.delete_app(1452648)




validate_user_params = {
    "user_identifier": "testmfa@example.com",
    "phone": "+34679731482",
    "context": {
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "ip": "217.216.86.93"
    }
}

smart_mfa = client.validate_user(validate_user_params)

if smart_mfa:
    state_token = smart_mfa.mfa["state_token"]
    otp_token = ""
    result = client.verify_token(state_token, otp_token)


embed_apps = client.get_embed_apps("80e821a505ed0f2f234ca1eb621e39b8be8a0528", "assume_user@example.com")
print_errors_if_none(client, embed_apps)

event_types = client.get_event_types()
print_errors_if_none(client, event_types)

events = client.get_events()
print_errors_if_none(client, events)

event = client.get_event(events[0].id)
print_errors_if_none(client, event)

query_events = {
    'limit': 50
}
events = client.get_events(query_events)
print_errors_if_none(client, events)

url_link = client.generate_invite_link("test@example.com")
print_errors_if_none(client, url_link)

sent = client.send_invite_link("test@example.com")
print_errors_if_none_or_false(client, sent)


limits = client.get_rate_limits()
print_errors_if_none(client, limits)

users = client.get_users()
print_errors_if_none(client, users)

apps = client.get_user_apps(users[0].id)
print_errors_if_none(client, apps)

user_fail = client.create_user({"firstname": "xx"})
if user_fail is not None or (client.error != '400' and client.error != '422' and client.error_description != 'lastname is an required attribute for post request for user' and 
  client.error_description != 'Validation failed: Need at least an email or username'):
    print("create_user test failed when wrong params")

roles = client.get_roles()
print_errors_if_none(client, roles)

import uuid
username1 = uuid.uuid4().hex
mail = "%s@example.com" % username1
user1 = client.create_user({"username": username1, "email": mail, "firstname": "xx", "lastname": "yy"})
print_errors_if_none(client, user1)
if user1.username != username1:
   print("create_user test failed")

userv2 = client.create_user({"username": username1, "email": mail, "firstname": "xx", "lastname": "yy", "password": "1", "password_confirmation": "1"}, validate_policy=False)
if userv2 is not None or (client.error != '400' and client.error != '422' and client.error_description != 'lastname is an required attribute for post request for user' and 
  client.error_description != 'Validation failed: Email must be unique, Username must be unique'):
    print("create_user test failed when not unique")

user1_obtainer = client.get_user(user1.id)
print_errors_if_none(client, user1_obtainer)
if user1.username != user1_obtainer.username:
    print("get_user test failed")

user1 = client.update_user(user1.id, {"firstname": "xx2"})
print_errors_if_none(client, user1)
if user1.firstname != "xx2":
    print("update_user test failed")
user1_obtainer = client.get_user(user1.id)
print_errors_if_none(client, user1_obtainer)
if user1.firstname != "xx2":
    print("update_user test failed")

username2 = uuid.uuid4().hex
mail2 = "%s@example.com" % username2
user2 = client.create_user({"username": username2, "email": mail2, "firstname": "xx", "lastname": "yy"})
print_errors_if_none(client, user2)
if user2.username != username2:
    print("create_user test failed")
user2_obtainer = client.get_user(user2.id)
print_errors_if_none(client, user2_obtainer)
if user2.username != user2_obtainer.username:
    print("get_user test failed")
if not client.delete_user(user2.id):
    print("delete_user test failed")
    print(client.error)
    print(client.error_description)
user2_obtainer = client.get_user(user2.id)
if user2_obtainer is not None:
    print("delete_user test failed")

roles = client.get_roles()
print_errors_if_none(client, roles)

role = client.get_role(roles[0].id)
print_errors_if_none(client, role)

user_apps = client.get_user_apps(user1.id)

apps = client.get_apps()


result = client.assign_role_to_user(user1.id, ['a'])
if result is not False or client.error != '400' or client.error_description != 'role_id_array should be -> array of positive integers':
   print("assign_role_to_user should fail")

result = client.assign_role_to_user(user1.id, [99999999999999999999999])
if result is not False or client.error != '400' or 'role_id_array should be a subset of' not in client.error_description:
   print("assign_role_to_user should fail")

result = client.assign_role_to_user(user1.id, [roles[0].id, roles[1].id])
print_errors_if_none_or_false(client, result);

user1_obtainer = client.get_user(user1.id)
if user1_obtainer.role_ids != [roles[0].id, roles[1].id]:
    print("assign_role_to_user failed")

result = client.remove_role_from_user(user1.id, [99999999999999999999999])
if result is not False or client.error != '400' or 'role_id_array should be a subset of' not in client.error_description:
   print("assign_role_to_user should fail")

result = client.remove_role_from_user(user1.id, [roles[0].id])
print_errors_if_none_or_false(client, result);
user1_obtainer = client.get_user(user1.id)
if user1_obtainer.role_ids != [roles[1].id]:
    print("remove_role_from_user failed")

new_role_id = client.create_role({"name": "New Role"})
new_role = client.get_role(new_role_id)

new_role_id = client.update_role({"name": "New Role Updated"})
new_role = client.get_role(new_role_id)




result = client.delete_role(new_role_id)



mfa_token = client.generate_mfa_token(user1.id, 60, True)
print_errors_if_none(client, mfa_token)

result = client.set_password_using_clear_text(user1.id, "11", "aa")
if result is not False or client.error != '400' or client.error_description != 'password and password_confirmation must be same':
   print("set_password_using_clear_text should fail")

password = "Aa765432-XxX";
result = client.set_password_using_clear_text(user1.id, password, password)
print_errors_if_none_or_false(client, result)

session_login_token_params = {
    "username_or_email": user1.username,
    "password": "lalala",
    "subdomain": subdomain
}
session_token_data = client.create_session_login_token(session_login_token_params)
if session_token_data is not None or client.error != '401' or client.error_description != 'Authentication Failed: Invalid user credentials':
    print("create_session_login_token should fail")

session_login_token_params["password"] = password
session_token_data = client.create_session_login_token(session_login_token_params)
print_errors_if_none(client, session_token_data)
if not hasattr(session_token_data, 'session_token') or session_token_data.session_token is None or session_token_data.session_token == "":
   print("create_session_login_token failed")

password = "Aa765431-YyY";
salt = "11xxxx1";
import hashlib
hashed_salted_password = hashlib.sha256(salt + password).hexdigest()
result = client.set_password_using_hash_salt(user1.id, hashed_salted_password, hashed_salted_password, "salt+sha256", salt);

session_token_data = client.create_session_login_token(session_login_token_params)
if session_token_data is not None or client.error != '401' or client.error_description != 'Authentication Failed: Invalid user credentials':
    print("create_session_login_token should fail")

session_login_token_params["password"] = password
session_token_data = client.create_session_login_token(session_login_token_params)
print_errors_if_none(client, session_token_data)
if not hasattr(session_token_data, 'session_token') or session_token_data.session_token is None or session_token_data.session_token == "":
    print("create_session_login_token failed")

saml_app_id = 949247
saml_endpoint_response = client.get_saml_assertion(user1.username, password, saml_app_id, subdomain)
print_errors_if_none(client, saml_endpoint_response)
if saml_endpoint_response is None:
    print("get_saml_assertion failed")
elif saml_endpoint_response.saml_response is None:
    print("get_saml_assertion requires verify")

auth_factors = client.get_factors(999999999999999999999)
if auth_factors is not None or client.error != '404' or client.error_description != 'User for id 999999999999999999999 was not found':
    print("get_factors should fail")

auth_factors = client.get_factors(user1.id)
print_errors_if_none(client, auth_factors)
if auth_factors != []:
    print("get_factors should retrieve [] on new user with no group")

group_with_factors = 431199
user1 = client.update_user(user1.id, {"group_id": group_with_factors})
print_errors_if_none(client, user1)

auth_factors = client.get_factors(user1.id)
print_errors_if_none(client, auth_factors)
if auth_factors == []:
    print("get_factors should retrieve factors when available")

factor = client.enroll_factor(user1.id, auth_factors[0].id, "Factor", "+34679731482")
result = client.activate_factor(user1.id, factor.id)

enrolled_factors = client.get_enrolled_factors(user1.id)
print_errors_if_none(client, enrolled_factors)

token = ""
import pdb; pdb.set_trace()

if enrolled_factors:
    result = client.verify_factor(user1.id, enrolled_factors[0].id, token)
    print_errors_if_none_or_false(client, result)

    result = client.remove_factor(user1.id, enrolled_factors[0].id)
    print_errors_if_none_or_false(client, result)
    enrolled_factors = client.get_enrolled_factors(user1.id)
    print_errors_if_none(client, enrolled_factors)

session_token_data = client.create_session_login_token(session_login_token_params)
print_errors_if_none(client, session_token_data)

client.get_session_token_verified(session_token_data.devices[0].id, session_token_data.state_token, token)

saml_endpoint_response = client.get_saml_assertion(user1.username, password, saml_app_id, subdomain)
print_errors_if_none(client, saml_endpoint_response)
if saml_endpoint_response.saml_response is None:
    print("get_saml_assertion requires verify")

    mfa = saml_endpoint_response.mfa
    saml_endpoint_response_after_verify = client.get_saml_assertion_verifying(saml_app_id, mfa.devices[0].id, mfa.state_token, token)

privileges = client.get_privileges()
privilege = client.get_privilege(privileges[0].id)

name = "privilege_example";
version = "2018-05-18";

statement1 = Statement(
    "Allow",
    [
        "users:List",
        "users:Get",
    ],
    ["*"]
)

statement2 = Statement(
    "Allow",
    [
        "apps:List",
        "apps:Get",
    ],
    ["*"]
)

statements = [
    statement1,
    statement2
]

privilege = client.create_privilege(name, version, statements)

#privileges = client.get_privileges()

#privilege = client.get_privilege(privileges[0].id)

#statement1 = Statement(
#    "Allow",
#    [
#        "users:List",
#    ],
#    ["*"]
#)

#statement2 = Statement(
#    "Allow",
#    [
#        "apps:Get",
#    ],
#    ["*"]
#)

#statements = [
#    statement1,
#    statement2
#]

#privilege = client.update_privilege(privileges[0].id, name, version, statements)

#privilege = client.get_privilege(privileges[0].id)

#client.delete_privilege(privileges[0].id)

#privileges = client.get_privileges()


role_ids_cursor = client.get_roles_assigned_to_privilege(privilege.id)


role_id_1 = 139229
result = client.assign_roles_to_privilege(privilege.id, [role_id_1])

client.remove_role_from_privilege(privilege.id, role_id_1)

role_ids = client.get_roles_assigned_to_privilege(privilege.id)

user_ids = client.get_users_assigned_to_privilege(privilege.id)

client.assign_users_to_privilege(privilege.id, [34687020, 34690720])

client.remove_user_from_privilege(privilege.id, 34687020)

user_ids = client.get_users_assigned_to_privilege(privilege.id)


#query_parameters = {
#       "limit": "10"
#}
#users = client.get_users(query_parameters)



#session_login_token_params = {
#    "username_or_email": "test_freeradius",
#    "password": "1test_freeradius!",
#    "subdomain": "TODO"
#}
#session_token_data = client.create_session_login_token(session_login_token_params)
#print session_token_data

#session_login_token_params = {
#    "username_or_email": "test_freeradius@example.com",
#    "password": "1test_freeradius@example.com!",
#    "subdomain": "TODO"
#}
#session_token_data = client.create_session_login_token(session_login_token_params)

#client.get_session_token_verified(session_token_data.devices[0].id, session_token_data.state_token, None, None)
#client.get_session_token_verified(session_token_data.devices[0].id, session_token_data.state_token, None, None, False)
#client.get_session_token_verified(session_token_data.devices[0].id, session_token_data.state_token, None, None, True)


#saml_endpoint_response2 = client.get_saml_assertion("test_freeradius@example.com", "1test_freeradius@example.com!", 614161,"TODO");
#mfa = saml_endpoint_response2.mfa
#saml_endpoint_response_after_verify = client.get_saml_assertion_verifying("614161", mfa.devices[0].id, mfa.state_token);
#saml_endpoint_response_after_verify = client.get_saml_assertion_verifying("614161", mfa.devices[0].id, mfa.state_token, None, None, False);
#saml_endpoint_response_after_verify = client.get_saml_assertion_verifying("614161", mfa.devices[0].id, mfa.state_token, None, None, True);

#print client.error
#print client.error_description
#print client.error_attribute


#token = client.get_access_token()

#token2 = client.regenerate_token()

#if client.revoke_token():
#	token3 = client.get_access_token()


# Get rate limits
#rate_limits = client.get_rate_limits()

#Get Users with query parameters
#query_parameters = {
#	"email": "sixto.garcia+us-preprod@onelogin.com"
#}
#users = client.get_users(query_parameters)

# Get Users with limit
#query_parameters = {
#	"limit": "6"
#}
#users = client.get_users(query_parameters)


# Get User by id
#user = client.get_user(27030376)

# Get User apps
#apps = client.get_user_apps(27030376)

#apps2 = client.get_user_apps(37321818)


# Get User Roles
#role_ids = client.get_user_roles(27030376)

# Get Custom Attributes
#custom_global_attributes = client.get_custom_attributes()

# Create user
#new_user_params = {
#    "email": "testcreate_1x1@example.com",
#    "firstname": "testcreate_1x1_fn",
#    "lastname": "testcreate_1x1_ln",
#    "username": "testcreate_1x1@example.com"
#}
#user = client.create_user(new_user_params)

# Update user with specific id
#user = client.get_user(34687020)
#update_user_params = user.get_user_params()
#update_user_params["firstname"] = 'modified_firstname'
#user = client.update_user(34687020, update_user_params)
#user = client.get_user(34687020)

# Assign & Remove Roles On Users
#role_ids = [
#    170000,
#    170001	
#]
#result = client.assign_role_to_user(34687020, role_ids)
#role_ids.pop()
#result = client.remove_role_from_user(34687020, role_ids)
#user = client.get_user(34687020)

# Sets Password by ID Using Cleartext
#result = client.set_password_using_clear_text(34687020, "Aa765431-YyY", "Aa765431-YyY");

# Sets Password by ID Using Salt and SHA-256
#password = "Aa765432-XxX";
#salt = "11xxxx1";
#import hashlib
#hashed_salted_password = hashlib.sha256(salt + password).hexdigest()
#result = client.set_password_using_hash_salt(34687020, hashed_salted_password, hashed_salted_password, "salt+sha256", salt);

# Set Custom Attribute Value to User
#customAttributes = {
#    "lala": "xxxx",
#    "lele": "yyyy"
#}
#result = client.set_custom_attribute_to_user(34687020, customAttributes);

# Log Out User
#result = client.log_user_out(34687020);

# Lock User
#result2 = client.lock_user(34687020, 5);

# Delete User
#result = client.delete_user(34690743)

# Create Session Login Token
#session_login_token_params = {
#    "username_or_email": "email_test@example.com",
#    "password": "1234567",
#    "subdomain": "TODO"
#}
#session_token_data = client.create_session_login_token(session_login_token_params)

# Create Session Login Token MFA , after verify
#session_login_token_mfa_params = {
#    "username_or_email": "testcreate_1@example.com",
#    "password": "1234567",
#    "subdomain": "TODO"
#}
#session_token_mfa_data = client.create_session_login_token(session_login_token_mfa_params)
#session_token_data2 = client.get_session_token_verified(session_token_mfa_data.devices[0].id, session_token_mfa_data.state_token, "71837700");

# Get Available Authentication Factors
#auth_factors = client.get_factors(34008771)

# Enroll an Authentication Factor
#enroll_factor = client.enroll_factor(34008771, 0000000, 'My Device', '+14156456830')

# Get Enrolled Authentication Factors
#otp_devices = client.get_enrolled_factors(34008771)

# Activate an Authentication Factor
#enrollment_response = client.activate_factor(34008771, device_id)

# Verify an Authentication Factor
#result = client.verify_factor(34008771, device_id, otp_token="4242342423")

# Get Roles
#roles = client.get_roles();

# Get Role
#role = client.get_role(139229)

# Get EventTypes
#event_types = client.get_event_types()

# Get Events
#events = client.get_events()

#query_events = {
#    'limit': 2
#}
#events = client.get_events(query_events)

# Get Event
#event = client.get_event(events[0].id)

# Create Event
#new_event_params = {
#    "event_type_id": 149,
#    "account_id": 89146,
#    "actor_system": "34",
#    "user_id": 27030376,
#    "user_name": "sixto.garcia+us-preprod@onelogin.com",
#    "custom_message": "test creating event from python :)"
#}
#result = client.create_event(new_event_params)

# Get Groups
#groups = client.get_groups()


# Test fetch again with include_unprocessed
#query_parameters = {'limit': 7}
#cursor = client.get_events(max_results=48, query_parameters=query_parameters)
#events = cursor.objects()

#query_parameters = {'limit': 5}
#cursor = client.get_events(max_results=24, query_parameters=query_parameters)
#events2 = cursor.objects()
#events2 += cursor.fetch_again(include_unprocessed=True).objects()



# Get Group
#group = client.get_group(groups[1].id)

# Get SAMLResponse directly
#saml_endpoint_response = client.get_saml_assertion("testapi@example.com", "testapipw.", "645460", "TODO");

#saml_endpoint_response = client.get_saml_assertion("testawscli@example.com", "1234567.!", "645460", "TODO");

# Get SAMLResponse after MFA
#saml_endpoint_response2 = client.get_saml_assertion("testapi2@example.com", "testapipw2.", "645460", "TODO");
#mfa = saml_endpoint_response2.mfa
#saml_endpoint_response_after_verify = client.get_saml_assertion_verifying("645460", mfa.devices[0].id, mfa.state_token, "78395727", None);

# Generate Invite Link
#url_link = client.generate_invite_link("testapi@example.com")

# Send Invite Link
#sent = client.send_invite_link("testapi2@example.com")

#Get Apps to Embed for a User
#import pdb; pdb.set_trace()
#embed_apps = client.get_embed_apps("", "")


print(client.error)
print(client.error_description)
import pdb; pdb.set_trace()
