# -*- coding: utf-8 -*-

# Copyright 2018 Whitestack, LLC
# Copyright 2018 Telefonica S.A.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact: esousa@whitestack.com or alfonso.tiernosepulveda@telefonica.com
##


"""
Authenticator is responsible for authenticating the users,
create the tokens unscoped and scoped, retrieve the role
list inside the projects that they are inserted
"""

__author__ = "Eduardo Sousa <esousa@whitestack.com>; Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"
__date__ = "$27-jul-2018 23:59:59$"

import cherrypy
import logging
import yaml
from base64 import standard_b64decode
from copy import deepcopy
# from functools import reduce
from http import HTTPStatus
from time import time
from os import path

from authconn import AuthException, AuthExceptionUnauthorized
from authconn_keystone import AuthconnKeystone
from authconn_internal import AuthconnInternal   # Comment out for testing&debugging, uncomment when ready
from osm_common import dbmongo
from osm_common import dbmemory
from osm_common.dbbase import DbException
from itertools import chain

from uuid import uuid4   # For Role _id with internal authentication backend


class Authenticator:
    """
    This class should hold all the mechanisms for User Authentication and
    Authorization. Initially it should support Openstack Keystone as a
    backend through a plugin model where more backends can be added and a
    RBAC model to manage permissions on operations.
    This class must be threading safe
    """

    periodin_db_pruning = 60 * 30  # for the internal backend only. every 30 minutes expired tokens will be pruned

    def __init__(self, valid_methods, valid_query_string):
        """
        Authenticator initializer. Setup the initial state of the object,
        while it waits for the config dictionary and database initialization.
        """
        self.backend = None
        self.config = None
        self.db = None
        self.tokens_cache = dict()
        self.next_db_prune_time = 0  # time when next cleaning of expired tokens must be done
        self.roles_to_operations_file = None
        self.roles_to_operations_table = None
        self.resources_to_operations_mapping = {}
        self.operation_to_allowed_roles = {}
        self.logger = logging.getLogger("nbi.authenticator")
        self.role_permissions = []
        self.valid_methods = valid_methods
        self.valid_query_string = valid_query_string

    def start(self, config):
        """
        Method to configure the Authenticator object. This method should be called
        after object creation. It is responsible by initializing the selected backend,
        as well as the initialization of the database connection.

        :param config: dictionary containing the relevant parameters for this object.
        """
        self.config = config

        try:
            if not self.db:
                if config["database"]["driver"] == "mongo":
                    self.db = dbmongo.DbMongo()
                    self.db.db_connect(config["database"])
                elif config["database"]["driver"] == "memory":
                    self.db = dbmemory.DbMemory()
                    self.db.db_connect(config["database"])
                else:
                    raise AuthException("Invalid configuration param '{}' at '[database]':'driver'"
                                        .format(config["database"]["driver"]))
            if not self.backend:
                if config["authentication"]["backend"] == "keystone":
                    self.backend = AuthconnKeystone(self.config["authentication"])
                elif config["authentication"]["backend"] == "internal":
                    self.backend = AuthconnInternal(self.config["authentication"], self.db, self.tokens_cache)
                    self._internal_tokens_prune()
                else:
                    raise AuthException("Unknown authentication backend: {}"
                                        .format(config["authentication"]["backend"]))

            if not self.roles_to_operations_file:
                if "roles_to_operations" in config["rbac"]:
                    self.roles_to_operations_file = config["rbac"]["roles_to_operations"]
                else:
                    possible_paths = (
                        __file__[:__file__.rfind("auth.py")] + "roles_to_operations.yml",
                        "./roles_to_operations.yml"
                    )
                    for config_file in possible_paths:
                        if path.isfile(config_file):
                            self.roles_to_operations_file = config_file
                            break
                if not self.roles_to_operations_file:
                    raise AuthException("Invalid permission configuration: roles_to_operations file missing")

            if not self.roles_to_operations_table:  # PROVISIONAL ?
                self.roles_to_operations_table = "roles_operations" \
                    if config["authentication"]["backend"] == "keystone" \
                    else "roles"

            # load role_permissions
            def load_role_permissions(method_dict):
                for k in method_dict:
                    if k == "ROLE_PERMISSION":
                        for method in chain(method_dict.get("METHODS", ()), method_dict.get("TODO", ())):
                            permission = method_dict["ROLE_PERMISSION"] + method.lower()
                            if permission not in self.role_permissions:
                                self.role_permissions.append(permission)
                    elif k in ("TODO", "METHODS"):
                        continue
                    else:
                        load_role_permissions(method_dict[k])

            load_role_permissions(self.valid_methods)
            for query_string in self.valid_query_string:
                for method in ("get", "put", "patch", "post", "delete"):
                    permission = query_string.lower() + ":" + method
                    if permission not in self.role_permissions:
                        self.role_permissions.append(permission)

        except Exception as e:
            raise AuthException(str(e))

    def stop(self):
        try:
            if self.db:
                self.db.db_disconnect()
        except DbException as e:
            raise AuthException(str(e), http_code=e.http_code)

    def init_db(self, target_version='1.0'):
        """
        Check if the database has been initialized, with at least one user. If not, create the required tables
        and insert the predefined mappings between roles and permissions.

        :param target_version: schema version that should be present in the database.
        :return: None if OK, exception if error or version is different.
        """

        # PCR 28/05/2019 Commented out to allow initialization for internal backend
        # if self.config["authentication"]["backend"] == "internal":
        #    return

        records = self.db.get_list(self.roles_to_operations_table)

        # Loading permissions to MongoDB if there is not any permission.
        if not records:
            with open(self.roles_to_operations_file, "r") as stream:
                roles_to_operations_yaml = yaml.load(stream)

            role_names = []
            for role_with_operations in roles_to_operations_yaml["roles"]:
                # Verifying if role already exists. If it does, raise exception
                if role_with_operations["name"] not in role_names:
                    role_names.append(role_with_operations["name"])
                else:
                    raise AuthException("Duplicated role name '{}' at file '{}''"
                                        .format(role_with_operations["name"], self.roles_to_operations_file))

                if not role_with_operations["permissions"]:
                    continue

                for permission, is_allowed in role_with_operations["permissions"].items():
                    if not isinstance(is_allowed, bool):
                        raise AuthException("Invalid value for permission '{}' at role '{}'; at file '{}'"
                                            .format(permission, role_with_operations["name"],
                                                    self.roles_to_operations_file))

                    # TODO chek permission is ok
                    if permission[-1] == ":":
                        raise AuthException("Invalid permission '{}' terminated in ':' for role '{}'; at file {}"
                                            .format(permission, role_with_operations["name"],
                                                    self.roles_to_operations_file))

                if "default" not in role_with_operations["permissions"]:
                    role_with_operations["permissions"]["default"] = False
                if "admin" not in role_with_operations["permissions"]:
                    role_with_operations["permissions"]["admin"] = False

                now = time()
                role_with_operations["_admin"] = {
                    "created": now,
                    "modified": now,
                }

                if self.config["authentication"]["backend"] == "keystone":
                    if role_with_operations["name"] != "anonymous":
                        backend_roles = self.backend.get_role_list(filter_q={"name": role_with_operations["name"]})
                        if backend_roles:
                            backend_id = backend_roles[0]["_id"]
                        else:
                            backend_id = self.backend.create_role(role_with_operations["name"])
                        role_with_operations["_id"] = backend_id
                else:
                    role_with_operations["_id"] = str(uuid4())

                self.db.create(self.roles_to_operations_table, role_with_operations)
                self.logger.info("Role '{}' created at database".format(role_with_operations["name"]))

        if self.config["authentication"]["backend"] != "internal":
            self.backend.assign_role_to_user("admin", "admin", "system_admin")

        self.load_operation_to_allowed_roles()

    def load_operation_to_allowed_roles(self):
        """
        Fills the internal self.operation_to_allowed_roles based on database role content and self.role_permissions
        It works in a shadow copy and replace at the end to allow other threads working with the old copy
        :return: None
        """

        permissions = {oper: [] for oper in self.role_permissions}
        records = self.db.get_list(self.roles_to_operations_table)

        ignore_fields = ["_id", "_admin", "name", "default"]
        for record in records:
            record_permissions = {oper: record["permissions"].get("default", False) for oper in self.role_permissions}
            operations_joined = [(oper, value) for oper, value in record["permissions"].items()
                                 if oper not in ignore_fields]
            operations_joined.sort(key=lambda x: x[0].count(":"))

            for oper in operations_joined:
                match = list(filter(lambda x: x.find(oper[0]) == 0, record_permissions.keys()))

                for m in match:
                    record_permissions[m] = oper[1]

            allowed_operations = [k for k, v in record_permissions.items() if v is True]

            for allowed_op in allowed_operations:
                permissions[allowed_op].append(record["name"])

        self.operation_to_allowed_roles = permissions

    def authorize(self, role_permission=None, query_string_operations=None):
        token = None
        user_passwd64 = None
        try:
            # 1. Get token Authorization bearer
            auth = cherrypy.request.headers.get("Authorization")
            if auth:
                auth_list = auth.split(" ")
                if auth_list[0].lower() == "bearer":
                    token = auth_list[-1]
                elif auth_list[0].lower() == "basic":
                    user_passwd64 = auth_list[-1]
            if not token:
                if cherrypy.session.get("Authorization"):
                    # 2. Try using session before request a new token. If not, basic authentication will generate
                    token = cherrypy.session.get("Authorization")
                    if token == "logout":
                        token = None  # force Unauthorized response to insert user password again
                elif user_passwd64 and cherrypy.request.config.get("auth.allow_basic_authentication"):
                    # 3. Get new token from user password
                    user = None
                    passwd = None
                    try:
                        user_passwd = standard_b64decode(user_passwd64).decode()
                        user, _, passwd = user_passwd.partition(":")
                    except Exception:
                        pass
                    outdata = self.new_token(None, {"username": user, "password": passwd})
                    token = outdata["_id"]
                    cherrypy.session['Authorization'] = token

            if not token:
                raise AuthException("Needed a token or Authorization http header",
                                    http_code=HTTPStatus.UNAUTHORIZED)
            token_info = self.backend.validate_token(token)
            # TODO add to token info remote host, port

            if role_permission:
                self.check_permissions(token_info, cherrypy.request.method, role_permission,
                                       query_string_operations)
            return token_info
        except AuthException as e:
            if not isinstance(e, AuthExceptionUnauthorized):
                if cherrypy.session.get('Authorization'):
                    del cherrypy.session['Authorization']
                cherrypy.response.headers["WWW-Authenticate"] = 'Bearer realm="{}"'.format(e)
            raise

    def new_token(self, token_info, indata, remote):
        new_token_info = self.backend.authenticate(
            user=indata.get("username"),
            password=indata.get("password"),
            token_info=token_info,
            project=indata.get("project_id")
        )

        new_token_info["remote_port"] = remote.port
        if not new_token_info.get("expires"):
            new_token_info["expires"] = time() + 3600
        if not new_token_info.get("admin"):
            new_token_info["admin"] = True if new_token_info.get("project_name") == "admin" else False
            # TODO put admin in RBAC

        if remote.name:
            new_token_info["remote_host"] = remote.name
        elif remote.ip:
            new_token_info["remote_host"] = remote.ip

        self.tokens_cache[new_token_info["_id"]] = new_token_info

        # TODO call self._internal_tokens_prune(now) ?
        return deepcopy(new_token_info)

    def get_token_list(self, token_info):
        if self.config["authentication"]["backend"] == "internal":
            return self._internal_get_token_list(token_info)
        else:
            # TODO: check if this can be avoided. Backend may provide enough information
            return [deepcopy(token) for token in self.tokens_cache.values()
                    if token["username"] == token_info["username"]]

    def get_token(self, token_info, token):
        if self.config["authentication"]["backend"] == "internal":
            return self._internal_get_token(token_info, token)
        else:
            # TODO: check if this can be avoided. Backend may provide enough information
            token_value = self.tokens_cache.get(token)
            if not token_value:
                raise AuthException("token not found", http_code=HTTPStatus.NOT_FOUND)
            if token_value["username"] != token_info["username"] and not token_info["admin"]:
                raise AuthException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
            return token_value

    def del_token(self, token):
        try:
            self.backend.revoke_token(token)
            self.tokens_cache.pop(token, None)
            return "token '{}' deleted".format(token)
        except KeyError:
            raise AuthException("Token '{}' not found".format(token), http_code=HTTPStatus.NOT_FOUND)

    def check_permissions(self, token_info, method, role_permission=None, query_string_operations=None):
        """
        Checks that operation has permissions to be done, base on the assigned roles to this user project
        :param token_info: Dictionary that contains "roles" with a list of assigned roles.
            This method fills the token_info["admin"] with True or False based on assigned tokens, if any allows admin
            This will be used among others to hide or not the _admin content of topics
        :param method: GET,PUT, POST, ...
        :param role_permission: role permission name of the operation required
        :param query_string_operations: list of possible admin query strings provided by user. It is checked that the
            assigned role allows this query string for this method
        :return: None if granted, exception if not allowed
        """

        roles_required = self.operation_to_allowed_roles[role_permission]
        roles_allowed = [role["name"] for role in token_info["roles"]]

        # fills token_info["admin"] if some roles allows it
        token_info["admin"] = False
        for role in roles_allowed:
            if role in self.operation_to_allowed_roles["admin:" + method.lower()]:
                token_info["admin"] = True
                break

        if "anonymous" in roles_required:
            return
        operation_allowed = False
        for role in roles_allowed:
            if role in roles_required:
                operation_allowed = True
                # if query_string operations, check if this role allows it
                if not query_string_operations:
                    return
                for query_string_operation in query_string_operations:
                    if role not in self.operation_to_allowed_roles[query_string_operation]:
                        break
                else:
                    return

        if not operation_allowed:
            raise AuthExceptionUnauthorized("Access denied: lack of permissions.")
        else:
            raise AuthExceptionUnauthorized("Access denied: You have not permissions to use these admin query string")

    def get_user_list(self):
        return self.backend.get_user_list()

    def _normalize_url(self, url, method):
        # DEPRECATED !!!
        # Removing query strings
        normalized_url = url if '?' not in url else url[:url.find("?")]
        normalized_url_splitted = normalized_url.split("/")
        parameters = {}

        filtered_keys = [key for key in self.resources_to_operations_mapping.keys()
                         if method in key.split()[0]]

        for idx, path_part in enumerate(normalized_url_splitted):
            tmp_keys = []
            for tmp_key in filtered_keys:
                splitted = tmp_key.split()[1].split("/")
                if idx >= len(splitted):
                    continue
                elif "<" in splitted[idx] and ">" in splitted[idx]:
                    if splitted[idx] == "<artifactPath>":
                        tmp_keys.append(tmp_key)
                        continue
                    elif idx == len(normalized_url_splitted) - 1 and \
                            len(normalized_url_splitted) != len(splitted):
                        continue
                    else:
                        tmp_keys.append(tmp_key)
                elif splitted[idx] == path_part:
                    if idx == len(normalized_url_splitted) - 1 and \
                            len(normalized_url_splitted) != len(splitted):
                        continue
                    else:
                        tmp_keys.append(tmp_key)
            filtered_keys = tmp_keys
            if len(filtered_keys) == 1 and \
                    filtered_keys[0].split("/")[-1] == "<artifactPath>":
                break

        if len(filtered_keys) == 0:
            raise AuthException("Cannot make an authorization decision. URL not found. URL: {0}".format(url))
        elif len(filtered_keys) > 1:
            raise AuthException("Cannot make an authorization decision. Multiple URLs found. URL: {0}".format(url))

        filtered_key = filtered_keys[0]

        for idx, path_part in enumerate(filtered_key.split()[1].split("/")):
            if "<" in path_part and ">" in path_part:
                if path_part == "<artifactPath>":
                    parameters[path_part[1:-1]] = "/".join(normalized_url_splitted[idx:])
                else:
                    parameters[path_part[1:-1]] = normalized_url_splitted[idx]

        return filtered_key, parameters

    def _internal_get_token_list(self, token_info):
        now = time()
        token_list = self.db.get_list("tokens", {"username": token_info["username"], "expires.gt": now})
        return token_list

    def _internal_get_token(self, token_info, token_id):
        token_value = self.db.get_one("tokens", {"_id": token_id}, fail_on_empty=False)
        if not token_value:
            raise AuthException("token not found", http_code=HTTPStatus.NOT_FOUND)
        if token_value["username"] != token_info["username"] and not token_info["admin"]:
            raise AuthException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        return token_value

    def _internal_tokens_prune(self, now=None):
        now = now or time()
        if not self.next_db_prune_time or self.next_db_prune_time >= now:
            self.db.del_list("tokens", {"expires.lt": now})
            self.next_db_prune_time = self.periodin_db_pruning + now
            self.tokens_cache.clear()  # force to reload tokens from database
