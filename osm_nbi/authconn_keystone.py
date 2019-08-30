# -*- coding: utf-8 -*-

# Copyright 2018 Whitestack, LLC
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
# contact: esousa@whitestack.com or glavado@whitestack.com
##

"""
AuthconnKeystone implements implements the connector for
Openstack Keystone and leverages the RBAC model, to bring
it for OSM.
"""


__author__ = "Eduardo Sousa <esousa@whitestack.com>"
__date__ = "$27-jul-2018 23:59:59$"

from authconn import Authconn, AuthException, AuthconnOperationException, AuthconnNotFoundException, \
    AuthconnConflictException

import logging
import requests
import time
from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneauth1.exceptions.http import Conflict
from keystoneclient.v3 import client
from http import HTTPStatus
from validation import is_valid_uuid


class AuthconnKeystone(Authconn):
    def __init__(self, config):
        Authconn.__init__(self, config)

        self.logger = logging.getLogger("nbi.authenticator.keystone")

        self.auth_url = "http://{0}:{1}/v3".format(config.get("auth_url", "keystone"), config.get("auth_port", "5000"))
        self.user_domain_name = config.get("user_domain_name", "default")
        self.admin_project = config.get("service_project", "service")
        self.admin_username = config.get("service_username", "nbi")
        self.admin_password = config.get("service_password", "nbi")
        self.project_domain_name = config.get("project_domain_name", "default")

        # Waiting for Keystone to be up
        available = None
        counter = 300
        while available is None:
            time.sleep(1)
            try:
                result = requests.get(self.auth_url)
                available = True if result.status_code == 200 else None
            except Exception:
                counter -= 1
                if counter == 0:
                    raise AuthException("Keystone not available after 300s timeout")

        self.auth = v3.Password(user_domain_name=self.user_domain_name,
                                username=self.admin_username,
                                password=self.admin_password,
                                project_domain_name=self.project_domain_name,
                                project_name=self.admin_project,
                                auth_url=self.auth_url)
        self.sess = session.Session(auth=self.auth)
        self.keystone = client.Client(session=self.sess)

    def authenticate(self, user, password, project=None, token_info=None):
        """
        Authenticate a user using username/password or token_info, plus project
        :param user: user: name, id or None
        :param password: password or None
        :param project: name, id, or None. If None first found project will be used to get an scope token
        :param token_info: previous token_info to obtain authorization
        :return: the scoped token info or raises an exception. The token is a dictionary with:
            _id:  token string id,
            username: username,
            project_id: scoped_token project_id,
            project_name: scoped_token project_name,
            expires: epoch time when it expires,

        """
        try:
            username = None
            user_id = None
            project_id = None
            project_name = None

            if user:
                if is_valid_uuid(user):
                    user_id = user
                else:
                    username = user

                # get an unscoped token firstly
                unscoped_token = self.keystone.get_raw_token_from_identity_service(
                    auth_url=self.auth_url,
                    user_id=user_id,
                    username=username,
                    password=password,
                    user_domain_name=self.user_domain_name,
                    project_domain_name=self.project_domain_name)
            elif token_info:
                unscoped_token = self.keystone.tokens.validate(token=token_info.get("_id"))
            else:
                raise AuthException("Provide credentials: username/password or Authorization Bearer token",
                                    http_code=HTTPStatus.UNAUTHORIZED)

            if not project:
                # get first project for the user
                project_list = self.keystone.projects.list(user=unscoped_token["user"]["id"])
                if not project_list:
                    raise AuthException("The user {} has not any project and cannot be used for authentication".
                                        format(user), http_code=HTTPStatus.UNAUTHORIZED)
                project_id = project_list[0].id
            else:
                if is_valid_uuid(project):
                    project_id = project
                else:
                    project_name = project

            scoped_token = self.keystone.get_raw_token_from_identity_service(
                auth_url=self.auth_url,
                project_name=project_name,
                project_id=project_id,
                user_domain_name=self.user_domain_name,
                project_domain_name=self.project_domain_name,
                token=unscoped_token["auth_token"])

            auth_token = {
                "_id": scoped_token.auth_token,
                "id": scoped_token.auth_token,
                "user_id": scoped_token.user_id,
                "username": scoped_token.username,
                "project_id": scoped_token.project_id,
                "project_name": scoped_token.project_name,
                "expires": scoped_token.expires.timestamp(),
                "issued_at": scoped_token.issued.timestamp()
            }

            return auth_token
        except ClientException as e:
            # self.logger.exception("Error during user authentication using keystone. Method: basic: {}".format(e))
            raise AuthException("Error during user authentication using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    # def authenticate_with_token(self, token, project=None):
    #     """
    #     Authenticate a user using a token. Can be used to revalidate the token
    #     or to get a scoped token.
    #
    #     :param token: a valid token.
    #     :param project: (optional) project for a scoped token.
    #     :return: return a revalidated token, scoped if a project was passed or
    #     the previous token was already scoped.
    #     """
    #     try:
    #         token_info = self.keystone.tokens.validate(token=token)
    #         projects = self.keystone.projects.list(user=token_info["user"]["id"])
    #         project_names = [project.name for project in projects]
    #
    #         new_token = self.keystone.get_raw_token_from_identity_service(
    #             auth_url=self.auth_url,
    #             token=token,
    #             project_name=project,
    #             project_id=None,
    #             user_domain_name=self.user_domain_name,
    #             project_domain_name=self.project_domain_name)
    #
    #         return new_token["auth_token"], project_names
    #     except ClientException as e:
    #         # self.logger.exception("Error during user authentication using keystone. Method: bearer: {}".format(e))
    #         raise AuthException("Error during user authentication using Keystone: {}".format(e),
    #                             http_code=HTTPStatus.UNAUTHORIZED)

    def validate_token(self, token):
        """
        Check if the token is valid.

        :param token: token id to be validated
        :return: dictionary with information associated with the token:
             "expires":
             "_id": token_id,
             "project_id": project_id,
             "username": ,
             "roles": list with dict containing {name, id}
         If the token is not valid an exception is raised.
        """
        if not token:
            return

        try:
            token_info = self.keystone.tokens.validate(token=token)
            ses = {
                "_id": token_info["auth_token"],
                "id": token_info["auth_token"],
                "project_id": token_info["project"]["id"],
                "project_name": token_info["project"]["name"],
                "user_id": token_info["user"]["id"],
                "username": token_info["user"]["name"],
                "roles": token_info["roles"],
                "expires": token_info.expires.timestamp(),
                "issued_at": token_info.issued.timestamp()
            }

            return ses
        except ClientException as e:
            # self.logger.exception("Error during token validation using keystone: {}".format(e))
            raise AuthException("Error during token validation using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def revoke_token(self, token):
        """
        Invalidate a token.

        :param token: token to be revoked
        """
        try:
            self.logger.info("Revoking token: " + token)
            self.keystone.tokens.revoke_token(token=token)

            return True
        except ClientException as e:
            # self.logger.exception("Error during token revocation using keystone: {}".format(e))
            raise AuthException("Error during token revocation using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def get_user_project_list(self, token):
        """
        Get all the projects associated with a user.

        :param token: valid token
        :return: list of projects
        """
        try:
            token_info = self.keystone.tokens.validate(token=token)
            projects = self.keystone.projects.list(user=token_info["user"]["id"])
            project_names = [project.name for project in projects]

            return project_names
        except ClientException as e:
            # self.logger.exception("Error during user project listing using keystone: {}".format(e))
            raise AuthException("Error during user project listing using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def get_user_role_list(self, token):
        """
        Get role list for a scoped project.

        :param token: scoped token.
        :return: returns the list of roles for the user in that project. If
        the token is unscoped it returns None.
        """
        try:
            token_info = self.keystone.tokens.validate(token=token)
            roles_info = self.keystone.roles.list(user=token_info["user"]["id"], project=token_info["project"]["id"])

            roles = [role.name for role in roles_info]

            return roles
        except ClientException as e:
            # self.logger.exception("Error during user role listing using keystone: {}".format(e))
            raise AuthException("Error during user role listing using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def create_user(self, user, password):
        """
        Create a user.

        :param user: username.
        :param password: password.
        :raises AuthconnOperationException: if user creation failed.
        :return: returns the id of the user in keystone.
        """
        try:
            new_user = self.keystone.users.create(user, password=password, domain=self.user_domain_name)
            return {"username": new_user.name, "_id": new_user.id}
        except Conflict as e:
            # self.logger.exception("Error during user creation using keystone: {}".format(e))
            raise AuthconnOperationException(e, http_code=HTTPStatus.CONFLICT)
        except ClientException as e:
            # self.logger.exception("Error during user creation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user creation using Keystone: {}".format(e))

    def update_user(self, user, new_name=None, new_password=None):
        """
        Change the user name and/or password.

        :param user: username or user_id
        :param new_name: new name
        :param new_password: new password.
        :raises AuthconnOperationException: if change failed.
        """
        try:
            if is_valid_uuid(user):
                user_id = user
            else:
                user_obj_list = self.keystone.users.list(name=user)
                if not user_obj_list:
                    raise AuthconnNotFoundException("User '{}' not found".format(user))
                user_id = user_obj_list[0].id

            self.keystone.users.update(user_id, password=new_password, name=new_name)
        except ClientException as e:
            # self.logger.exception("Error during user password/name update using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user password/name update using Keystone: {}".format(e))

    def delete_user(self, user_id):
        """
        Delete user.

        :param user_id: user identifier.
        :raises AuthconnOperationException: if user deletion failed.
        """
        try:
            # users = self.keystone.users.list()
            # user_obj = [user for user in users if user.id == user_id][0]
            # result, _ = self.keystone.users.delete(user_obj)

            result, detail = self.keystone.users.delete(user_id)
            if result.status_code != 204:
                raise ClientException("error {} {}".format(result.status_code, detail))

            return True
        except ClientException as e:
            # self.logger.exception("Error during user deletion using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user deletion using Keystone: {}".format(e))

    def get_user_list(self, filter_q=None):
        """
        Get user list.

        :param filter_q: dictionary to filter user list by name (username is also admited) and/or _id
        :return: returns a list of users.
        """
        try:
            filter_name = None
            if filter_q:
                filter_name = filter_q.get("name") or filter_q.get("username")
            users = self.keystone.users.list(name=filter_name)
            users = [{
                "username": user.name,
                "_id": user.id,
                "id": user.id
            } for user in users if user.name != self.admin_username]

            if filter_q and filter_q.get("_id"):
                users = [user for user in users if filter_q["_id"] == user["_id"]]

            for user in users:
                projects = self.keystone.projects.list(user=user["_id"])
                projects = [{
                    "name": project.name,
                    "_id": project.id,
                    "id": project.id
                } for project in projects]

                for project in projects:
                    roles = self.keystone.roles.list(user=user["_id"], project=project["_id"])
                    roles = [{
                        "name": role.name,
                        "_id": role.id,
                        "id": role.id
                    } for role in roles]
                    project["roles"] = roles

                user["projects"] = projects

            return users
        except ClientException as e:
            # self.logger.exception("Error during user listing using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user listing using Keystone: {}".format(e))

    def get_role_list(self, filter_q=None):
        """
        Get role list.

        :param filter_q: dictionary to filter role list by _id and/or name.
        :return: returns the list of roles.
        """
        try:
            filter_name = None
            if filter_q:
                filter_name = filter_q.get("name")
            roles_list = self.keystone.roles.list(name=filter_name)

            roles = [{
                "name": role.name,
                "_id": role.id
            } for role in roles_list if role.name != "service"]

            if filter_q and filter_q.get("_id"):
                roles = [role for role in roles if filter_q["_id"] == role["_id"]]

            return roles
        except ClientException as e:
            # self.logger.exception("Error during user role listing using keystone: {}".format(e))
            raise AuthException("Error during user role listing using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def create_role(self, role):
        """
        Create a role.

        :param role: role name.
        :raises AuthconnOperationException: if role creation failed.
        """
        try:
            result = self.keystone.roles.create(role)
            return result.id
        except Conflict as ex:
            raise AuthconnConflictException(str(ex))
        except ClientException as e:
            # self.logger.exception("Error during role creation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role creation using Keystone: {}".format(e))

    def delete_role(self, role_id):
        """
        Delete a role.

        :param role_id: role identifier.
        :raises AuthconnOperationException: if role deletion failed.
        """
        try:
            result, detail = self.keystone.roles.delete(role_id)

            if result.status_code != 204:
                raise ClientException("error {} {}".format(result.status_code, detail))

            return True
        except ClientException as e:
            # self.logger.exception("Error during role deletion using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role deletion using Keystone: {}".format(e))

    def update_role(self, role, new_name):
        """
        Change the name of a role
        :param role: role  name or id to be changed
        :param new_name: new name
        :return: None
        """
        try:
            if is_valid_uuid(role):
                role_id = role
            else:
                role_obj_list = self.keystone.roles.list(name=role)
                if not role_obj_list:
                    raise AuthconnNotFoundException("Role '{}' not found".format(role))
                role_id = role_obj_list[0].id
            self.keystone.roles.update(role_id, name=new_name)
        except ClientException as e:
            # self.logger.exception("Error during role update using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role updating using Keystone: {}".format(e))

    def get_project_list(self, filter_q=None):
        """
        Get all the projects.

        :param filter_q: dictionary to filter project list.
        :return: list of projects
        """
        try:
            filter_name = None
            if filter_q:
                filter_name = filter_q.get("name")
            projects = self.keystone.projects.list(name=filter_name)

            projects = [{
                "name": project.name,
                "_id": project.id
            } for project in projects]

            if filter_q and filter_q.get("_id"):
                projects = [project for project in projects
                            if filter_q["_id"] == project["_id"]]

            return projects
        except ClientException as e:
            # self.logger.exception("Error during user project listing using keystone: {}".format(e))
            raise AuthException("Error during user project listing using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def create_project(self, project):
        """
        Create a project.

        :param project: project name.
        :return: the internal id of the created project
        :raises AuthconnOperationException: if project creation failed.
        """
        try:
            result = self.keystone.projects.create(project, self.project_domain_name)
            return result.id
        except ClientException as e:
            # self.logger.exception("Error during project creation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during project creation using Keystone: {}".format(e))

    def delete_project(self, project_id):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises AuthconnOperationException: if project deletion failed.
        """
        try:
            # projects = self.keystone.projects.list()
            # project_obj = [project for project in projects if project.id == project_id][0]
            # result, _ = self.keystone.projects.delete(project_obj)

            result, detail = self.keystone.projects.delete(project_id)
            if result.status_code != 204:
                raise ClientException("error {} {}".format(result.status_code, detail))

            return True
        except ClientException as e:
            # self.logger.exception("Error during project deletion using keystone: {}".format(e))
            raise AuthconnOperationException("Error during project deletion using Keystone: {}".format(e))

    def update_project(self, project_id, new_name):
        """
        Change the name of a project
        :param project_id: project to be changed
        :param new_name: new name
        :return: None
        """
        try:
            self.keystone.projects.update(project_id, name=new_name)
        except ClientException as e:
            # self.logger.exception("Error during project update using keystone: {}".format(e))
            raise AuthconnOperationException("Error during project deletion using Keystone: {}".format(e))

    def assign_role_to_user(self, user, project, role):
        """
        Assigning a role to a user in a project.

        :param user: username.
        :param project: project name.
        :param role: role name.
        :raises AuthconnOperationException: if role assignment failed.
        """
        try:
            if is_valid_uuid(user):
                user_obj = self.keystone.users.get(user)
            else:
                user_obj_list = self.keystone.users.list(name=user)
                if not user_obj_list:
                    raise AuthconnNotFoundException("User '{}' not found".format(user))
                user_obj = user_obj_list[0]

            if is_valid_uuid(project):
                project_obj = self.keystone.projects.get(project)
            else:
                project_obj_list = self.keystone.projects.list(name=project)
                if not project_obj_list:
                    raise AuthconnNotFoundException("Project '{}' not found".format(project))
                project_obj = project_obj_list[0]

            if is_valid_uuid(role):
                role_obj = self.keystone.roles.get(role)
            else:
                role_obj_list = self.keystone.roles.list(name=role)
                if not role_obj_list:
                    raise AuthconnNotFoundException("Role '{}' not found".format(role))
                role_obj = role_obj_list[0]

            self.keystone.roles.grant(role_obj, user=user_obj, project=project_obj)
        except ClientException as e:
            # self.logger.exception("Error during user role assignment using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role '{}' assignment to user '{}' and project '{}' using "
                                             "Keystone: {}".format(role, user, project, e))

    def remove_role_from_user(self, user, project, role):
        """
        Remove a role from a user in a project.

        :param user: username.
        :param project: project name or id.
        :param role: role name or id.

        :raises AuthconnOperationException: if role assignment revocation failed.
        """
        try:
            if is_valid_uuid(user):
                user_obj = self.keystone.users.get(user)
            else:
                user_obj_list = self.keystone.users.list(name=user)
                if not user_obj_list:
                    raise AuthconnNotFoundException("User '{}' not found".format(user))
                user_obj = user_obj_list[0]

            if is_valid_uuid(project):
                project_obj = self.keystone.projects.get(project)
            else:
                project_obj_list = self.keystone.projects.list(name=project)
                if not project_obj_list:
                    raise AuthconnNotFoundException("Project '{}' not found".format(project))
                project_obj = project_obj_list[0]

            if is_valid_uuid(role):
                role_obj = self.keystone.roles.get(role)
            else:
                role_obj_list = self.keystone.roles.list(name=role)
                if not role_obj_list:
                    raise AuthconnNotFoundException("Role '{}' not found".format(role))
                role_obj = role_obj_list[0]

            self.keystone.roles.revoke(role_obj, user=user_obj, project=project_obj)
        except ClientException as e:
            # self.logger.exception("Error during user role revocation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role '{}' revocation to user '{}' and project '{}' using "
                                             "Keystone: {}".format(role, user, project, e))
