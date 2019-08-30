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
Authconn implements an Abstract class for the Auth backend connector
plugins with the definition of the methods to be implemented.
"""

__author__ = "Eduardo Sousa <esousa@whitestack.com>"
__date__ = "$27-jul-2018 23:59:59$"

from http import HTTPStatus


class AuthException(Exception):
    """
    Authentication error, because token, user password not recognized
    """
    def __init__(self, message, http_code=HTTPStatus.UNAUTHORIZED):
        super(AuthException, self).__init__(message)
        self.http_code = http_code


class AuthExceptionUnauthorized(AuthException):
    """
    Authentication error, because not having rights to make this operation
    """
    pass


class AuthconnException(Exception):
    """
    Common and base class Exception for all authconn exceptions.
    """
    def __init__(self, message, http_code=HTTPStatus.UNAUTHORIZED):
        super(AuthconnException, self).__init__(message)
        self.http_code = http_code


class AuthconnConnectionException(AuthconnException):
    """
    Connectivity error with Auth backend.
    """
    def __init__(self, message, http_code=HTTPStatus.BAD_GATEWAY):
        super(AuthconnConnectionException, self).__init__(message, http_code)


class AuthconnNotSupportedException(AuthconnException):
    """
    The request is not supported by the Auth backend.
    """
    def __init__(self, message, http_code=HTTPStatus.NOT_IMPLEMENTED):
        super(AuthconnNotSupportedException, self).__init__(message, http_code)


class AuthconnNotImplementedException(AuthconnException):
    """
    The method is not implemented by the Auth backend.
    """
    def __init__(self, message, http_code=HTTPStatus.NOT_IMPLEMENTED):
        super(AuthconnNotImplementedException, self).__init__(message, http_code)


class AuthconnOperationException(AuthconnException):
    """
    The operation executed failed.
    """
    def __init__(self, message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR):
        super(AuthconnOperationException, self).__init__(message, http_code)


class AuthconnNotFoundException(AuthconnException):
    """
    The operation executed failed because element not found.
    """
    def __init__(self, message, http_code=HTTPStatus.NOT_FOUND):
        super().__init__(message, http_code)


class AuthconnConflictException(AuthconnException):
    """
    The operation has conflicts.
    """
    def __init__(self, message, http_code=HTTPStatus.CONFLICT):
        super().__init__(message, http_code)


class Authconn:
    """
    Abstract base class for all the Auth backend connector plugins.
    Each Auth backend connector plugin must be a subclass of
    Authconn class.
    """
    def __init__(self, config):
        """
        Constructor of the Authconn class.

        Note: each subclass

        :param config: configuration dictionary containing all the
        necessary configuration parameters.
        """
        self.config = config

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
        raise AuthconnNotImplementedException("Should have implemented this")

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
    #     raise AuthconnNotImplementedException("Should have implemented this")

    def validate_token(self, token):
        """
        Check if the token is valid.

        :param token: token to validate
        :return: dictionary with information associated with the token. If the
        token is not valid, returns None.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def revoke_token(self, token):
        """
        Invalidate a token.

        :param token: token to be revoked
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def get_user_project_list(self, token):
        """
        Get all the projects associated with a user.

        :param token: valid token
        :return: list of projects
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def get_user_role_list(self, token):
        """
        Get role list for a scoped project.

        :param token: scoped token.
        :return: returns the list of roles for the user in that project. If
        the token is unscoped it returns None.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def create_user(self, user, password):
        """
        Create a user.

        :param user: username.
        :param password: password.
        :raises AuthconnOperationException: if user creation failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def update_user(self, user, new_name=None, new_password=None):
        """
        Change the user name and/or password.

        :param user: username or user_id
        :param new_name: new name
        :param new_password: new password.
        :raises AuthconnOperationException: if change failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def delete_user(self, user_id):
        """
        Delete user.

        :param user_id: user identifier.
        :raises AuthconnOperationException: if user deletion failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def get_user_list(self, filter_q=None):
        """
        Get user list.

        :param filter_q: dictionary to filter user list by name (username is also admited) and/or _id
        :return: returns a list of users.
        """

    def create_role(self, role):
        """
        Create a role.

        :param role: role name.
        :raises AuthconnOperationException: if role creation failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def delete_role(self, role_id):
        """
        Delete a role.

        :param role_id: role identifier.
        :raises AuthconnOperationException: if user deletion failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def get_role_list(self, filter_q=None):
        """
        Get all the roles.

        :param filter_q: dictionary to filter role list by _id and/or name.
        :return: list of roles
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def update_role(self, role, new_name):
        """
        Change the name of a role
        :param role: role name or id to be changed
        :param new_name: new name
        :return: None
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def create_project(self, project):
        """
        Create a project.

        :param project: project name.
        :return: the internal id of the created project
        :raises AuthconnOperationException: if project creation failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def delete_project(self, project_id):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises AuthconnOperationException: if project deletion failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def get_project_list(self, filter_q=None):
        """
        Get all the projects.

        :param filter_q: dictionary to filter project list, by "name" and/or "_id"
        :return: list of projects
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def update_project(self, project_id, new_name):
        """
        Change the name of a project
        :param project_id: project to be changed
        :param new_name: new name
        :return: None
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def assign_role_to_user(self, user, project, role):
        """
        Assigning a role to a user in a project.

        :param user: username.
        :param project: project name.
        :param role: role name.
        :raises AuthconnOperationException: if role assignment failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")

    def remove_role_from_user(self, user, project, role):
        """
        Remove a role from a user in a project.

        :param user: username.
        :param project: project name.
        :param role: role name.
        :raises AuthconnOperationException: if role assignment revocation failed.
        """
        raise AuthconnNotImplementedException("Should have implemented this")
