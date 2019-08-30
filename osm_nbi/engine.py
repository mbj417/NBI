# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import yaml
from osm_common import dbmongo, dbmemory, fslocal, msglocal, msgkafka, version as common_version
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from http import HTTPStatus

from authconn_keystone import AuthconnKeystone
from authconn_internal import AuthconnInternal
from base_topic import EngineException, versiontuple
from admin_topics import UserTopic, ProjectTopic, VimAccountTopic, WimAccountTopic, SdnTopic
from admin_topics import UserTopicAuth, ProjectTopicAuth, RoleTopicAuth
from descriptor_topics import VnfdTopic, NsdTopic, PduTopic, NstTopic
from instance_topics import NsrTopic, VnfrTopic, NsLcmOpTopic, NsiTopic, NsiLcmOpTopic
from pmjobs_topics import PmJobsTopic
from base64 import b64encode
from os import urandom, path
from threading import Lock

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"
min_common_version = "0.1.16"


class Engine(object):
    map_from_topic_to_class = {
        "vnfds": VnfdTopic,
        "nsds": NsdTopic,
        "nsts": NstTopic,
        "pdus": PduTopic,
        "nsrs": NsrTopic,
        "vnfrs": VnfrTopic,
        "nslcmops": NsLcmOpTopic,
        "vim_accounts": VimAccountTopic,
        "wim_accounts": WimAccountTopic,
        "sdns": SdnTopic,
        "users": UserTopic,
        "projects": ProjectTopic,
        "roles": RoleTopicAuth,   # Valid for both internal and keystone authentication backends
        "nsis": NsiTopic,
        "nsilcmops": NsiLcmOpTopic
        # [NEW_TOPIC]: add an entry here
        # "pm_jobs": PmJobsTopic will be added manually because it needs other parameters
    }

    map_target_version_to_int = {
        "1.0": 1000,
        "1.1": 1001,
        "1.2": 1002,
        # Add new versions here
    }

    def __init__(self):
        self.db = None
        self.fs = None
        self.msg = None
        self.auth = None
        self.config = None
        self.operations = None
        self.logger = logging.getLogger("nbi.engine")
        self.map_topic = {}
        self.write_lock = None

    def start(self, config):
        """
        Connect to database, filesystem storage, and messaging
        :param config: two level dictionary with configuration. Top level should contain 'database', 'storage',
        :return: None
        """
        self.config = config
        # check right version of common
        if versiontuple(common_version) < versiontuple(min_common_version):
            raise EngineException("Not compatible osm/common version '{}'. Needed '{}' or higher".format(
                common_version, min_common_version))

        try:
            if not self.db:
                if config["database"]["driver"] == "mongo":
                    self.db = dbmongo.DbMongo()
                    self.db.db_connect(config["database"])
                elif config["database"]["driver"] == "memory":
                    self.db = dbmemory.DbMemory()
                    self.db.db_connect(config["database"])
                else:
                    raise EngineException("Invalid configuration param '{}' at '[database]':'driver'".format(
                        config["database"]["driver"]))
            if not self.fs:
                if config["storage"]["driver"] == "local":
                    self.fs = fslocal.FsLocal()
                    self.fs.fs_connect(config["storage"])
                else:
                    raise EngineException("Invalid configuration param '{}' at '[storage]':'driver'".format(
                        config["storage"]["driver"]))
            if not self.msg:
                if config["message"]["driver"] == "local":
                    self.msg = msglocal.MsgLocal()
                    self.msg.connect(config["message"])
                elif config["message"]["driver"] == "kafka":
                    self.msg = msgkafka.MsgKafka()
                    self.msg.connect(config["message"])
                else:
                    raise EngineException("Invalid configuration param '{}' at '[message]':'driver'".format(
                        config["message"]["driver"]))
            if not self.auth:
                if config["authentication"]["backend"] == "keystone":
                    self.auth = AuthconnKeystone(config["authentication"])
                else:
                    self.auth = AuthconnInternal(config["authentication"], self.db, dict())   # TO BE CONFIRMED
            if not self.operations:
                if "resources_to_operations" in config["rbac"]:
                    resources_to_operations_file = config["rbac"]["resources_to_operations"]
                else:
                    possible_paths = (
                        __file__[:__file__.rfind("engine.py")] + "resources_to_operations.yml",
                        "./resources_to_operations.yml"
                    )
                    for config_file in possible_paths:
                        if path.isfile(config_file):
                            resources_to_operations_file = config_file
                            break
                    if not resources_to_operations_file:                   
                        raise EngineException("Invalid permission configuration: resources_to_operations file missing")

                with open(resources_to_operations_file, 'r') as f:
                    resources_to_operations = yaml.load(f)

                self.operations = []

                for _, value in resources_to_operations["resources_to_operations"].items():
                    if value not in self.operations:
                        self.operations += [value]

            if config["authentication"]["backend"] == "keystone":
                self.map_from_topic_to_class["users"] = UserTopicAuth
                self.map_from_topic_to_class["projects"] = ProjectTopicAuth
                self.map_from_topic_to_class["roles"] = RoleTopicAuth

            self.write_lock = Lock()
            # create one class per topic
            for topic, topic_class in self.map_from_topic_to_class.items():
                if self.auth and topic_class in (UserTopicAuth, ProjectTopicAuth):
                    self.map_topic[topic] = topic_class(self.db, self.fs, self.msg, self.auth)
                elif self.auth and topic_class == RoleTopicAuth:
                    self.map_topic[topic] = topic_class(self.db, self.fs, self.msg, self.auth,
                                                        self.operations)
                else:
                    self.map_topic[topic] = topic_class(self.db, self.fs, self.msg)
            
            self.map_topic["pm_jobs"] = PmJobsTopic(config["prometheus"].get("host"), config["prometheus"].get("port"))
        except (DbException, FsException, MsgException) as e:
            raise EngineException(str(e), http_code=e.http_code)

    def stop(self):
        try:
            if self.db:
                self.db.db_disconnect()
            if self.fs:
                self.fs.fs_disconnect()
            if self.msg:
                self.msg.disconnect()
            self.write_lock = None
        except (DbException, FsException, MsgException) as e:
            raise EngineException(str(e), http_code=e.http_code)

    def new_item(self, rollback, session, topic, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into database. For nsds and vnfds it creates an almost empty DISABLED  entry,
        that must be completed with a call to method upload_content
        :param rollback: list to append created items at database in case a rollback must to be done
        :param session: contains the used login username and working project, force to avoid checkins, public
        :param topic: it can be: users, projects, vim_accounts, sdns, nsrs, nsds, vnfds
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        with self.write_lock:
            return self.map_topic[topic].new(rollback, session, indata, kwargs, headers)

    def upload_content(self, session, topic, _id, indata, kwargs, headers):
        """
        Upload content for an already created entry (_id)
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        with self.write_lock:
            return self.map_topic[topic].upload_content(session, _id, indata, kwargs, headers)

    def get_item_list(self, session, topic, filter_q=None):
        """
        Get a list of items
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter_q.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].list(session, filter_q)

    def get_item(self, session, topic, _id):
        """
        Get complete information on an item
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :return: dictionary, raise exception if not found.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].show(session, _id)

    def get_file(self, session, topic, _id, path=None, accept_header=None):
        """
        Get descriptor package or artifact file content
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :param path: artifact path or "$DESCRIPTOR" or None
        :param accept_header: Content of Accept header. Must contain applition/zip or/and text/plain
        :return: opened file plus Accept format or raises an exception
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].get_file(session, _id, path, accept_header)

    def del_item_list(self, session, topic, _filter=None):
        """
        Delete a list of items
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param _filter: filter of data to be applied
        :return: The deleted list, it can be empty if no one match the _filter.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        with self.write_lock:
            return self.map_topic[topic].delete_list(session, _filter)

    def del_item(self, session, topic, _id):
        """
        Delete item by its internal id
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param _id: server id of the item
        :return: dictionary with deleted item _id. It raises exception if not found.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        with self.write_lock:
            return self.map_topic[topic].delete(session, _id)

    def edit_item(self, session, topic, _id, indata=None, kwargs=None):
        """
        Update an existing entry at database
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param _id: identifier to be updated
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :return: dictionary, raise exception if not found.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        with self.write_lock:
            return self.map_topic[topic].edit(session, _id, indata, kwargs)

    def create_admin_project(self):
        """
        Creates a new project 'admin' into database if database is empty. Useful for initialization.
        :return: _id identity of the inserted data, or None
        """

        projects = self.db.get_one("projects", fail_on_empty=False, fail_on_more=False)
        if projects:
            return None
        project_desc = {"name": "admin"}
        fake_session = {"project_id": "admin", "username": "admin", "admin": True, "force": True, "public": None}
        rollback_list = []
        _id = self.map_topic["projects"].new(rollback_list, fake_session, project_desc)
        return _id

    def create_admin_user(self):
        """
        Creates a new user admin/admin into database if database is empty. Useful for initialization
        :return: _id identity of the inserted data, or None
        """
        users = self.db.get_one("users", fail_on_empty=False, fail_on_more=False)
        if users:
            return None
        user_desc = {"username": "admin", "password": "admin", "projects": ["admin"]}
        fake_session = {"project_id": "admin", "username": "admin", "admin": True, "force": True, "public": None}
        rollback_list = []
        _id = self.map_topic["users"].new(rollback_list, fake_session, user_desc)
        return _id

    def create_admin(self):
        """
        Creates new 'admin' user and project into database if database is empty. Useful for initialization.
        :return: _id identity of the inserted data, or None
        """
        project_id = self.create_admin_project()
        user_id = self.create_admin_user()
        if project_id or user_id:
            return {'project_id': project_id, 'user_id': user_id}
        else:
            return None

    def upgrade_db(self, current_version, target_version):
        if target_version not in self.map_target_version_to_int.keys():
            raise EngineException("Cannot upgrade to version '{}' with this version of code".format(target_version),
                                  http_code=HTTPStatus.INTERNAL_SERVER_ERROR)

        if current_version == target_version:
            return
        
        target_version_int = self.map_target_version_to_int[target_version]

        if not current_version:
            # create database version
            serial = urandom(32)
            version_data = {
                "_id": "version",               # Always "version"
                "version_int": 1000,            # version number
                "version": "1.0",               # version text
                "date": "2018-10-25",           # version date
                "description": "added serial",  # changes in this version
                'status': "ENABLED",            # ENABLED, DISABLED (migration in process), ERROR,
                'serial': b64encode(serial)
            }
            self.db.create("admin", version_data)
            self.db.set_secret_key(serial)
            current_version = "1.0"
            
        if current_version in ("1.0", "1.1") and target_version_int >= self.map_target_version_to_int["1.2"]:
            table = "roles_operations" if self.config['authentication']['backend'] == "keystone" else "roles"
            self.db.del_list(table)
            
            version_data = {
                "_id": "version",
                "version_int": 1002,
                "version": "1.2",
                "date": "2019-06-11",
                "description": "set new format for roles_operations"
            }

            self.db.set_one("admin", {"_id": "version"}, version_data)
            current_version = "1.2"
            # TODO add future migrations here

    def init_db(self, target_version='1.0'):
        """
        Init database if empty. If not empty it checks that database version and migrates if needed
        If empty, it creates a new user admin/admin at 'users' and a new entry at 'version'
        :param target_version: check desired database version. Migrate to it if possible or raises exception
        :return: None if ok, exception if error or if the version is different.
        """

        version_data = self.db.get_one("admin", {"_id": "version"}, fail_on_empty=False, fail_on_more=True)
        # check database status is ok
        if version_data and version_data.get("status") != 'ENABLED':
            raise EngineException("Wrong database status '{}'".format(
                version_data["status"]), HTTPStatus.INTERNAL_SERVER_ERROR)

        # check version
        db_version = None if not version_data else version_data.get("version")
        if db_version != target_version:
            self.upgrade_db(db_version, target_version)

        # create admin project&user if they don't exist
        if self.config['authentication']['backend'] == 'internal' or not self.auth:
            self.create_admin()
        
        return
