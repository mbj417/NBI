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
from uuid import uuid4
from http import HTTPStatus
from time import time
from osm_common.dbbase import deep_update_rfc7396
from validation import validate_input, ValidationError, is_valid_uuid

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class EngineException(Exception):

    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST):
        self.http_code = http_code
        Exception.__init__(self, message)


def get_iterable(input_var):
    """
    Returns an iterable, in case input_var is None it just returns an empty tuple
    :param input_var: can be a list, tuple or None
    :return: input_var or () if it is None
    """
    if input_var is None:
        return ()
    return input_var


def versiontuple(v):
    """utility for compare dot separate versions. Fills with zeros to proper number comparison"""
    filled = []
    for point in v.split("."):
        filled.append(point.zfill(8))
    return tuple(filled)


class BaseTopic:
    # static variables for all instance classes
    topic = None        # to_override
    topic_msg = None    # to_override
    schema_new = None   # to_override
    schema_edit = None  # to_override
    multiproject = True  # True if this Topic can be shared by several projects. Then it contains _admin.projects_read

    # Alternative ID Fields for some Topics
    alt_id_field = {
        "projects": "name",
        "users": "username",
        "roles": "name",
        "roles_operations": "name"
    }

    def __init__(self, db, fs, msg):
        self.db = db
        self.fs = fs
        self.msg = msg
        self.logger = logging.getLogger("nbi.engine")

    @staticmethod
    def id_field(topic, value):
        """Returns ID Field for given topic and field value"""
        if topic in BaseTopic.alt_id_field.keys() and not is_valid_uuid(value):
            return BaseTopic.alt_id_field[topic]
        else:
            return "_id"

    @staticmethod
    def _remove_envelop(indata=None):
        if not indata:
            return {}
        return indata

    def _validate_input_new(self, input, force=False):
        """
        Validates input user content for a new entry. It uses jsonschema. Some overrides will use pyangbind
        :param input: user input content for the new topic
        :param force: may be used for being more tolerant
        :return: The same input content, or a changed version of it.
        """
        if self.schema_new:
            validate_input(input, self.schema_new)
        return input

    def _validate_input_edit(self, input, force=False):
        """
        Validates input user content for an edition. It uses jsonschema. Some overrides will use pyangbind
        :param input: user input content for the new topic
        :param force: may be used for being more tolerant
        :return: The same input content, or a changed version of it.
        """
        if self.schema_edit:
            validate_input(input, self.schema_edit)
        return input

    @staticmethod
    def _get_project_filter(session):
        """
        Generates a filter dictionary for querying database, so that only allowed items for this project can be
        addressed. Only propietary or public can be used. Allowed projects are at _admin.project_read/write. If it is
        not present or contains ANY mean public.
        :param session: contains:
            project_id: project list this session has rights to access. Can be empty, one or several
            set_project: items created will contain this project list  
            force: True or False
            public: True, False or None
            method: "list", "show", "write", "delete"
            admin: True or False
        :return: dictionary with project filter
        """
        p_filter = {}
        project_filter_n = []
        project_filter = list(session["project_id"])

        if session["method"] not in ("list", "delete"):
            if project_filter:
                project_filter.append("ANY")
        elif session["public"] is not None:
            if session["public"]:
                project_filter.append("ANY")
            else:
                project_filter_n.append("ANY")

        if session.get("PROJECT.ne"):
            project_filter_n.append(session["PROJECT.ne"])

        if project_filter:
            if session["method"] in ("list", "show", "delete") or session.get("set_project"):
                p_filter["_admin.projects_read.cont"] = project_filter
            else:
                p_filter["_admin.projects_write.cont"] = project_filter
        if project_filter_n:
            if session["method"] in ("list", "show", "delete") or session.get("set_project"):
                p_filter["_admin.projects_read.ncont"] = project_filter_n
            else:
                p_filter["_admin.projects_write.ncont"] = project_filter_n

        return p_filter

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        pass

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified. This methdo may change it.
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """
        if not self.multiproject:
            return
        # Change public status
        if session["public"] is not None:
            if session["public"] and "ANY" not in final_content["_admin"]["projects_read"]:
                final_content["_admin"]["projects_read"].append("ANY")
                final_content["_admin"]["projects_write"].clear()
            if not session["public"] and "ANY" in final_content["_admin"]["projects_read"]:
                final_content["_admin"]["projects_read"].remove("ANY")

        # Change project status
        if session.get("set_project"):
            for p in session["set_project"]:
                if p not in final_content["_admin"]["projects_read"]:
                    final_content["_admin"]["projects_read"].append(p)

    def check_unique_name(self, session, name, _id=None):
        """
        Check that the name is unique for this project
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param name: name to be checked
        :param _id: If not None, ignore this entry that are going to change
        :return: None or raises EngineException
        """
        if not self.multiproject:
            _filter = {}
        else:
            _filter = self._get_project_filter(session)
        _filter["name"] = name
        if _id:
            _filter["_id.neq"] = _id
        if self.db.get_one(self.topic, _filter, fail_on_empty=False, fail_on_more=False):
            raise EngineException("name '{}' already exists for {}".format(name, self.topic), HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        """
        Modifies content descriptor to include _admin
        :param content: descriptor to be modified
        :param project_id: if included, it add project read/write permissions. Can be None or a list
        :param make_public: if included it is generated as public for reading.
        :return: None, but content is modified
        """
        now = time()
        if "_admin" not in content:
            content["_admin"] = {}
        if not content["_admin"].get("created"):
            content["_admin"]["created"] = now
        content["_admin"]["modified"] = now
        if not content.get("_id"):
            content["_id"] = str(uuid4())
        if project_id is not None:
            if not content["_admin"].get("projects_read"):
                content["_admin"]["projects_read"] = list(project_id)
                if make_public:
                    content["_admin"]["projects_read"].append("ANY")
            if not content["_admin"].get("projects_write"):
                content["_admin"]["projects_write"] = list(project_id)

    @staticmethod
    def format_on_edit(final_content, edit_content):
        if final_content.get("_admin"):
            now = time()
            final_content["_admin"]["modified"] = now

    def _send_msg(self, action, content):
        if self.topic_msg:
            content.pop("_admin", None)
            self.msg.write(self.topic_msg, action, content)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        pass

    @staticmethod
    def _update_input_with_kwargs(desc, kwargs):
        """
        Update descriptor with the kwargs. It contains dot separated keys
        :param desc: dictionary to be updated
        :param kwargs: plain dictionary to be used for updating.
        :return: None, 'desc' is modified. It raises EngineException.
        """
        if not kwargs:
            return
        try:
            for k, v in kwargs.items():
                update_content = desc
                kitem_old = None
                klist = k.split(".")
                for kitem in klist:
                    if kitem_old is not None:
                        update_content = update_content[kitem_old]
                    if isinstance(update_content, dict):
                        kitem_old = kitem
                    elif isinstance(update_content, list):
                        kitem_old = int(kitem)
                    else:
                        raise EngineException(
                            "Invalid query string '{}'. Descriptor is not a list nor dict at '{}'".format(k, kitem))
                update_content[kitem_old] = v
        except KeyError:
            raise EngineException(
                "Invalid query string '{}'. Descriptor does not contain '{}'".format(k, kitem_old))
        except ValueError:
            raise EngineException("Invalid query string '{}'. Expected integer index list instead of '{}'".format(
                k, kitem))
        except IndexError:
            raise EngineException(
                "Invalid query string '{}'. Index '{}' out of  range".format(k, kitem_old))

    def show(self, session, _id):
        """
        Get complete information on an topic
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        if not self.multiproject:
            filter_db = {}
        else:
            filter_db = self._get_project_filter(session)
        # To allow project&user addressing by name AS WELL AS _id
        filter_db[BaseTopic.id_field(self.topic, _id)] = _id
        return self.db.get_one(self.topic, filter_db)
        # TODO transform data for SOL005 URL requests
        # TODO remove _admin if not admin

    def get_file(self, session, _id, path=None, accept_header=None):
        """
        Only implemented for descriptor topics. Return the file content of a descriptor
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: Identity of the item to get content
        :param path: artifact path or "$DESCRIPTOR" or None
        :param accept_header: Content of Accept header. Must contain applition/zip or/and text/plain
        :return: opened file or raises an exception
        """
        raise EngineException("Method get_file not valid for this topic", HTTPStatus.INTERNAL_SERVER_ERROR)

    def list(self, session, filter_q=None):
        """
        Get a list of the topic that matches a filter
        :param session: contains the used login username and working project
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        if not filter_q:
            filter_q = {}
        if self.multiproject:
            filter_q.update(self._get_project_filter(session))

        # TODO transform data for SOL005 URL requests. Transform filtering
        # TODO implement "field-type" query string SOL005
        return self.db.get_list(self.topic, filter_q)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into database.
        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data.
        """
        try:
            content = self._remove_envelop(indata)

            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, force=session["force"])
            self.check_conflict_on_new(session, content)
            self.format_on_new(content, project_id=session["project_id"], make_public=session["public"])
            _id = self.db.create(self.topic, content)
            rollback.append({"topic": self.topic, "_id": _id})
            self._send_msg("create", content)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def upload_content(self, session, _id, indata, kwargs, headers):
        """
        Only implemented for descriptor topics.  Used for receiving content by chunks (with a transaction_id header
        and/or gzip file. It will store and extract)
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id : the database id of entry to be updated
        :param indata: http body request
        :param kwargs: user query string to override parameters. NOT USED
        :param headers:  http request headers
        :return: True package has is completely uploaded or False if partial content has been uplodaed.
            Raise exception on error
        """
        raise EngineException("Method upload_content not valid for this topic", HTTPStatus.INTERNAL_SERVER_ERROR)

    def delete_list(self, session, filter_q=None):
        """
        Delete a several entries of a topic. This is for internal usage and test only, not exposed to NBI API
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param filter_q: filter of data to be applied
        :return: The deleted list, it can be empty if no one match the filter.
        """
        # TODO add admin to filter, validate rights
        if not filter_q:
            filter_q = {}
        if self.multiproject:
            filter_q.update(self._get_project_filter(session))
        return self.db.del_list(self.topic, filter_q)

    def delete_extra(self, session, _id, db_content):
        """
        Delete other things apart from database entry of a item _id.
        e.g.: other associated elements at database and other file system storage
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param db_content: The database content of the _id. It is already deleted when reached this method, but the
            content is needed in same cases
        :return: None if ok or raises EngineException with the problem
        """
        pass

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """

        # To allow addressing projects and users by name AS WELL AS by _id
        filter_q = {BaseTopic.id_field(self.topic, _id): _id}
        item_content = self.db.get_one(self.topic, filter_q)

        # TODO add admin to filter, validate rights
        # data = self.get_item(topic, _id)
        self.check_conflict_on_del(session, _id, item_content)
        if dry_run:
            return None
        
        if self.multiproject:
            filter_q.update(self._get_project_filter(session))
        if self.multiproject and session["project_id"]:
            # remove reference from project_read. If not last delete
            self.db.set_one(self.topic, filter_q, update_dict=None,
                            pull={"_admin.projects_read": {"$in": session["project_id"]}})
            # try to delete if there is not any more reference from projects. Ignore if it is not deleted
            filter_q = {'_id': _id, '_admin.projects_read': [[], ["ANY"]]}
            v = self.db.del_one(self.topic, filter_q, fail_on_empty=False)
            if not v or not v["deleted"]:
                return v
        else:
            v = self.db.del_one(self.topic, filter_q)
        self.delete_extra(session, _id, item_content)
        self._send_msg("deleted", {"_id": _id})
        return v

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        """
        Change the content of an item
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param indata: contains the changes to apply
        :param kwargs: modifies indata
        :param content: original content of the item
        :return:
        """
        indata = self._remove_envelop(indata)

        # Override descriptor with query string kwargs
        if kwargs:
            self._update_input_with_kwargs(indata, kwargs)
        try:
            if indata and session.get("set_project"):
                raise EngineException("Cannot edit content and set to project (query string SET_PROJECT) at same time",
                                      HTTPStatus.UNPROCESSABLE_ENTITY)
            indata = self._validate_input_edit(indata, force=session["force"])

            # TODO self._check_edition(session, indata, _id, force)
            if not content:
                content = self.show(session, _id)
            deep_update_rfc7396(content, indata)
            self.check_conflict_on_edit(session, content, indata, _id=_id)
            self.format_on_edit(content, indata)
            # To allow project addressing by name AS WELL AS _id
            # self.db.replace(self.topic, _id, content)
            cid = content.get("_id")
            self.db.replace(self.topic, cid if cid else _id, content)

            indata.pop("_admin", None)
            indata["_id"] = _id
            self._send_msg("edit", indata)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
