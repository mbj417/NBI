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

# import logging
from uuid import uuid4
from http import HTTPStatus
from time import time
from copy import copy, deepcopy
from validation import validate_input, ValidationError, ns_instantiate, ns_action, ns_scale, nsi_instantiate
from base_topic import BaseTopic, EngineException, get_iterable
# from descriptor_topics import DescriptorTopic
from yaml import safe_dump
from osm_common.dbbase import DbException
from re import match  # For checking that additional parameter names are valid Jinja2 identifiers

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class NsrTopic(BaseTopic):
    topic = "nsrs"
    topic_msg = "ns"
    schema_new = ns_instantiate

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def _check_descriptor_dependencies(self, session, descriptor):
        """
        Check that the dependent descriptors exist on a new descriptor or edition
        :param session: client session information
        :param descriptor: descriptor to be inserted or edit
        :return: None or raises exception
        """
        if not descriptor.get("nsdId"):
            return
        nsd_id = descriptor["nsdId"]
        if not self.get_item_list(session, "nsds", {"id": nsd_id}):
            raise EngineException("Descriptor error at nsdId='{}' references a non exist nsd".format(nsd_id),
                                  http_code=HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=make_public)
        content["_admin"]["nsState"] = "NOT_INSTANTIATED"

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check that NSR is not instantiated
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: nsr internal id
        :param db_content: The database content of the nsr
        :return: None or raises EngineException with the conflict
        """
        if session["force"]:
            return
        nsr = db_content
        if nsr["_admin"].get("nsState") == "INSTANTIATED":
            raise EngineException("nsr '{}' cannot be deleted because it is in 'INSTANTIATED' state. "
                                  "Launch 'terminate' operation first; or force deletion".format(_id),
                                  http_code=HTTPStatus.CONFLICT)

    def delete_extra(self, session, _id, db_content):
        """
        Deletes associated nslcmops and vnfrs from database. Deletes associated filesystem.
         Set usageState of pdu, vnfd, nsd
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param db_content: The database content of the descriptor
        :return: None if ok or raises EngineException with the problem
        """
        self.fs.file_delete(_id, ignore_non_exist=True)
        self.db.del_list("nslcmops", {"nsInstanceId": _id})
        self.db.del_list("vnfrs", {"nsr-id-ref": _id})

        # set all used pdus as free
        self.db.set_list("pdus", {"_admin.usage.nsr_id": _id},
                         {"_admin.usageState": "NOT_IN_USE", "_admin.usage": None})

        # Set NSD usageState
        nsr = db_content
        used_nsd_id = nsr.get("nsd-id")
        if used_nsd_id:
            # check if used by another NSR
            nsrs_list = self.db.get_one("nsrs", {"nsd-id": used_nsd_id},
                                        fail_on_empty=False, fail_on_more=False)
            if not nsrs_list:
                self.db.set_one("nsds", {"_id": used_nsd_id}, {"_admin.usageState": "NOT_IN_USE"})

        # Set VNFD usageState
        used_vnfd_id_list = nsr.get("vnfd-id")
        if used_vnfd_id_list:
            for used_vnfd_id in used_vnfd_id_list:
                # check if used by another NSR
                nsrs_list = self.db.get_one("nsrs", {"vnfd-id": used_vnfd_id},
                                            fail_on_empty=False, fail_on_more=False)
                if not nsrs_list:
                    self.db.set_one("vnfds", {"_id": used_vnfd_id}, {"_admin.usageState": "NOT_IN_USE"})

    @staticmethod
    def _format_ns_request(ns_request):
        formated_request = copy(ns_request)
        formated_request.pop("additionalParamsForNs", None)
        formated_request.pop("additionalParamsForVnf", None)
        return formated_request

    @staticmethod
    def _format_addional_params(ns_request, member_vnf_index=None, descriptor=None):
        """
        Get and format user additional params for NS or VNF
        :param ns_request: User instantiation additional parameters
        :param member_vnf_index: None for extract NS params, or member_vnf_index to extract VNF params
        :param descriptor: If not None it check that needed parameters of descriptor are supplied
        :return: a formated copy of additional params or None if not supplied
        """
        additional_params = None
        if not member_vnf_index:
            additional_params = copy(ns_request.get("additionalParamsForNs"))
            where_ = "additionalParamsForNs"
        elif ns_request.get("additionalParamsForVnf"):
            for additionalParamsForVnf in get_iterable(ns_request.get("additionalParamsForVnf")):
                if additionalParamsForVnf["member-vnf-index"] == member_vnf_index:
                    additional_params = copy(additionalParamsForVnf.get("additionalParams"))
                    where_ = "additionalParamsForVnf[member-vnf-index={}]".format(
                        additionalParamsForVnf["member-vnf-index"])
                    break
        if additional_params:
            for k, v in additional_params.items():
                # BEGIN Check that additional parameter names are valid Jinja2 identifiers
                if not match('^[a-zA-Z_][a-zA-Z0-9_]*$', k):
                    raise EngineException("Invalid param name at {}:{}. Must contain only alphanumeric characters "
                                          "and underscores, and cannot start with a digit"
                                          .format(where_, k))
                # END Check that additional parameter names are valid Jinja2 identifiers
                if not isinstance(k, str):
                    raise EngineException("Invalid param at {}:{}. Only string keys are allowed".format(where_, k))
                if "." in k or "$" in k:
                    raise EngineException("Invalid param at {}:{}. Keys must not contain dots or $".format(where_, k))
                if isinstance(v, (dict, tuple, list)):
                    additional_params[k] = "!!yaml " + safe_dump(v)

        if descriptor:
            # check that enough parameters are supplied for the initial-config-primitive
            # TODO: check for cloud-init
            if member_vnf_index:
                if descriptor.get("vnf-configuration"):
                    for initial_primitive in get_iterable(
                            descriptor["vnf-configuration"].get("initial-config-primitive")):
                        for param in get_iterable(initial_primitive.get("parameter")):
                            if param["value"].startswith("<") and param["value"].endswith(">"):
                                if param["value"] in ("<rw_mgmt_ip>", "<VDU_SCALE_INFO>"):
                                    continue
                                if not additional_params or param["value"][1:-1] not in additional_params:
                                    raise EngineException("Parameter '{}' needed for vnfd[id={}]:vnf-configuration:"
                                                          "initial-config-primitive[name={}] not supplied".
                                                          format(param["value"], descriptor["id"],
                                                                 initial_primitive["name"]))

        return additional_params

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new nsr into database. It also creates needed vnfrs
        :param rollback: list to append the created items at database in case a rollback must be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: params to be used for the nsr
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: the _id of nsr descriptor created at database
        """

        try:
            step = "validating input parameters"
            ns_request = self._remove_envelop(indata)
            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(ns_request, kwargs)
            self._validate_input_new(ns_request, session["force"])

            # look for nsr
            step = "getting nsd id='{}' from database".format(ns_request.get("nsdId"))
            _filter = self._get_project_filter(session)
            _filter["_id"] = ns_request["nsdId"]
            nsd = self.db.get_one("nsds", _filter)
            del _filter["_id"]

            nsr_id = str(uuid4())

            now = time()
            step = "filling nsr from input data"
            nsr_descriptor = {
                "name": ns_request["nsName"],
                "name-ref": ns_request["nsName"],
                "short-name": ns_request["nsName"],
                "admin-status": "ENABLED",
                "nsd": nsd,
                "datacenter": ns_request["vimAccountId"],
                "resource-orchestrator": "osmopenmano",
                "description": ns_request.get("nsDescription", ""),
                "constituent-vnfr-ref": [],

                "operational-status": "init",    # typedef ns-operational-
                "config-status": "init",         # typedef config-states
                "detailed-status": "scheduled",

                "orchestration-progress": {},
                # {"networks": {"active": 0, "total": 0}, "vms": {"active": 0, "total": 0}},

                "create-time": now,
                "nsd-name-ref": nsd["name"],
                "operational-events": [],   # "id", "timestamp", "description", "event",
                "nsd-ref": nsd["id"],
                "nsd-id": nsd["_id"],
                "vnfd-id": [],
                "instantiate_params": self._format_ns_request(ns_request),
                "additionalParamsForNs": self._format_addional_params(ns_request),
                "ns-instance-config-ref": nsr_id,
                "id": nsr_id,
                "_id": nsr_id,
                # "input-parameter": xpath, value,
                "ssh-authorized-key": ns_request.get("ssh_keys"),  # TODO remove
            }
            ns_request["nsr_id"] = nsr_id
            # Create vld
            if nsd.get("vld"):
                nsr_descriptor["vld"] = []
                for nsd_vld in nsd.get("vld"):
                    nsr_descriptor["vld"].append(
                        {key: nsd_vld[key] for key in ("id", "vim-network-name", "vim-network-id") if key in nsd_vld})

            # Create VNFR
            needed_vnfds = {}
            for member_vnf in nsd.get("constituent-vnfd", ()):
                vnfd_id = member_vnf["vnfd-id-ref"]
                step = "getting vnfd id='{}' constituent-vnfd='{}' from database".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])
                if vnfd_id not in needed_vnfds:
                    # Obtain vnfd
                    _filter["id"] = vnfd_id
                    vnfd = self.db.get_one("vnfds", _filter, fail_on_empty=True, fail_on_more=True)
                    del _filter["id"]
                    vnfd.pop("_admin")
                    needed_vnfds[vnfd_id] = vnfd
                    nsr_descriptor["vnfd-id"].append(vnfd["_id"])
                else:
                    vnfd = needed_vnfds[vnfd_id]
                step = "filling vnfr  vnfd-id='{}' constituent-vnfd='{}'".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])
                vnfr_id = str(uuid4())
                vnfr_descriptor = {
                    "id": vnfr_id,
                    "_id": vnfr_id,
                    "nsr-id-ref": nsr_id,
                    "member-vnf-index-ref": member_vnf["member-vnf-index"],
                    "additionalParamsForVnf": self._format_addional_params(ns_request, member_vnf["member-vnf-index"],
                                                                           vnfd),
                    "created-time": now,
                    # "vnfd": vnfd,        # at OSM model.but removed to avoid data duplication TODO: revise
                    "vnfd-ref": vnfd_id,
                    "vnfd-id": vnfd["_id"],    # not at OSM model, but useful
                    "vim-account-id": None,
                    "vdur": [],
                    "connection-point": [],
                    "ip-address": None,  # mgmt-interface filled by LCM
                }

                # Create vld
                if vnfd.get("internal-vld"):
                    vnfr_descriptor["vld"] = []
                    for vnfd_vld in vnfd.get("internal-vld"):
                        vnfr_descriptor["vld"].append(
                            {key: vnfd_vld[key] for key in ("id", "vim-network-name", "vim-network-id") if key in
                             vnfd_vld})

                vnfd_mgmt_cp = vnfd["mgmt-interface"].get("cp")
                for cp in vnfd.get("connection-point", ()):
                    vnf_cp = {
                        "name": cp["name"],
                        "connection-point-id": cp.get("id"),
                        "id": cp.get("id"),
                        # "ip-address", "mac-address" # filled by LCM
                        # vim-id  # TODO it would be nice having a vim port id
                    }
                    vnfr_descriptor["connection-point"].append(vnf_cp)
                for vdu in vnfd.get("vdu", ()):
                    vdur = {
                        "vdu-id-ref": vdu["id"],
                        # TODO      "name": ""     Name of the VDU in the VIM
                        "ip-address": None,  # mgmt-interface filled by LCM
                        # "vim-id", "flavor-id", "image-id", "management-ip" # filled by LCM
                        "internal-connection-point": [],
                        "interfaces": [],
                    }
                    if vdu.get("pdu-type"):
                        vdur["pdu-type"] = vdu["pdu-type"]
                    # TODO volumes: name, volume-id
                    for icp in vdu.get("internal-connection-point", ()):
                        vdu_icp = {
                            "id": icp["id"],
                            "connection-point-id": icp["id"],
                            "name": icp.get("name"),
                            # "ip-address", "mac-address" # filled by LCM
                            # vim-id  # TODO it would be nice having a vim port id
                        }
                        vdur["internal-connection-point"].append(vdu_icp)
                    for iface in vdu.get("interface", ()):
                        vdu_iface = {
                            "name": iface.get("name"),
                            # "ip-address", "mac-address" # filled by LCM
                            # vim-id  # TODO it would be nice having a vim port id
                        }
                        if vnfd_mgmt_cp and iface.get("external-connection-point-ref") == vnfd_mgmt_cp:
                            vdu_iface["mgmt-vnf"] = True
                        if iface.get("mgmt-interface"):
                            vdu_iface["mgmt-interface"] = True  # TODO change to mgmt-vdu

                        # look for network where this interface is connected
                        if iface.get("external-connection-point-ref"):
                            for nsd_vld in get_iterable(nsd.get("vld")):
                                for nsd_vld_cp in get_iterable(nsd_vld.get("vnfd-connection-point-ref")):
                                    if nsd_vld_cp.get("vnfd-connection-point-ref") == \
                                            iface["external-connection-point-ref"] and \
                                            nsd_vld_cp.get("member-vnf-index-ref") == member_vnf["member-vnf-index"]:
                                        vdu_iface["ns-vld-id"] = nsd_vld["id"]
                                        break
                                else:
                                    continue
                                break
                        elif iface.get("internal-connection-point-ref"):
                            for vnfd_ivld in get_iterable(vnfd.get("internal-vld")):
                                for vnfd_ivld_icp in get_iterable(vnfd_ivld.get("internal-connection-point")):
                                    if vnfd_ivld_icp.get("id-ref") == iface["internal-connection-point-ref"]:
                                        vdu_iface["vnf-vld-id"] = vnfd_ivld["id"]
                                        break
                                else:
                                    continue
                                break

                        vdur["interfaces"].append(vdu_iface)
                    count = vdu.get("count", 1)
                    if count is None:
                        count = 1
                    count = int(count)    # TODO remove when descriptor serialized with payngbind
                    for index in range(0, count):
                        if index:
                            vdur = deepcopy(vdur)
                        vdur["_id"] = str(uuid4())
                        vdur["count-index"] = index
                        vnfr_descriptor["vdur"].append(vdur)

                step = "creating vnfr vnfd-id='{}' constituent-vnfd='{}' at database".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])

                # add at database
                BaseTopic.format_on_new(vnfr_descriptor, session["project_id"], make_public=session["public"])
                self.db.create("vnfrs", vnfr_descriptor)
                rollback.append({"topic": "vnfrs", "_id": vnfr_id})
                nsr_descriptor["constituent-vnfr-ref"].append(vnfr_id)

            step = "creating nsr at database"
            self.format_on_new(nsr_descriptor, session["project_id"], make_public=session["public"])
            self.db.create("nsrs", nsr_descriptor)
            rollback.append({"topic": "nsrs", "_id": nsr_id})

            step = "creating nsr temporal folder"
            self.fs.mkdir(nsr_id)

            return nsr_id
        except Exception as e:
            self.logger.exception("Exception {} at NsrTopic.new()".format(e), exc_info=True)
            raise EngineException("Error {}: {}".format(step, e))
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)


class VnfrTopic(BaseTopic):
    topic = "vnfrs"
    topic_msg = None

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def delete(self, session, _id, dry_run=False):
        raise EngineException("Method delete called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        # Not used because vnfrs are created and deleted by NsrTopic class directly
        raise EngineException("Method new called directly", HTTPStatus.INTERNAL_SERVER_ERROR)


class NsLcmOpTopic(BaseTopic):
    topic = "nslcmops"
    topic_msg = "ns"
    operation_schema = {    # mapping between operation and jsonschema to validate
        "instantiate": ns_instantiate,
        "action": ns_action,
        "scale": ns_scale,
        "terminate": None,
    }

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def _check_ns_operation(self, session, nsr, operation, indata):
        """
        Check that user has enter right parameters for the operation
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param indata: descriptor with the parameters of the operation
        :return: None
        """
        vnfds = {}
        vim_accounts = []
        wim_accounts = []
        nsd = nsr["nsd"]

        def check_valid_vnf_member_index(member_vnf_index):
            # TODO change to vnfR
            for vnf in nsd["constituent-vnfd"]:
                if member_vnf_index == vnf["member-vnf-index"]:
                    vnfd_id = vnf["vnfd-id-ref"]
                    if vnfd_id not in vnfds:
                        vnfds[vnfd_id] = self.db.get_one("vnfds", {"id": vnfd_id})
                    return vnfds[vnfd_id]
            else:
                raise EngineException("Invalid parameter member_vnf_index='{}' is not one of the "
                                      "nsd:constituent-vnfd".format(member_vnf_index))

        def _check_vnf_instantiation_params(in_vnfd, vnfd):

            for in_vdu in get_iterable(in_vnfd.get("vdu")):
                for vdu in get_iterable(vnfd.get("vdu")):
                    if in_vdu["id"] == vdu["id"]:
                        for volume in get_iterable(in_vdu.get("volume")):
                            for volumed in get_iterable(vdu.get("volumes")):
                                if volumed["name"] == volume["name"]:
                                    break
                            else:
                                raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:vdu[id='{}']:"
                                                      "volume:name='{}' is not present at vnfd:vdu:volumes list".
                                                      format(in_vnf["member-vnf-index"], in_vdu["id"],
                                                             volume["name"]))
                        for in_iface in get_iterable(in_vdu["interface"]):
                            for iface in get_iterable(vdu.get("interface")):
                                if in_iface["name"] == iface["name"]:
                                    break
                            else:
                                raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:vdu[id='{}']:"
                                                      "interface[name='{}'] is not present at vnfd:vdu:interface"
                                                      .format(in_vnf["member-vnf-index"], in_vdu["id"],
                                                              in_iface["name"]))
                        break
                else:
                    raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:vdu[id='{}'] is is not present "
                                          "at vnfd:vdu".format(in_vnf["member-vnf-index"], in_vdu["id"]))

            for in_ivld in get_iterable(in_vnfd.get("internal-vld")):
                for ivld in get_iterable(vnfd.get("internal-vld")):
                    if in_ivld["name"] == ivld["name"] or in_ivld["name"] == ivld["id"]:
                        for in_icp in get_iterable(in_ivld["internal-connection-point"]):
                            for icp in ivld["internal-connection-point"]:
                                if in_icp["id-ref"] == icp["id-ref"]:
                                    break
                            else:
                                raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:internal-vld[name"
                                                      "='{}']:internal-connection-point[id-ref:'{}'] is not present at "
                                                      "vnfd:internal-vld:name/id:internal-connection-point"
                                                      .format(in_vnf["member-vnf-index"], in_ivld["name"],
                                                              in_icp["id-ref"], vnfd["id"]))
                        break
                else:
                    raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:internal-vld:name='{}'"
                                          " is not present at vnfd '{}'".format(in_vnf["member-vnf-index"],
                                                                                in_ivld["name"], vnfd["id"]))

        def check_valid_vim_account(vim_account):
            if vim_account in vim_accounts:
                return
            try:
                db_filter = self._get_project_filter(session)
                db_filter["_id"] = vim_account
                self.db.get_one("vim_accounts", db_filter)
            except Exception:
                raise EngineException("Invalid vimAccountId='{}' not present for the project".format(vim_account))
            vim_accounts.append(vim_account)

        def check_valid_wim_account(wim_account):
            if not isinstance(wim_account, str):
                return
            elif wim_account in wim_accounts:
                return
            try:
                db_filter = self._get_project_filter(session, write=False, show_all=True)
                db_filter["_id"] = wim_account
                self.db.get_one("wim_accounts", db_filter)
            except Exception:
                raise EngineException("Invalid wimAccountId='{}' not present for the project".format(wim_account))
            wim_accounts.append(wim_account)

        if operation == "action":
            # check vnf_member_index
            if indata.get("vnf_member_index"):
                indata["member_vnf_index"] = indata.pop("vnf_member_index")    # for backward compatibility
            if indata.get("member_vnf_index"):
                vnfd = check_valid_vnf_member_index(indata["member_vnf_index"])
                descriptor_configuration = vnfd.get("vnf-configuration", {}).get("config-primitive")
            else:  # use a NSD
                descriptor_configuration = nsd.get("ns-configuration", {}).get("config-primitive")
            # check primitive
            for config_primitive in get_iterable(descriptor_configuration):
                if indata["primitive"] == config_primitive["name"]:
                    # check needed primitive_params are provided
                    if indata.get("primitive_params"):
                        in_primitive_params_copy = copy(indata["primitive_params"])
                    else:
                        in_primitive_params_copy = {}
                    for paramd in get_iterable(config_primitive.get("parameter")):
                        if paramd["name"] in in_primitive_params_copy:
                            del in_primitive_params_copy[paramd["name"]]
                        elif not paramd.get("default-value"):
                            raise EngineException("Needed parameter {} not provided for primitive '{}'".format(
                                paramd["name"], indata["primitive"]))
                    # check no extra primitive params are provided
                    if in_primitive_params_copy:
                        raise EngineException("parameter/s '{}' not present at vnfd /nsd for primitive '{}'".format(
                            list(in_primitive_params_copy.keys()), indata["primitive"]))
                    break
            else:
                raise EngineException("Invalid primitive '{}' is not present at vnfd/nsd".format(indata["primitive"]))
        if operation == "scale":
            vnfd = check_valid_vnf_member_index(indata["scaleVnfData"]["scaleByStepData"]["member-vnf-index"])
            for scaling_group in get_iterable(vnfd.get("scaling-group-descriptor")):
                if indata["scaleVnfData"]["scaleByStepData"]["scaling-group-descriptor"] == scaling_group["name"]:
                    break
            else:
                raise EngineException("Invalid scaleVnfData:scaleByStepData:scaling-group-descriptor '{}' is not "
                                      "present at vnfd:scaling-group-descriptor".format(
                                          indata["scaleVnfData"]["scaleByStepData"]["scaling-group-descriptor"]))
        if operation == "instantiate":
            # check vim_account
            check_valid_vim_account(indata["vimAccountId"])
            check_valid_wim_account(indata.get("wimAccountId"))
            for in_vnf in get_iterable(indata.get("vnf")):
                vnfd = check_valid_vnf_member_index(in_vnf["member-vnf-index"])
                _check_vnf_instantiation_params(in_vnf, vnfd)
                if in_vnf.get("vimAccountId"):
                    check_valid_vim_account(in_vnf["vimAccountId"])

            for in_vld in get_iterable(indata.get("vld")):
                check_valid_wim_account(in_vld.get("wimAccountId"))
                for vldd in get_iterable(nsd.get("vld")):
                    if in_vld["name"] == vldd["name"] or in_vld["name"] == vldd["id"]:
                        break
                else:
                    raise EngineException("Invalid parameter vld:name='{}' is not present at nsd:vld".format(
                        in_vld["name"]))

    def _look_for_pdu(self, session, rollback, vnfr, vim_account, vnfr_update, vnfr_update_rollback):
        """
        Look for a free PDU in the catalog matching vdur type and interfaces. Fills vnfr.vdur with the interface
        (ip_address, ...) information.
        Modifies PDU _admin.usageState to 'IN_USE'
        
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param rollback: list with the database modifications to rollback if needed
        :param vnfr: vnfr to be updated. It is modified with pdu interface info if pdu is found
        :param vim_account: vim_account where this vnfr should be deployed
        :param vnfr_update: dictionary filled by this method with changes to be done at database vnfr
        :param vnfr_update_rollback: dictionary filled by this method with original content of vnfr in case a rollback
                                     of the changed vnfr is needed

        :return: List of PDU interfaces that are connected to an existing VIM network. Each item contains:
                 "vim-network-name": used at VIM
                  "name": interface name
                  "vnf-vld-id": internal VNFD vld where this interface is connected, or
                  "ns-vld-id": NSD vld where this interface is connected.
                  NOTE: One, and only one between 'vnf-vld-id' and 'ns-vld-id' contains a value. The other will be None
        """

        ifaces_forcing_vim_network = []
        for vdur_index, vdur in enumerate(get_iterable(vnfr.get("vdur"))):
            if not vdur.get("pdu-type"):
                continue
            pdu_type = vdur.get("pdu-type")
            pdu_filter = self._get_project_filter(session)
            pdu_filter["vim_accounts"] = vim_account
            pdu_filter["type"] = pdu_type
            pdu_filter["_admin.operationalState"] = "ENABLED"
            pdu_filter["_admin.usageState"] = "NOT_IN_USE"
            # TODO feature 1417: "shared": True,

            available_pdus = self.db.get_list("pdus", pdu_filter)
            for pdu in available_pdus:
                # step 1 check if this pdu contains needed interfaces:
                match_interfaces = True
                for vdur_interface in vdur["interfaces"]:
                    for pdu_interface in pdu["interfaces"]:
                        if pdu_interface["name"] == vdur_interface["name"]:
                            # TODO feature 1417: match per mgmt type
                            break
                    else:  # no interface found for name
                        match_interfaces = False
                        break
                if match_interfaces:
                    break
            else:
                raise EngineException(
                    "No PDU of type={} at vim_account={} found for member_vnf_index={}, vdu={} matching interface "
                    "names".format(pdu_type, vim_account, vnfr["member-vnf-index-ref"], vdur["vdu-id-ref"]))

            # step 2. Update pdu
            rollback_pdu = {
                "_admin.usageState": pdu["_admin"]["usageState"],
                "_admin.usage.vnfr_id": None,
                "_admin.usage.nsr_id": None,
                "_admin.usage.vdur": None,
            }
            self.db.set_one("pdus", {"_id": pdu["_id"]},
                            {"_admin.usageState": "IN_USE",
                             "_admin.usage": {"vnfr_id": vnfr["_id"],
                                              "nsr_id": vnfr["nsr-id-ref"],
                                              "vdur": vdur["vdu-id-ref"]}
                             })
            rollback.append({"topic": "pdus", "_id": pdu["_id"], "operation": "set", "content": rollback_pdu})

            # step 3. Fill vnfr info by filling vdur
            vdu_text = "vdur.{}".format(vdur_index)
            vnfr_update_rollback[vdu_text + ".pdu-id"] = None
            vnfr_update[vdu_text + ".pdu-id"] = pdu["_id"]
            for iface_index, vdur_interface in enumerate(vdur["interfaces"]):
                for pdu_interface in pdu["interfaces"]:
                    if pdu_interface["name"] == vdur_interface["name"]:
                        iface_text = vdu_text + ".interfaces.{}".format(iface_index)
                        for k, v in pdu_interface.items():
                            if k in ("ip-address", "mac-address"):  # TODO: switch-xxxxx must be inserted
                                vnfr_update[iface_text + ".{}".format(k)] = v
                                vnfr_update_rollback[iface_text + ".{}".format(k)] = vdur_interface.get(v)
                        if pdu_interface.get("ip-address"):
                            if vdur_interface.get("mgmt-interface"):
                                vnfr_update_rollback[vdu_text + ".ip-address"] = vdur.get("ip-address")
                                vnfr_update[vdu_text + ".ip-address"] = pdu_interface["ip-address"]
                            if vdur_interface.get("mgmt-vnf"):
                                vnfr_update_rollback["ip-address"] = vnfr.get("ip-address")
                                vnfr_update["ip-address"] = pdu_interface["ip-address"]
                        if pdu_interface.get("vim-network-name") or pdu_interface.get("vim-network-id"):
                            ifaces_forcing_vim_network.append({
                                "name": vdur_interface.get("vnf-vld-id") or vdur_interface.get("ns-vld-id"),
                                "vnf-vld-id": vdur_interface.get("vnf-vld-id"),
                                "ns-vld-id": vdur_interface.get("ns-vld-id")})
                            if pdu_interface.get("vim-network-id"):
                                ifaces_forcing_vim_network.append({
                                    "vim-network-id": pdu_interface.get("vim-network-id")})
                            if pdu_interface.get("vim-network-name"):
                                ifaces_forcing_vim_network.append({
                                    "vim-network-name": pdu_interface.get("vim-network-name")})
                        break

        return ifaces_forcing_vim_network

    def _update_vnfrs(self, session, rollback, nsr, indata):
        vnfrs = None
        # get vnfr
        nsr_id = nsr["_id"]
        vnfrs = self.db.get_list("vnfrs", {"nsr-id-ref": nsr_id})

        for vnfr in vnfrs:
            vnfr_update = {}
            vnfr_update_rollback = {}
            member_vnf_index = vnfr["member-vnf-index-ref"]
            # update vim-account-id

            vim_account = indata["vimAccountId"]
            # check instantiate parameters
            for vnf_inst_params in get_iterable(indata.get("vnf")):
                if vnf_inst_params["member-vnf-index"] != member_vnf_index:
                    continue
                if vnf_inst_params.get("vimAccountId"):
                    vim_account = vnf_inst_params.get("vimAccountId")

            vnfr_update["vim-account-id"] = vim_account
            vnfr_update_rollback["vim-account-id"] = vnfr.get("vim-account-id")

            # get pdu
            ifaces_forcing_vim_network = self._look_for_pdu(session, rollback, vnfr, vim_account, vnfr_update,
                                                            vnfr_update_rollback)

            # updata database vnfr
            self.db.set_one("vnfrs", {"_id": vnfr["_id"]}, vnfr_update)
            rollback.append({"topic": "vnfrs", "_id": vnfr["_id"], "operation": "set", "content": vnfr_update_rollback})

            # Update indada in case pdu forces to use a concrete vim-network-name
            # TODO check if user has already insert a vim-network-name and raises an error
            if not ifaces_forcing_vim_network:
                continue
            for iface_info in ifaces_forcing_vim_network:
                if iface_info.get("ns-vld-id"):
                    if "vld" not in indata:
                        indata["vld"] = []
                    indata["vld"].append({key: iface_info[key] for key in
                                          ("name", "vim-network-name", "vim-network-id") if iface_info.get(key)})

                elif iface_info.get("vnf-vld-id"):
                    if "vnf" not in indata:
                        indata["vnf"] = []
                    indata["vnf"].append({
                        "member-vnf-index": member_vnf_index,
                        "internal-vld": [{key: iface_info[key] for key in
                                          ("name", "vim-network-name", "vim-network-id") if iface_info.get(key)}]
                    })

    @staticmethod
    def _create_nslcmop(nsr_id, operation, params):
        """
        Creates a ns-lcm-opp content to be stored at database.
        :param nsr_id: internal id of the instance
        :param operation: instantiate, terminate, scale, action, ...
        :param params: user parameters for the operation
        :return: dictionary following SOL005 format
        """
        now = time()
        _id = str(uuid4())
        nslcmop = {
            "id": _id,
            "_id": _id,
            "operationState": "PROCESSING",  # COMPLETED,PARTIALLY_COMPLETED,FAILED_TEMP,FAILED,ROLLING_BACK,ROLLED_BACK
            "statusEnteredTime": now,
            "nsInstanceId": nsr_id,
            "lcmOperationType": operation,
            "startTime": now,
            "isAutomaticInvocation": False,
            "operationParams": params,
            "isCancelPending": False,
            "links": {
                "self": "/osm/nslcm/v1/ns_lcm_op_occs/" + _id,
                "nsInstance": "/osm/nslcm/v1/ns_instances/" + nsr_id,
            }
        }
        return nslcmop

    def _get_enabled_vims(self, session):
        db_filter = self._get_project_filter(session)
        db_filter["_admin.operationalState"] = "ENABLED"
        vims = self.db.get_list("vim_accounts", db_filter)
        vimAccounts = []
        for vim in vims:
            vimAccounts.append(vim['_id'])
        return vimAccounts
                
    

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, slice_object=False):
        """
        Performs a new operation over a ns
        :param rollback: list to append created items at database in case a rollback must to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: descriptor with the parameters of the operation. It must contains among others
            nsInstanceId: _id of the nsr to perform the operation
            operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: id of the nslcmops
        """
        def check_if_nsr_is_not_slice_member(session, nsr_id):
            nsis = None
            db_filter = self._get_project_filter(session)
            db_filter["_admin.nsrs-detailed-list.ANYINDEX.nsrId"] = nsr_id
            nsis = self.db.get_one("nsis", db_filter, fail_on_empty=False, fail_on_more=False)
            if nsis:
                raise EngineException("The NS instance {} cannot be terminate because is used by the slice {}".format(
                                      nsr_id, nsis["_id"]), http_code=HTTPStatus.CONFLICT)

        try:
            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(indata, kwargs)
            operation = indata["lcmOperationType"]
            nsInstanceId = indata["nsInstanceId"]

            validate_input(indata, self.operation_schema[operation])
            # get ns from nsr_id
            _filter = BaseTopic._get_project_filter(session)
            _filter["_id"] = nsInstanceId
            nsr = self.db.get_one("nsrs", _filter)

            # initial checking
            if operation == "terminate" and slice_object is False:
                check_if_nsr_is_not_slice_member(session, nsr["_id"])
            if not nsr["_admin"].get("nsState") or nsr["_admin"]["nsState"] == "NOT_INSTANTIATED":
                if operation == "terminate" and indata.get("autoremove"):
                    # NSR must be deleted
                    return None    # a none in this case is used to indicate not instantiated. It can be removed
                if operation != "instantiate":
                    raise EngineException("ns_instance '{}' cannot be '{}' because it is not instantiated".format(
                        nsInstanceId, operation), HTTPStatus.CONFLICT)
            else:
                if operation == "instantiate" and not session["force"]:
                    raise EngineException("ns_instance '{}' cannot be '{}' because it is already instantiated".format(
                        nsInstanceId, operation), HTTPStatus.CONFLICT)
            self._check_ns_operation(session, nsr, operation, indata)

            if operation == "instantiate":
                self._update_vnfrs(session, rollback, nsr, indata)

            nslcmop_desc = self._create_nslcmop(nsInstanceId, operation, indata)
            self.format_on_new(nslcmop_desc, session["project_id"], make_public=session["public"])
            _vims = self._get_enabled_vims(session)
            nslcmop_desc['operationParams']['validVimAccounts'] = _vims
            _id = self.db.create("nslcmops", nslcmop_desc)
            rollback.append({"topic": "nslcmops", "_id": _id})
            if not slice_object:
                self.msg.write("ns", operation, nslcmop_desc)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
        # except DbException as e:
        #     raise EngineException("Cannot get ns_instance '{}': {}".format(e), HTTPStatus.NOT_FOUND)

    def delete(self, session, _id, dry_run=False):
        raise EngineException("Method delete called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)


class NsiTopic(BaseTopic):
    topic = "nsis"
    topic_msg = "nsi"

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)
        self.nsrTopic = NsrTopic(db, fs, msg)

    @staticmethod
    def _format_ns_request(ns_request):
        formated_request = copy(ns_request)
        # TODO: Add request params
        return formated_request

    @staticmethod
    def _format_addional_params(slice_request):
        """
        Get and format user additional params for NS or VNF
        :param slice_request: User instantiation additional parameters
        :return: a formatted copy of additional params or None if not supplied
        """
        additional_params = copy(slice_request.get("additionalParamsForNsi"))
        if additional_params:
            for k, v in additional_params.items():
                if not isinstance(k, str):
                    raise EngineException("Invalid param at additionalParamsForNsi:{}. Only string keys are allowed".
                                          format(k))
                if "." in k or "$" in k:
                    raise EngineException("Invalid param at additionalParamsForNsi:{}. Keys must not contain dots or $".
                                          format(k))
                if isinstance(v, (dict, tuple, list)):
                    additional_params[k] = "!!yaml " + safe_dump(v)
        return additional_params

    def _check_descriptor_dependencies(self, session, descriptor):
        """
        Check that the dependent descriptors exist on a new descriptor or edition
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param descriptor: descriptor to be inserted or edit
        :return: None or raises exception
        """
        if not descriptor.get("nst-ref"):
            return
        nstd_id = descriptor["nst-ref"]
        if not self.get_item_list(session, "nsts", {"id": nstd_id}):
            raise EngineException("Descriptor error at nst-ref='{}' references a non exist nstd".format(nstd_id),
                                  http_code=HTTPStatus.CONFLICT)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check that NSI is not instantiated
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: nsi internal id
        :param db_content: The database content of the _id
        :return: None or raises EngineException with the conflict
        """
        if session["force"]:
            return
        nsi = db_content
        if nsi["_admin"].get("nsiState") == "INSTANTIATED":
            raise EngineException("nsi '{}' cannot be deleted because it is in 'INSTANTIATED' state. "
                                  "Launch 'terminate' operation first; or force deletion".format(_id),
                                  http_code=HTTPStatus.CONFLICT)

    def delete_extra(self, session, _id, db_content):
        """
        Deletes associated nsilcmops from database. Deletes associated filesystem.
         Set usageState of nst
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param db_content: The database content of the descriptor
        :return: None if ok or raises EngineException with the problem
        """

        # Deleting the nsrs belonging to nsir
        nsir = db_content
        for nsrs_detailed_item in nsir["_admin"]["nsrs-detailed-list"]:
            nsr_id = nsrs_detailed_item["nsrId"]
            if nsrs_detailed_item.get("shared"):
                _filter = {"_admin.nsrs-detailed-list.ANYINDEX.shared": True,
                           "_admin.nsrs-detailed-list.ANYINDEX.nsrId": nsr_id,
                           "_id.ne": nsir["_id"]}
                nsi = self.db.get_one("nsis", _filter, fail_on_empty=False, fail_on_more=False)
                if nsi:  # last one using nsr
                    continue
            try:
                self.nsrTopic.delete(session, nsr_id, dry_run=False)
            except (DbException, EngineException) as e:
                if e.http_code == HTTPStatus.NOT_FOUND:
                    pass
                else:
                    raise

        # delete related nsilcmops database entries
        self.db.del_list("nsilcmops", {"netsliceInstanceId": _id})

        # Check and set used NST usage state
        nsir_admin = nsir.get("_admin")
        if nsir_admin and nsir_admin.get("nst-id"):
            # check if used by another NSI
            nsis_list = self.db.get_one("nsis", {"nst-id": nsir_admin["nst-id"]},
                                        fail_on_empty=False, fail_on_more=False)
            if not nsis_list:
                self.db.set_one("nsts", {"_id": nsir_admin["nst-id"]}, {"_admin.usageState": "NOT_IN_USE"})

    # def delete(self, session, _id, dry_run=False):
    #     """
    #     Delete item by its internal _id
    #     :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
    #     :param _id: server internal id
    #     :param dry_run: make checking but do not delete
    #     :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
    #     """
    #     # TODO add admin to filter, validate rights
    #     BaseTopic.delete(self, session, _id, dry_run=True)
    #     if dry_run:
    #         return
    #
    #     # Deleting the nsrs belonging to nsir
    #     nsir = self.db.get_one("nsis", {"_id": _id})
    #     for nsrs_detailed_item in nsir["_admin"]["nsrs-detailed-list"]:
    #         nsr_id = nsrs_detailed_item["nsrId"]
    #         if nsrs_detailed_item.get("shared"):
    #             _filter = {"_admin.nsrs-detailed-list.ANYINDEX.shared": True,
    #                        "_admin.nsrs-detailed-list.ANYINDEX.nsrId": nsr_id,
    #                        "_id.ne": nsir["_id"]}
    #             nsi = self.db.get_one("nsis", _filter, fail_on_empty=False, fail_on_more=False)
    #             if nsi:  # last one using nsr
    #                 continue
    #         try:
    #             self.nsrTopic.delete(session, nsr_id, dry_run=False)
    #         except (DbException, EngineException) as e:
    #             if e.http_code == HTTPStatus.NOT_FOUND:
    #                 pass
    #             else:
    #                 raise
    #     # deletes NetSlice instance object
    #     v = self.db.del_one("nsis", {"_id": _id})
    #
    #     # makes a temporal list of nsilcmops objects related to the _id given and deletes them from db
    #     _filter = {"netsliceInstanceId": _id}
    #     self.db.del_list("nsilcmops", _filter)
    #
    #     # Search if nst is being used by other nsi
    #     nsir_admin = nsir.get("_admin")
    #     if nsir_admin:
    #         if nsir_admin.get("nst-id"):
    #             nsis_list = self.db.get_one("nsis", {"nst-id": nsir_admin["nst-id"]},
    #                                         fail_on_empty=False, fail_on_more=False)
    #             if not nsis_list:
    #                 self.db.set_one("nsts", {"_id": nsir_admin["nst-id"]}, {"_admin.usageState": "NOT_IN_USE"})
    #     return v

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new netslice instance record into database. It also creates needed nsrs and vnfrs
        :param rollback: list to append the created items at database in case a rollback must be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: params to be used for the nsir
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: the _id of nsi descriptor created at database
        """

        try:
            step = ""
            slice_request = self._remove_envelop(indata)
            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(slice_request, kwargs)
            self._validate_input_new(slice_request, session["force"])

            # look for nstd
            step = "getting nstd id='{}' from database".format(slice_request.get("nstId"))
            _filter = self._get_project_filter(session)
            _filter["_id"] = slice_request["nstId"]
            nstd = self.db.get_one("nsts", _filter)
            del _filter["_id"]

            nstd.pop("_admin", None)
            nstd_id = nstd.pop("_id", None)
            nsi_id = str(uuid4())
            step = "filling nsi_descriptor with input data"

            # Creating the NSIR
            nsi_descriptor = {
                "id": nsi_id,
                "name": slice_request["nsiName"],
                "description": slice_request.get("nsiDescription", ""),
                "datacenter": slice_request["vimAccountId"],
                "nst-ref": nstd["id"],
                "instantiation_parameters": slice_request,
                "network-slice-template": nstd,
                "nsr-ref-list": [],
                "vlr-list": [],
                "_id": nsi_id,
                "additionalParamsForNsi": self._format_addional_params(slice_request)
            }

            step = "creating nsi at database"
            self.format_on_new(nsi_descriptor, session["project_id"], make_public=session["public"])
            nsi_descriptor["_admin"]["nsiState"] = "NOT_INSTANTIATED"
            nsi_descriptor["_admin"]["netslice-subnet"] = None
            nsi_descriptor["_admin"]["deployed"] = {}
            nsi_descriptor["_admin"]["deployed"]["RO"] = []
            nsi_descriptor["_admin"]["nst-id"] = nstd_id

            # Creating netslice-vld for the RO.
            step = "creating netslice-vld at database"

            # Building the vlds list to be deployed
            # From netslice descriptors, creating the initial list
            nsi_vlds = []

            for netslice_vlds in get_iterable(nstd.get("netslice-vld")):
                # Getting template Instantiation parameters from NST
                nsi_vld = deepcopy(netslice_vlds)
                nsi_vld["shared-nsrs-list"] = []
                nsi_vld["vimAccountId"] = slice_request["vimAccountId"]
                nsi_vlds.append(nsi_vld)

            nsi_descriptor["_admin"]["netslice-vld"] = nsi_vlds
            # Creating netslice-subnet_record. 
            needed_nsds = {}
            services = []

            # Updating the nstd with the nsd["_id"] associated to the nss -> services list
            for member_ns in nstd["netslice-subnet"]:
                nsd_id = member_ns["nsd-ref"]
                step = "getting nstd id='{}' constituent-nsd='{}' from database".format(
                    member_ns["nsd-ref"], member_ns["id"])
                if nsd_id not in needed_nsds:
                    # Obtain nsd
                    _filter["id"] = nsd_id
                    nsd = self.db.get_one("nsds", _filter, fail_on_empty=True, fail_on_more=True)
                    del _filter["id"]
                    nsd.pop("_admin")
                    needed_nsds[nsd_id] = nsd
                else:
                    nsd = needed_nsds[nsd_id]
                member_ns["_id"] = needed_nsds[nsd_id].get("_id")
                services.append(member_ns)

                step = "filling nsir nsd-id='{}' constituent-nsd='{}' from database".format(
                    member_ns["nsd-ref"], member_ns["id"])

            # creates Network Services records (NSRs)
            step = "creating nsrs at database using NsrTopic.new()"
            ns_params = slice_request.get("netslice-subnet")
            nsrs_list = []
            nsi_netslice_subnet = []
            for service in services:
                # Check if the netslice-subnet is shared and if it is share if the nss exists
                _id_nsr = None
                indata_ns = {}
                # Is the nss shared and instantiated?
                _filter["_admin.nsrs-detailed-list.ANYINDEX.shared"] = True
                _filter["_admin.nsrs-detailed-list.ANYINDEX.nsd-id"] = service["nsd-ref"]
                nsi = self.db.get_one("nsis", _filter, fail_on_empty=False, fail_on_more=False)
                
                if nsi and service.get("is-shared-nss"):
                    nsrs_detailed_list = nsi["_admin"]["nsrs-detailed-list"]
                    for nsrs_detailed_item in nsrs_detailed_list:
                        if nsrs_detailed_item["nsd-id"] == service["nsd-ref"]:
                            _id_nsr = nsrs_detailed_item["nsrId"]
                            break
                    for netslice_subnet in nsi["_admin"]["netslice-subnet"]:
                        if netslice_subnet["nss-id"] == service["id"]:
                            indata_ns = netslice_subnet
                            break
                else:
                    indata_ns = {}
                    if service.get("instantiation-parameters"):
                        indata_ns = deepcopy(service["instantiation-parameters"])
                        # del service["instantiation-parameters"]
                        
                    indata_ns["nsdId"] = service["_id"]
                    indata_ns["nsName"] = slice_request.get("nsiName") + "." + service["id"]
                    indata_ns["vimAccountId"] = slice_request.get("vimAccountId")
                    indata_ns["nsDescription"] = service["description"]
                    if slice_request.get("ssh_keys"):
                        indata_ns["ssh_keys"] = slice_request.get("ssh_keys")

                    if ns_params:
                        for ns_param in ns_params:
                            if ns_param.get("id") == service["id"]:
                                copy_ns_param = deepcopy(ns_param)
                                del copy_ns_param["id"]
                                indata_ns.update(copy_ns_param)
                                break                   

                    # Creates Nsr objects
                    _id_nsr = self.nsrTopic.new(rollback, session, indata_ns, kwargs, headers)
                nsrs_item = {"nsrId": _id_nsr, "shared": service.get("is-shared-nss"), "nsd-id": service["nsd-ref"], 
                             "nslcmop_instantiate": None}
                indata_ns["nss-id"] = service["id"]
                nsrs_list.append(nsrs_item)
                nsi_netslice_subnet.append(indata_ns)
                nsr_ref = {"nsr-ref": _id_nsr}
                nsi_descriptor["nsr-ref-list"].append(nsr_ref)

            # Adding the nsrs list to the nsi
            nsi_descriptor["_admin"]["nsrs-detailed-list"] = nsrs_list
            nsi_descriptor["_admin"]["netslice-subnet"] = nsi_netslice_subnet
            self.db.set_one("nsts", {"_id": slice_request["nstId"]}, {"_admin.usageState": "IN_USE"})

            # Creating the entry in the database
            self.db.create("nsis", nsi_descriptor)
            rollback.append({"topic": "nsis", "_id": nsi_id})
            return nsi_id
        except Exception as e:
            self.logger.exception("Exception {} at NsiTopic.new()".format(e), exc_info=True)
            raise EngineException("Error {}: {}".format(step, e))
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)


class NsiLcmOpTopic(BaseTopic):
    topic = "nsilcmops"
    topic_msg = "nsi"
    operation_schema = {  # mapping between operation and jsonschema to validate
        "instantiate": nsi_instantiate,
        "terminate": None
    }
    
    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)
        self.nsi_NsLcmOpTopic = NsLcmOpTopic(self.db, self.fs, self.msg)

    def _check_nsi_operation(self, session, nsir, operation, indata):
        """
        Check that user has enter right parameters for the operation
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param indata: descriptor with the parameters of the operation
        :return: None
        """
        nsds = {}
        nstd = nsir["network-slice-template"]

        def check_valid_netslice_subnet_id(nstId):
            # TODO change to vnfR (??)
            for netslice_subnet in nstd["netslice-subnet"]:
                if nstId == netslice_subnet["id"]:
                    nsd_id = netslice_subnet["nsd-ref"]
                    if nsd_id not in nsds:
                        nsds[nsd_id] = self.db.get_one("nsds", {"id": nsd_id})
                    return nsds[nsd_id]
            else:
                raise EngineException("Invalid parameter nstId='{}' is not one of the "
                                      "nst:netslice-subnet".format(nstId))
        if operation == "instantiate":
            # check the existance of netslice-subnet items
            for in_nst in get_iterable(indata.get("netslice-subnet")):   
                check_valid_netslice_subnet_id(in_nst["id"])

    def _create_nsilcmop(self, session, netsliceInstanceId, operation, params):
        now = time()
        _id = str(uuid4())
        nsilcmop = {
            "id": _id,
            "_id": _id,
            "operationState": "PROCESSING",  # COMPLETED,PARTIALLY_COMPLETED,FAILED_TEMP,FAILED,ROLLING_BACK,ROLLED_BACK
            "statusEnteredTime": now,
            "netsliceInstanceId": netsliceInstanceId,
            "lcmOperationType": operation,
            "startTime": now,
            "isAutomaticInvocation": False,
            "operationParams": params,
            "isCancelPending": False,
            "links": {
                "self": "/osm/nsilcm/v1/nsi_lcm_op_occs/" + _id,
                "netsliceInstanceId": "/osm/nsilcm/v1/netslice_instances/" + netsliceInstanceId,
            }
        }
        return nsilcmop

    def add_shared_nsr_2vld(self, nsir, nsr_item):
        for nst_sb_item in nsir["network-slice-template"].get("netslice-subnet"):
            if nst_sb_item.get("is-shared-nss"):
                for admin_subnet_item in nsir["_admin"].get("netslice-subnet"):
                    if admin_subnet_item["nss-id"] == nst_sb_item["id"]:
                        for admin_vld_item in nsir["_admin"].get("netslice-vld"):
                            for admin_vld_nss_cp_ref_item in admin_vld_item["nss-connection-point-ref"]:
                                if admin_subnet_item["nss-id"] == admin_vld_nss_cp_ref_item["nss-ref"]:
                                    if not nsr_item["nsrId"] in admin_vld_item["shared-nsrs-list"]:
                                        admin_vld_item["shared-nsrs-list"].append(nsr_item["nsrId"])
                                    break
        # self.db.set_one("nsis", {"_id": nsir["_id"]}, nsir)
        self.db.set_one("nsis", {"_id": nsir["_id"]}, {"_admin.netslice-vld": nsir["_admin"].get("netslice-vld")})

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Performs a new operation over a ns
        :param rollback: list to append created items at database in case a rollback must to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: descriptor with the parameters of the operation. It must contains among others
            netsliceInstanceId: _id of the nsir to perform the operation
            operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: id of the nslcmops
        """
        try:
            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(indata, kwargs)
            operation = indata["lcmOperationType"]
            netsliceInstanceId = indata["netsliceInstanceId"]
            validate_input(indata, self.operation_schema[operation])

            # get nsi from netsliceInstanceId
            _filter = self._get_project_filter(session)
            _filter["_id"] = netsliceInstanceId
            nsir = self.db.get_one("nsis", _filter)
            del _filter["_id"]

            # initial checking
            if not nsir["_admin"].get("nsiState") or nsir["_admin"]["nsiState"] == "NOT_INSTANTIATED":
                if operation == "terminate" and indata.get("autoremove"):
                    # NSIR must be deleted
                    return None    # a none in this case is used to indicate not instantiated. It can be removed
                if operation != "instantiate":
                    raise EngineException("netslice_instance '{}' cannot be '{}' because it is not instantiated".format(
                        netsliceInstanceId, operation), HTTPStatus.CONFLICT)
            else:
                if operation == "instantiate" and not session["force"]:
                    raise EngineException("netslice_instance '{}' cannot be '{}' because it is already instantiated".
                                          format(netsliceInstanceId, operation), HTTPStatus.CONFLICT)
            
            # Creating all the NS_operation (nslcmop)
            # Get service list from db
            nsrs_list = nsir["_admin"]["nsrs-detailed-list"]
            nslcmops = []
            # nslcmops_item = None
            for index, nsr_item in enumerate(nsrs_list):
                nsi = None
                if nsr_item.get("shared"):
                    _filter["_admin.nsrs-detailed-list.ANYINDEX.shared"] = True
                    _filter["_admin.nsrs-detailed-list.ANYINDEX.nsrId"] = nsr_item["nsrId"]
                    _filter["_admin.nsrs-detailed-list.ANYINDEX.nslcmop_instantiate.ne"] = None
                    _filter["_id.ne"] = netsliceInstanceId
                    nsi = self.db.get_one("nsis", _filter, fail_on_empty=False, fail_on_more=False)
                    if operation == "terminate":
                        _update = {"_admin.nsrs-detailed-list.{}.nslcmop_instantiate".format(index): None}
                        self.db.set_one("nsis", {"_id": nsir["_id"]}, _update)
                        
                    # looks the first nsi fulfilling the conditions but not being the current NSIR
                    if nsi:
                        nsi_admin_shared = nsi["_admin"]["nsrs-detailed-list"]
                        for nsi_nsr_item in nsi_admin_shared:
                            if nsi_nsr_item["nsd-id"] == nsr_item["nsd-id"] and nsi_nsr_item["shared"]:
                                self.add_shared_nsr_2vld(nsir, nsr_item)
                                nslcmops.append(nsi_nsr_item["nslcmop_instantiate"])
                                _update = {"_admin.nsrs-detailed-list.{}".format(index): nsi_nsr_item}
                                self.db.set_one("nsis", {"_id": nsir["_id"]}, _update)
                                break
                        # continue to not create nslcmop since nsrs is shared and nsrs was created
                        continue
                    else:
                        self.add_shared_nsr_2vld(nsir, nsr_item)

                try:
                    service = self.db.get_one("nsrs", {"_id": nsr_item["nsrId"]})
                    indata_ns = {}
                    indata_ns = service["instantiate_params"]
                    indata_ns["lcmOperationType"] = operation
                    indata_ns["nsInstanceId"] = service["_id"]
                    # Including netslice_id in the ns instantiate Operation
                    indata_ns["netsliceInstanceId"] = netsliceInstanceId
                    # Creating NS_LCM_OP with the flag slice_object=True to not trigger the service instantiation
                    # message via kafka bus
                    nslcmop = self.nsi_NsLcmOpTopic.new(rollback, session, indata_ns, kwargs, headers, 
                                                        slice_object=True)
                    nslcmops.append(nslcmop)
                    if operation == "terminate":
                        nslcmop = None
                    _update = {"_admin.nsrs-detailed-list.{}.nslcmop_instantiate".format(index): nslcmop}
                    self.db.set_one("nsis", {"_id": nsir["_id"]}, _update)
                except (DbException, EngineException) as e:
                    if e.http_code == HTTPStatus.NOT_FOUND:
                        self.logger.info("HTTPStatus.NOT_FOUND")
                        pass
                    else:
                        raise

            # Creates nsilcmop
            indata["nslcmops_ids"] = nslcmops
            self._check_nsi_operation(session, nsir, operation, indata)

            nsilcmop_desc = self._create_nsilcmop(session, netsliceInstanceId, operation, indata)
            self.format_on_new(nsilcmop_desc, session["project_id"], make_public=session["public"])
            _id = self.db.create("nsilcmops", nsilcmop_desc)
            rollback.append({"topic": "nsilcmops", "_id": _id})
            self.msg.write("nsi", operation, nsilcmop_desc)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def delete(self, session, _id, dry_run=False):
        raise EngineException("Method delete called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)
