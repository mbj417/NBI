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


import asyncio
import aiohttp
from base_topic import EngineException

__author__ = "Vijay R S <vijay.r@tataelxsi.co.in>"


class PmJobsTopic():
    def __init__(self, host=None, port=None):
        self.url = 'http://{}:{}'.format(host, port)
        self.metric_list = ['cpu_utilization', 'average_memory_utilization', 'disk_read_ops',
                            'disk_write_ops', 'disk_read_bytes', 'disk_write_bytes', 'packets_dropped',
                            'packets_sent', 'packets_received']

    async def _prom_metric_request(self, ns_id):
        try:
            async with aiohttp.ClientSession() as session:
                data = []
                for metlist in self.metric_list:
                    request_url = self.url+'/api/v1/query?query=osm_'+metlist+"{ns_id='"+ns_id+"'}"
                    async with session.get(request_url) as resp:
                        resp = await resp.json()
                        resp = resp['data']['result']
                        if resp:
                            data.append(resp)
                return data
        except aiohttp.client_exceptions.ClientConnectorError as e:
            raise EngineException("Connection Failure: {}".format(e))

    def show(self, session, ns_id):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        prom_metric = loop.run_until_complete(self._prom_metric_request(ns_id))
        metric = {}
        metric_temp = []
        for index_list in prom_metric:
            for index in index_list:
                process_metric = {'performanceValue': {'performanceValue': {}}}
                process_metric['objectInstanceId'] = index['metric']['ns_id']
                process_metric['performanceMetric'] = index['metric']['__name__']
                process_metric['performanceValue']['timestamp'] = index['value'][0]
                process_metric['performanceValue']['performanceValue']['performanceValue'] = index['value'][1]
                process_metric['performanceValue']['performanceValue']['vnfMemberIndex'] \
                    = index['metric']['vnf_member_index']
                process_metric['performanceValue']['performanceValue']['vduName'] = index['metric']['vdu_name']
                metric_temp.append(process_metric)
        metric['entries'] = metric_temp
        return metric
