#! /usr/bin/python3
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

import sys
import requests
import yaml
from os import getenv

__author__ = "Alfonso Tierno, alfonso.tiernosepulveda@telefonica.com"
__date__ = "$2019-05-31$"
__version__ = "0.1"
version_date = "May 2019"


def usage():
    print("Usage: ", sys.argv[0], "topic key message")
    print("   Sends a kafka message using URL test of NBI")
    print("  host is defined by env OSMNBI_HOST (localhost by default)")
    print("  port is defined by env OSMNBI_PORT (9999 by default)")
    return


if __name__ == "__main__":
    try:
        if "--help" in sys.argv:
            usage()
            exit(0)

        if len(sys.argv) != 4:
            print("missing parameters. Type --help for more information", file=sys.stderr)
            exit(1)

        topic, key, message = sys.argv[1:]
        host = getenv("OSMNBI_HOST", "localhost")
        port = getenv("OSMNBI_PORT", "9999")
        url = "https://{host}:{port}/osm/test/message/{topic}".format(host=host, port=port, topic=topic)
        print(url)
        data = {key: message}

        r = requests.post(url, data=yaml.safe_dump(data), verify=False)
        if r.status_code not in (200, 201, 202, 204):
            print("Received code={}, content='{}'".format(r.status_code, r.text))
            exit(1)
        print("{} -> {}: {}".format(topic, key, message))

    except Exception:
        raise
