#!/usr/bin/python

# The MIT License (MIT)
#
# Copyright (c) 2017 Daniel Bechler
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

DOCUMENTATION = '''
---
module: couchdb_database
short_description: Creates or removes a database and manages its permissions.
description:
    - Creates or removes a database and manages its permissions.
options:
    name:
        description:
            - The name of the database
        required: true
    host:
        description:
            - The host running the database
        required: false
        default: localhost
    port:
        description:
            - The port to connect to
        required: false
        default: 5984
    scheme:
        description:
            - the scheme used to connect
        required: false
        default: http
    admin_roles:
        description:
            - The roles that should be able to administer this database
        required: false
        default: []
    admin_names:
        description:
            - The names of users that should be able to administer this database
        required: false
        default: []
    member_roles:
        description:
            - The roles that should be able to read and write from and to this database
        required: false
        default: []
    member_names:
        description:
            - The names of users that should be able to read and write from and to this database
        required: false
        default: []
    state:
        description:
            - The database state
        required: false
        default: present
        choices: [ "present", "absent" ]
    login_user:
        description:
            - The username used to authenticate with
        required: false
    login_password:
        description:
            - The password used to authenticate with
        required: false
version_added: 1.9
requirements: [ "requests" ]
notes:
    - This modules requires the CouchDB cookie authentication handler to be enabled.
author: Daniel Bechler
'''

from ansible_collections.aroberts.couchdb.plugins.module_utils.couchdb import CouchDBClient, CouchDBException, HAS_REQUESTS
try:
    from requests.exceptions import ConnectionError
except: pass

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', default="localhost"),
            port=dict(type='int', default=5984),
            scheme=dict(type='str', default="http"),
            name=dict(type='str', required=True),
            admin_names=dict(type='list', default=None),
            admin_roles=dict(type='list', default=None),
            member_names=dict(type='list', default=None),
            member_roles=dict(type='list', default=None),
            state=dict(type='str', default="present", choices=["absent", "present"]),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True)
        )
    )

    if not HAS_REQUESTS:
        module.fail_json(msg="requests is not installed")

    host = module.params['host']
    port = module.params['port']
    scheme = module.params['scheme']
    name = module.params['name']
    admin_names = module.params['admin_names']
    admin_roles = module.params['admin_roles']
    member_names = module.params['member_names']
    member_roles = module.params['member_roles']
    state = module.params['state']
    login_user = module.params['login_user']
    login_password = module.params['login_password']

    couchdb = CouchDBClient(host, port, scheme, login_user, login_password)
    try:
        couchdb.login()
        changed = False
        kwargs = {}
        if state == "present":
            changed, kwargs = couchdb.database_present(name, admin_names, admin_roles, member_names, member_roles)
        elif state == "absent":
            changed, kwargs = couchdb.database_absent(name)
        module.exit_json(changed=changed, **kwargs)
    except CouchDBException as e:
        kwargs = {
            "msg": e.reason,
            "status_code": e.status_code,
            "error": e.error_type,
            "origin": e.origin
        }
        module.fail_json(**kwargs)
    except ConnectionError:
        kwargs = {
            "msg": "Failed to connect to CouchDB at {0}:{1}".format(host, port),
            "host": host,
            "port": port
        }
        module.fail_json(**kwargs)
    finally:
        couchdb.logout()


from ansible.module_utils.basic import *

main()
