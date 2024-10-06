#!/usr/bin/python

# The MIT License (MIT)
#
# Copyright (c) 2015 Daniel Bechler
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
module: couchdb_user
short_description: Adds, changes or removes a user from a CouchDB database.
description:
    - Adds, changes or removes a user from a CouchDB database.
options:
    name:
        description:
            - The name of the user
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
    node:
        description:
            - The cluster node to apply the changes to. Required for CouchDB 2.0 and later
        required: false
    password:
        description:
            - The password of the user
        required: false
    raw_password:
        description:
            - Indicates whether the password is already salted and hashed
        required: false
        choices: [ "yes", "no" ]
        default: "no"
    admin:
        description:
            - Indicates whether the targeted user is admin or not
        required: false
        choices: [ "yes", "no" ]
        default: "no"
    roles:
        description:
            - The roles of the user
        required: false
        default: []
    state:
        description:
            - The database user state. If set to `absent` a `login_user` and `login_password` must be provided.
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

EXAMPLES = '''
# create an admin user (does not require login credentials when no other admin exists)
- couchdb_user: name=heisenberg password=the-one-who-knocks admin=yes state=present

# create another admin user (requires login credentials)
- couchdb_user: >
    name=gustavo
    password=los-pollos-hermanos
    admin=yes
    state=present
    login_user=heisenberg
    login_password=the-one-who-knocks

# create a regular user (by default users can create their own user documents)
- couchdb_user: name=mike password=half-measures state=present

# assign roles to that user
- couchdb_user: >
    name=mike
    roles=cleaner,consultant
    state=present
    login_user=any-admin-or-the-target-user
    login_password=password

# change password (requires login credentials of either the target user or an admin)
- couchdb_user: name=mike password=bulletproof state=present login_user=mike login_password=half-measures

# assign a pre-generated password hash
- couchdb_user: >
    name=mike
    password=-pbkdf2-4a1bc30e4f3a7c03ad703ca0fdc60b37580a2542,3600790547b8af251f385410cd702f0e,10
    raw_password=yes
    state=present
    login_user=any-admin-or-the-target-user
    login_password=password

# remove admin user (requires login credentials of an admin user)
- couchdb_user: name=gustavo admin=yes state=absent login_user=any-admin login_password=password

# remove regular user (requires login credentials)
- couchdb_user: name=mike state=absent login_user=any-admin-or-the-target-user login_password=password
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
            password=dict(type='str', required=False, no_log=True),
            raw_password=dict(type='bool', choices=BOOLEANS, default='no'),
            admin=dict(type='bool', choices=BOOLEANS, default='no'),
            roles=dict(type='list', default=None),
            state=dict(type='str', default="present", choices=["absent", "present"]),
            login_user=dict(type='str', required=False),
            login_password=dict(type='str', required=False, no_log=True),
            node=dict(type='str', required=False)
        ),
        required_together=[['login_user', 'login_password']]
    )

    if not HAS_REQUESTS:
        module.fail_json(msg="requests is not installed")

    host = module.params['host']
    port = module.params['port']
    scheme = module.params['scheme']
    node = module.params['node']
    username = module.params['name']
    password = module.params['password']
    raw_password = module.params['raw_password']
    admin = module.params['admin']
    roles = module.params['roles']
    state = module.params['state']
    login_user = module.params['login_user']
    login_password = module.params['login_password']

    # I thought about making this configurable, but then thought it would be better to let the
    # module figure it out on its own. Unfortunately once an admin account exists, the config API
    # can only be accessed by admin users; so there is no reliable way to get this information.
    #
    # In order to make this work all non-admin-user-specific operations would need to be performed
    # by an admin user. That seems overly restrictive, since its not an actual restriction of CouchDB.
    # Even the CouchDB docs don't seem to have an answer on how a user is supposed to create his own
    # document in case he or she doesn't know the name of the authentication_db.
    #
    # So for now I prefer to neglect this feature and wait to see if anyone actually needs it.
    authentication_db = '_users'

    couchdb = CouchDBClient(host, port, scheme, login_user, login_password, authentication_db, node)
    try:
        if state == "absent" and not login_user:
            if admin:
                module.fail_json(msg="You need to be admin in order to remove admin users.")
            elif not couchdb.is_admin_party():
                module.fail_json(msg="You need to be authenticated in order to remove users "
                                     "when you have admin users.")

        couchdb.login()
        changed = False
        kwargs = {}
        if admin is True:
            if state == "present":
                changed = couchdb.create_or_update_admin_user(username, password, raw_password)
            elif state == "absent":
                changed = couchdb.remove_admin_user(username)
        else:
            if state == "present":
                changed = couchdb.create_or_update_user(username, password, raw_password=raw_password, roles=roles)
            elif state == "absent":
                changed = couchdb.remove_user(username)
                kwargs = {
                    "msg": "Notice: Due to CouchDBs secure design, there is no way to tell "
                           "for sure, whether the user has actually been deleted if you didn't "
                           "provide a proper 'login_user' and 'login_password'."
                }
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
            "port": port,
            "scheme": scheme
        }
        module.fail_json(**kwargs)
    finally:
        couchdb.logout()


from ansible.module_utils.basic import *

main()
