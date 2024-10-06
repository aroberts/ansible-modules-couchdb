try:
    import json
except ImportError:
    import simplejson as json

HAS_REQUESTS = True
try:
    import requests
    from requests.auth import AuthBase
    from requests.exceptions import ConnectionError

    class HTTPCookieAuth(AuthBase):

        def __init__(self, session_token):
            self.session_token = session_token

        def __call__(self, r):
            # delete any existing cookies on the request
            r.headers.pop('Cookies', None)
            r.prepare_cookies({
                "AuthSession": self.session_token
            })
            return r
except ImportError:
    HAS_REQUESTS = False

class CouchDBException(Exception):

    def __init__(self, status_code, error_type="unknown", reason=None, origin=None):
        self.status_code = status_code
        self.error_type = error_type
        self.reason = reason
        self.origin = origin


class AuthenticationException(Exception):

    def __init__(self, user, message):
        self.user = user
        self.message = message


class CouchDBClient(object):

    def __init__(self, host="localhost", port="5984", scheme="http", login_user=None, login_password=None, authentication_db="_users", node=None):
        self._auth = None
        self.host = host
        self.port = port
        self.scheme = scheme
        self.login_user = login_user
        self.login_password = login_password
        self.authentication_db = authentication_db
        self.node = node

    def login(self):
        self._auth = None
        if self.login_user:
            try:
                session = self.create_session(self.login_user, self.login_password)
                self._auth = HTTPCookieAuth(session)
            except AuthenticationException:
                pass

    def logout(self):
        if self._auth:
            session_token = self._auth.session_token
            try:
                self.close_session(session_token)
            finally:
                self._auth = None

    def is_admin_party(self):
        try:
            admins = self._get_config_value("admins")
            return admins is None
        except CouchDBException as e:
            if e.status_code in [requests.codes.unauthorized, requests.codes.forbidden]:
                return False
            else:
                raise e

    def create_session(self, username, password):
        url = self._get_absolute_url("/_session")
        data = "name={0}&password={1}".format(username, password)
        headers = {
            "Accept": "application/json",
            "Content-Length": str(len(data)),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.post(url, headers=headers, data=data)
        if r.status_code == requests.codes.ok:
            auth_session = r.cookies.get("AuthSession")
            return auth_session
        elif r.status_code == requests.codes.unauthorized:
            reason = r.json()["reason"]
            raise AuthenticationException(user=username, message=reason)
        else:
            raise self._create_exception(r)

    def close_session(self, session_token):
        url = self._get_absolute_url("/_session")
        requests.post(url, **{
            "headers": {"Accept": "application/json"},
            "cookies": {"AuthSession": session_token}
        })

    def create_or_update_admin_user(self, username, password, raw_password=False):
        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return False
        except AuthenticationException:
            pass
        if raw_password and self._get_config_value("admins", username) == password:
            return False
        return self._set_config_value("admins", username, '"{0}"'.format(password), raw=raw_password)

    def remove_admin_user(self, username):
        url = self._get_config_url("admins", username)
        headers = {"Accept": "application/json"}
        r = requests.delete(url, headers=headers, auth=self._auth)
        if r.status_code == requests.codes.ok:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        else:
            raise self._create_exception(r)

    def create_or_update_user(self, username, password, raw_password=False, roles=None):
        if not roles:
            roles = []

        has_changes = False
        document = self.get_document(self.authentication_db, "org.couchdb.user:{0}".format(username))
        if not document:
            document = {}
            has_changes = True

        if raw_password:
            password_scheme_and_derived_key, salt, iterations = password.split(",", 3)
            password_scheme, derived_key = password_scheme_and_derived_key[1:].split("-")
            original_data = [
                document.get("password_scheme"),
                document.get("derived_key"),
                document.get("salt"),
                int(document.get("iterations"))
            ]
            desired_data = [password_scheme, derived_key, salt, int(iterations)]
            if original_data != desired_data:
                document["password_scheme"] = password_scheme
                document["derived_key"] = derived_key
                document["salt"] = salt
                document["iterations"] = int(iterations)
                document.pop("password", None)
                has_changes = True
        elif not self._can_authenticate(username, password):
            document["password"] = password
            document.pop("password_scheme", None)
            document.pop("derived_key", None)
            document.pop("salt", None)
            document.pop("iterations", None)
            has_changes = True

        if document.get("name") != username:
            document["name"] = username
            has_changes = True
        if document.get("roles") != roles:
            document["roles"] = roles
            has_changes = True
        document["type"] = "user"

        if not has_changes:
            return False

        headers = {
            "Accept": "application/json",
            "X-Couch-Full-Commit": "true",
            "If-Match": document.get("_rev")
        }
        r = requests.put(url=self._get_user_url(username),
                         data=json.dumps(document),
                         headers=headers,
                         auth=self._auth)
        if r.status_code in [requests.codes.created, requests.codes.accepted]:
            return True
        else:
            raise self._create_exception(r)

    def remove_user(self, username):
        user = self.get_document(self.authentication_db, "org.couchdb.user:{0}".format(username))
        if user is None:
            return False
        url = self._get_user_url(username)
        headers = {
            "Accept": "application/json",
            "If-Match": user.get("_rev")
        }
        r = requests.delete(url, headers=headers, auth=self._auth)
        if r.status_code in [requests.codes.ok, requests.codes.accepted]:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        else:
            raise self._create_exception(r)

    def get_document(self, database, document_id):
        url = self._get_absolute_url("/{0}/{1}".format(database, document_id))
        headers = {"Accept": "application/json"}
        r = requests.get(url, headers=headers, auth=self._auth)
        if r.status_code in [requests.codes.ok, requests.codes.not_modified]:
            return r.json()
        elif r.status_code == requests.codes.not_found:
            return None
        else:
            raise self._create_exception(r)

    def _get_absolute_url(self, path):
        return "{3}://{0}:{1}{2}".format(self.host, self.port, path, self.scheme)

    def _get_user_url(self, username):
        return self._get_absolute_url("/{0}/org.couchdb.user:{1}".format(self.authentication_db, username))

    def _get_config_url(self, section, option=None):
        path_elements = []
        node = self.node if self.node else '_local'
        path_elements.append('/_node/{0}'.format(node))
        path_elements.append('/_config/{0}'.format(section))
        if option:
            path_elements.append('/{0}'.format(option))
        return self._get_absolute_url(''.join(path_elements))

    def _get_config_value(self, section, option=None):
        url = self._get_config_url(section, option)
        r = requests.get(url, auth=self._auth)
        if r.status_code == requests.codes.ok:
            value = r.text
            return value.strip()
        elif r.status_code == requests.codes.not_found:
            return None
        else:
            raise self._create_exception(r)

    def _set_config_value(self, section, option, value, raw=False):
        url = self._get_config_url(section, option)
        params = {"raw": "true"} if raw else None
        r = requests.put(url, **{
            "headers": {"Accept": "application/json"},
            "auth": self._auth,
            "data": value,
            "params": params
        })
        if r.status_code == requests.codes.ok:
            return r.text != value
        else:
            raise self._create_exception(r)

    def _can_authenticate(self, username, password):
        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return True
        except AuthenticationException:
            return False

    @staticmethod
    def _create_exception(r):
        status_code = r.status_code
        if r.headers['content-type'] == 'application/json':
            response_body = r.json()
            error_type = response_body['error']
            reason = response_body['reason']
            origin = {
                "url": r.request.url,
                "method": r.request.method,
                "headers": dict(r.request.headers)
            }
            return CouchDBException(status_code, reason=reason, error_type=error_type, origin=origin)
        else:
            response_body = r.text
            return CouchDBException(status_code, reason=response_body)

    # db module methods
    @staticmethod
    def update_dict_entry_values(values, target_dict, target_key):
        original_values = target_dict.get(target_key, [])
        if isinstance(values, list) and len(values) > 0:
            target_dict[target_key] = values
        else:
            target_dict[target_key] = []
        changed = original_values != target_dict[target_key]
        return changed

    def database_exist(self, database):
        url = self._get_absolute_url("/_all_dbs")
        r = requests.get(url, auth=self._auth)
        if r.status_code in [requests.codes.ok, requests.codes.not_modified]:
            dbs = r.json()
            return database in dbs
        else:
            raise self._create_exception(r)

    def database_present(self, name, admin_names, admin_roles, member_names, member_roles):
        if not self.database_exist(name):
            r = requests.put(self._get_absolute_url('/{0}'.format(name)),
                             auth=self._auth,
                             headers={"accept": "application/json"})
            database_created = False
            if r.status_code == 200:
                database_created = True
            elif r.status_code == 201:
                database_created = True
            elif r.status_code == 412:
                database_created = False
            else:
                raise self._create_exception(r)
        else:
            database_created = False

        document = self.get_document(name, '_security')
        if document is None:
            document = {}
        if document.get('admins') is None:
            document['admins'] = {}
        if document.get('members') is None:
            document['members'] = {}

        admin_names_changed = self.update_dict_entry_values(admin_names, document['admins'], 'names')
        admin_roles_changed = self.update_dict_entry_values(admin_roles, document['admins'], 'roles')
        member_names_changed = self.update_dict_entry_values(member_names, document['members'], 'names')
        member_roles_changed = self.update_dict_entry_values(member_roles, document['members'], 'roles')

        security_document_changed = admin_names_changed or admin_roles_changed or member_names_changed or member_roles_changed
        security_document_updated = False
        if security_document_changed:
            r = requests.put(self._get_absolute_url('/{0}/_security'.format(name)), **{
                'data': json.dumps(document),
                'auth': self._auth,
                'headers': {
                    'Accept': 'application/json',
                    'X-Couch-Full-Commit': 'true'
                }
            })
            if r.status_code == requests.codes.ok:
                security_document_updated = True
            else:
                raise self._create_exception(r)

        changed = database_created or security_document_updated
        context = {
            'database_created': database_created,
            'permissions_changed': security_document_updated
        }
        return changed, context

    def database_absent(self, name):
        response = requests.get(self._get_absolute_url('/{0}'.format(name)), auth=self._auth)

        database_deleted = False
        if response.status_code == 200:
            delete_request = requests.delete(self._get_absolute_url('/' + name), auth=self._auth)
            if delete_request.status_code == 200:
                database_deleted = True
            else:
                raise self._create_exception(response)

        context = {
            'database_deleted': database_deleted
        }
        return database_deleted, context

