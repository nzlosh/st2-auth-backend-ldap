# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# pylint: disable=no-member

from __future__ import absolute_import
import ldap
import logging
LOG = logging.getLogger(__name__)

__all__ = [
    'LDAPAuthenticationBackend'
]


class LDAPAuthenticationBackend(object):
    """
    Backend which reads authentication information from a ldap server.
    Supported authentication methods:
        * Anonymous session with user lookup.
        * Bind Distinguish Name with user lookup.
        * Bind Distinguish Name with user and group lookup.
    """
    def __init__(self,
                 ldap_uri,
                 use_tls=False,
                 bind_dn='',
                 bind_pw='',
                 user=None,
                 group=None,
                 chase_referrals=True,
                 cert_policy='demand'):
        """
        :param ldap_uri:    URL of the LDAP Server. <proto>://<host>[:port]
        :type ldap_uri:     ``str``
        :param use_tls:     Boolean parameter to set if tls is required.
        :type use_tls:      ``bool``
        :param cert_policy: Set x509 certificate validation policy.
        :type cert_policy:  ``string``
        :param bind_dn:     The Distinguish Name account to bind to the ldap server.
        :type bind_dn:      ``str``
        :param bind_pw:     The Distinguish Name account's password.
        :type bind_pw:      ``str``
        :param user:        Search parameters used to authenticate the user.
                            (base_dn, search_filter, scope)
        :type user:         ``dict``
        :param group:       Search parameters used to confirm the user is a member of a given group.
                            (base_dn, search_filter, scope)
        :type group:        ``dict``
        :param chase_referrals: Boolean specifying whether to
                                chase referrals (defaults to true).
        :type chase_referrals: ``bool``
        """
        self.ldap_uri = ldap_uri
        self.use_tls = use_tls
        self.bind_dn = bind_dn
        self.bind_pw = bind_pw
        self.user = user
        self.group = group
        self.chase_referrals = chase_referrals
        self.cert_policy = self._cert_policy_to_ldap_option(cert_policy)

    def _scope_to_ldap_option(self, scope):
        """
        Transform scope string into ldap module constant.
        """
        return {"base":    ldap.SCOPE_BASE,
                "onelevel": ldap.SCOPE_ONELEVEL,
                "subtree":  ldap.SCOPE_SUBTREE
                }.get(scope.lower()) or ldap.SCOPE_SUBTREE

    def _cert_policy_to_ldap_option(self, tls_opt="demand"):
        """
        demand and hard (default):
            no certificate provided: quits
            bad certificate provided: quits
        try
            no certificate provided: continues
            bad certificate provided: quits
        allow
            no certificate provided: continues
            bad certificate provided: continues
        never
            no certificate is requested
        """
        return {"demand": ldap.OPT_X_TLS_DEMAND,
                "hard":   ldap.OPT_X_TLS_HARD,
                "try":    ldap.OPT_X_TLS_TRY,
                "allow":  ldap.OPT_X_TLS_ALLOW,
                "never":  ldap.OPT_X_TLS_NEVER
                }.get(tls_opt.lower()) or ldap.OPT_X_TLS_DEMAND

    def authenticate(self, username, password):
        """
        Simple binding to authenticate username/password against the LDAP server.
        :param username: username to authenticate.
        :type username: ``str``
        :param password: password to use with for authentication.
        :type password: ``str``
        """
        connection = self._ldap_connect()
        if not connection:
            return False
        try:
            if self.bind_dn == '' == self.bind_pw:
                LOG.debug('Attempting to fast bind anonymously.')
                connection.simple_bind_s()
                LOG.debug('Connected to LDAP as %s ' % connection.whoami_s())
            else:
                LOG.debug('Attempting to fast bind with DN.')
                if self.bind_dn.find('{username}') != -1:
                    self.bind_dn = self.bind_dn.format(username=username)
                if self.bind_pw.find('{password}') != -1:
                    self.bind_pw = self.bind_pw.format(password=password)

                connection.simple_bind_s(self.bind_dn, self.bind_pw)
                LOG.debug('Connected to LDAP as %s ' % connection.whoami_s())

            if self.user:
                # Authenticate username and password.
                result = self._ldap_search(connection, username, self.user)
                if len(result) == 1:

                else:
                    if len(result) == 0:
                        LOG.debug('No matching user found.')
                    else:
                        LOG.debug('Failed to uniquely identify the user. Matched %d ldap objects.' %
                                  (len(result)))
                        LOG.debug('The user search_filter scope may be too broad or there are referrals in the result.')
                    return False
                user_dn = result[0][0]
                LOG.debug('DN identified as : %s' % user_dn)
                try:
                    user_connection = self._ldap_connect()
                    user_connection.simple_bind_s(user_dn, password)
                    LOG.debug('User successfully authenticated as %s ' % connection.whoami_s())
                except ldap.LDAPError as e:
                    LOG.debug('LDAP Error: %s' % (str(e)))
                    return False
                finally:
                    user_connection.unbind()

            if self.group:
                # Confirm the user is a member of a given group.
                result = self._ldap_search(connection, username, self.group)
                if len(result) != 1:
                    LOG.debug('Unable to find %s in the group.' % username)
                    return False

        except ldap.LDAPError as e:
            LOG.debug('(authenticate) LDAP Error: %s : Type %s' % (str(e), type(e)))
            return False
        finally:
            connection.unbind()
            LOG.debug('LDAP connection closed')
        return True

    def _ldap_connect(self):
        """
        Prepare ldap object for binding phase.
        """
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            connection = ldap.initialize(self.ldap_uri)
            connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            connection.set_option(ldap.OPT_REFERRALS, int(self._chase_referrals))
            if self.use_tls:
                connection.set_option(ldap.OPT_X_TLS, self.cert_policy)
                connection.start_tls_s()
                LOG.debug('Connection now using TLS')
            return connection
        except ldap.LDAPError as e:
            LOG.debug('(_ldap_connect) LDAP Error: %s : Type %s' % (str(e), type(e)))
            return False

    def _ldap_search(self, connection, username, criteria):
        """
        Perform a search against the LDAP server using an established connection.
        :param connection:  The established LDAP connection.
        :type connection:   ``LDAPobject``
        :param username:    The username to be used in the search filter.
        :type username:     ``str``
        :param criteria:    A dictionary of search filter parameters.
                            (base_dn, search_filter, scope, pattern)
        :type criteria:     ``dict``
        """
        base_dn = criteria.get('base_dn') or ""
        search_filter = criteria.get('search_filter').format(username=username) or ""
        scope = self._scope_to_ldap_option(criteria.get('scope'))
        log_results = criteria.get('log_results') or False

        LOG.debug('Searching ... base_dn:"%s" scope:"%s" search_filter:"%s"' % (base_dn, scope, search_filter))
        result = connection.search_s(base_dn, scope, search_filter)
        if log_results == True:
            LOG.debug("RESULT: {}".format(result))
        return result

    def get_user(self, username):
        pass
