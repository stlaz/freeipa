#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import os

from ipalib import Registry
from ipalib import Updater
from ipalib.constants import IPAAPI_USER, IPAAPI_GROUP
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython import certdb

register = Registry()


@register()
class update_ra_cert_store(Updater):
    """
    Moves the cert store from /etc/httpd/alias to /var/lib/ipa/radb
    """

    def execute(self, **options):
        olddb = certdb.NSSDatabase(nssdir=paths.HTTPD_ALIAS_DIR)
        if not olddb.has_nickname('ipaCert'):
            # Nothign to do
            return False, []

        newdb = certdb.NSSDatabase(nssdir=paths.IPA_RADB_DIR)
        if os.path.exists(paths.IPA_RADB_DIR):
            if newdb.has_nickname('ipaCert'):
                self.log.warning(
                    "An 'ipaCert' nickname exists in both the old {} and the "
                    "new {} NSS Databases!".format(paths.HTTPD_ALIAS_DIR,
                                                   paths.IPA_RADB_DIR))
                return False, []
        else:
            # Create the DB
            newdb.create_db(user=IPAAPI_USER, group=IPAAPI_GROUP, backup=True)

        # Import cert chain (ignore errors, as certs may already be imported)
        certlist = olddb.list_certs()
        certflags = {}
        for name, flags in certlist:
            certflags[name] = flags
        for name in olddb.get_trust_chain('ipaCert'):
            if name == 'ipaCert':
                continue
            try:
                cert = olddb.get_cert(name, pem=True)
                newdb.add_cert(cert, name, certflags[name], pem=True)
            except Exception as e:  # pylint disable=broad-except
                self.log.warning("Failed to import '{}' from trust "
                                 "chain: {}".format(name, str(e)))

        # As the last step delete the RA Cert
        certmonger.stop_tracking(secdir=olddb.secdir,
                                 nickname='ipaCert')
        olddb.delete_cert('ipaCert')

        return False, []
