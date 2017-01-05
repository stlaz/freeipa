#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

'''
This Debian family platform module exports platform dependant constants.
'''

# Fallback to default path definitions
from ipaplatform.base.constants import BaseConstantsNamespace


class DebianConstantsNamespace(BaseConstantsNamespace):
    HTTPD_USER = "www-data"
    NAMED_USER = "bind"
    NAMED_GROUP = "bind"
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "NTPD_OPTS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\'"
    ODS_USER = "opendnssec"
    ODS_GROUP = "opendnssec"
    SECURE_NFS_VAR = "NEED_GSSD"

constants = DebianConstantsNamespace()
