#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
IPA client install module

Provides methods for installation, uninstallation of IPA client
"""

from __future__ import (
    print_function,
    absolute_import,
)

import dns
import getpass
import gssapi
import netifaces
import os
import SSSDConfig
import socket
import sys
import tempfile
import time

# pylint: disable=import-error
from six.moves.configparser import RawConfigParser
from six.moves.urllib.parse import urlparse, urlunparse
# pylint: enable=import-error

from ipaclient import (
    ipadiscovery,
    ipachangeconf,
    ntpconf,
)
from ipalib import (
    api,
    certstore,
    errors,
    x509,
)
from ipalib.constants import CACERT
from ipalib.rpc import delete_persistent_client_session_data
from ipalib.util import (
    broadcast_ip_address_warning,
    network_ip_address_warning,
    verify_host_resolvable,
)
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython import (
    certdb,
    certmonger,
    kernel_keyring,
    ipaldap,
    ipautil,
    sysrestore,
)
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger
from ipapython.ipautil import (
    CalledProcessError,
    dir_exists,
    file_exists,
    realm_to_suffix,
    run,
    user_input,
)
from ipapython.ssh import SSHPublicKey


SUCCESS = 0
CLIENT_INSTALL_ERROR = 1
CLIENT_NOT_CONFIGURED = 2
CLIENT_ALREADY_CONFIGURED = 3
CLIENT_UNINSTALL_ERROR = 4  # error after restoring files/state

fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)


def remove_file(filename):
    """
    Deletes a file. If the file does not exist (OSError 2) does nothing.
    Otherwise logs an error message and instructs the user to remove the
    offending file manually
    :param filename: name of the file to be removed
    """

    try:
        os.remove(filename)
    except OSError as e:
        if e.errno == 2:
            return

        root_logger.error("Failed to remove file %s: %s", filename, e)
        root_logger.error('Please remove %s manually, as it can cause '
                          'subsequent installation to fail.', filename)


def log_service_error(name, action, error):
    root_logger.error("%s failed to %s: %s", name, action, str(error))


def get_cert_path(cert_path):
    """
    If a CA certificate is passed in on the command line, use that.

    Else if a CA file exists in CACERT then use that.

    Otherwise return None.
    """
    if cert_path is not None:
        return cert_path

    if os.path.exists(CACERT):
        return CACERT

    return None


def save_state(service):
    enabled = service.is_enabled()
    running = service.is_running()

    if enabled or running:
        statestore.backup_state(service.service_name, 'enabled', enabled)
        statestore.backup_state(service.service_name, 'running', running)


def restore_state(service):
    enabled = statestore.restore_state(service.service_name, 'enabled')
    running = statestore.restore_state(service.service_name, 'running')

    if enabled:
        try:
            service.enable()
        except Exception:
            root_logger.warning(
                "Failed to configure automatic startup of the %s daemon",
                service.service_name
            )
    if running:
        try:
            service.start()
        except Exception:
            root_logger.warning(
                "Failed to restart the %s daemon",
                service.service_name
            )


def nssldap_exists():
    """Checks whether nss_ldap or nss-pam-ldapd is installed.
     If anyone of mandatory files was found returns True and list of all files
     found.
    """
    files_to_check = [
        {
            'function': 'configure_ldap_conf',
            'mandatory': [
                paths.LDAP_CONF,
                paths.NSS_LDAP_CONF,
                paths.LIBNSS_LDAP_CONF],
            'optional':[paths.PAM_LDAP_CONF]
        },
        {
            'function': 'configure_nslcd_conf',
            'mandatory': [paths.NSLCD_CONF]
        }
    ]
    files_found = {}
    retval = False

    for function in files_to_check:
        files_found[function['function']] = []
        for file_type in ['mandatory', 'optional']:
            try:
                for filename in function[file_type]:
                    if file_exists(filename):
                        files_found[function['function']].append(filename)
                        if file_type == 'mandatory':
                            retval = True
            except KeyError:
                pass

    return (retval, files_found)


def delete_ipa_domain():
    """Helper function for uninstall.
    Deletes IPA domain from sssd.conf
    """
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()

        ipa_domain_name = None

        for name in domains:
            domain = sssdconfig.get_domain(name)
            try:
                provider = domain.get_option('id_provider')
                if provider == "ipa":
                    ipa_domain_name = name
                    break
            except SSSDConfig.NoOptionError:
                continue

        if ipa_domain_name is not None:
            sssdconfig.delete_domain(ipa_domain_name)
            sssdconfig.write()
        else:
            root_logger.warning(
                "IPA domain could not be found in "
                "/etc/sssd/sssd.conf and therefore not deleted")
    except IOError:
        root_logger.warning(
            "IPA domain could not be deleted. "
            "No access to the /etc/sssd/sssd.conf file.")


def is_ipa_client_installed(on_master=False):
    """
    Consider IPA client not installed if nothing is backed up
    and default.conf file does not exist. If on_master is set to True,
    the existence of default.conf file is not taken into consideration,
    since it has been already created by ipa-server-install.
    """

    installed = (
        fstore.has_files() or (
            not on_master and os.path.exists(paths.IPA_DEFAULT_CONF)
        )
    )

    return installed


def configure_nsswitch_database(fstore, database, services, preserve=True,
                                append=True, default_value=()):
    """
    Edits the specified nsswitch.conf database (e.g. passwd, group, sudoers)
    to use the specified service(s).

    Arguments:
        fstore - FileStore to backup the nsswitch.conf
        database - database configuration that should be ammended,
                   e.g 'sudoers'
        service - list of services that should be added, e.g. ['sss']
        preserve - if True, the already configured services will be preserved

    The next arguments modify the behaviour if preserve=True:
        append - if True, the services will be appended, if False, prepended
        default_value - list of services that are considered as default (if
                        the database is not mentioned in nsswitch.conf), e.g.
                        ['files']
    """

    # Backup the original version of nsswitch.conf, we're going to edit it now
    if not fstore.has_file(paths.NSSWITCH_CONF):
        fstore.backup_file(paths.NSSWITCH_CONF)

    conf = ipachangeconf.IPAChangeConf("IPA Installer")
    conf.setOptionAssignment(':')

    if preserve:
        # Read the existing configuration
        with open(paths.NSSWITCH_CONF, 'r') as f:
            opts = conf.parse(f)
            raw_database_entry = conf.findOpts(opts, 'option', database)[1]

        # Detect the list of already configured services
        if not raw_database_entry:
            # If there is no database entry, database is not present in
            # the nsswitch.conf. Set the list of services to the
            # default list, if passed.
            configured_services = list(default_value)
        else:
            configured_services = raw_database_entry['value'].strip().split()

        # Make sure no service is added if already mentioned in the list
        added_services = [s for s in services
                          if s not in configured_services]

        # Prepend / append the list of new services
        if append:
            new_value = ' ' + ' '.join(configured_services + added_services)
        else:
            new_value = ' ' + ' '.join(added_services + configured_services)

    else:
        # Preserve not set, let's rewrite existing configuration
        new_value = ' ' + ' '.join(services)

    # Set new services as sources for database
    opts = [
        {
            'name': database,
            'type': 'option',
            'action': 'set',
            'value': new_value
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ]

    conf.changeConf(paths.NSSWITCH_CONF, opts)
    root_logger.info("Configured %s in %s" % (database, paths.NSSWITCH_CONF))


def configure_ipa_conf(
        fstore, cli_basedn, cli_realm, cli_domain, cli_server, hostname):
    ipaconf = ipachangeconf.IPAChangeConf("IPA Installer")
    ipaconf.setOptionAssignment(" = ")
    ipaconf.setSectionNameDelimiters(("[", "]"))

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ]

    # [global]
    defopts = [
        {
            'name': 'basedn',
            'type': 'option',
            'value': cli_basedn
        },
        {
            'name': 'realm',
            'type': 'option',
            'value': cli_realm
        },
        {
            'name': 'domain',
            'type': 'option',
            'value': cli_domain
        },
        {
            'name': 'server',
            'type': 'option',
            'value': cli_server[0]
        },
        {
            'name': 'host',
            'type': 'option',
            'value': hostname
        },
        {
            'name': 'xmlrpc_uri',
            'type': 'option',
            'value': 'https://%s/ipa/xml' % ipautil.format_netloc(
                cli_server[0])
        },
        {
            'name': 'enable_ra',
            'type': 'option',
            'value': 'True'
        }
    ]

    opts.extend([
        {
            'name': 'global',
            'type': 'section',
            'value': defopts
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ])

    target_fname = paths.IPA_DEFAULT_CONF
    fstore.backup_file(target_fname)
    ipaconf.newConf(target_fname, opts)
    os.chmod(target_fname, 0o644)

    return 0


def disable_ra():
    """Set the enable_ra option in /etc/ipa/default.conf to False

    Note that api.env will retain the old value (it is readonly).
    """
    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    parser.set('global', 'enable_ra', 'False')
    fp = open(paths.IPA_DEFAULT_CONF, 'w')
    parser.write(fp)
    fp.close()


def configure_ldap_conf(
        fstore, cli_basedn, cli_realm, cli_domain, cli_server, dnsok, options,
        files):
    ldapconf = ipachangeconf.IPAChangeConf("IPA Installer")
    ldapconf.setOptionAssignment(" ")

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'ldap_version',
            'type': 'option',
            'value': '3'
        },
        {
            'name': 'base',
            'type': 'option',
            'value': cli_basedn
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'nss_base_passwd',
            'type': 'option',
            'value': str(
                DN(('cn', 'users'), ('cn', 'accounts'), cli_basedn)
            ) + '?sub'
        },
        {
            'name': 'nss_base_group',
            'type': 'option',
            'value': str(
                DN(('cn', 'groups'), ('cn', 'accounts'), cli_basedn)
            ) + '?sub'
        },
        {
            'name': 'nss_schema',
            'type': 'option',
            'value': 'rfc2307bis'
        },
        {
            'name': 'nss_map_attribute',
            'type': 'option',
            'value': 'uniqueMember member'
        },
        {
            'name': 'nss_initgroups_ignoreusers',
            'type': 'option',
            'value': 'root,dirsrv'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'nss_reconnect_maxsleeptime',
            'type': 'option',
            'value': '8'
        },
        {
            'name': 'nss_reconnect_sleeptime',
            'type': 'option',
            'value': '1'
        },
        {
            'name': 'bind_timelimit',
            'type': 'option',
            'value': '5'
        },
        {
            'name': 'timelimit',
            'type': 'option',
            'value': '15'
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ]
    if not dnsok or options.force or options.on_master:
        if options.on_master:
            opts.append({
                'name': 'uri',
                'type': 'option',
                'value': 'ldap://localhost'
            })
        else:
            opts.append({
                'name': 'uri',
                'type': 'option',
                'value': 'ldap://{}'.format(
                    ipautil.format_netloc(cli_server[0]))
            })
    else:
        opts.append({
            'name': 'nss_srv_domain',
            'type': 'option',
            'value': cli_domain
        })

    opts.append({
        'name': 'empty',
        'type': 'empty'
    })

    # Depending on the release and distribution this may exist in any
    # number of different file names, update what we find
    for filename in files:
        try:
            fstore.backup_file(filename)
            ldapconf.newConf(filename, opts)
        except Exception as e:
            root_logger.error("Creation of %s failed: %s", filename, str(e))
            return (1, 'LDAP', filename)

    if files:
        return (0, 'LDAP', ', '.join(files))

    return 0, None, None


def configure_nslcd_conf(
        fstore, cli_basedn, cli_realm, cli_domain, cli_server, dnsok, options,
        files):
    nslcdconf = ipachangeconf.IPAChangeConf("IPA Installer")
    nslcdconf.setOptionAssignment(" ")

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'ldap_version',
            'type': 'option',
            'value': '3'
        },
        {
            'name': 'base',
            'type': 'option',
            'value': cli_basedn
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'base passwd',
            'type': 'option',
            'value': str(
                DN(('cn', 'users'), ('cn', 'accounts'), cli_basedn))
        },
        {
            'name': 'base group',
            'type': 'option',
            'value': str(
                DN(('cn', 'groups'), ('cn', 'accounts'), cli_basedn))
        },
        {
            'name': 'timelimit',
            'type': 'option',
            'value': '15'
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ]

    if not dnsok or options.force or options.on_master:
        if options.on_master:
            opts.append({
                'name': 'uri',
                'type': 'option',
                'value': 'ldap://localhost'
            })
        else:
            opts.append({
                'name': 'uri',
                'type': 'option',
                'value': 'ldap://{}'.format(
                    ipautil.format_netloc(cli_server[0]))
            })
    else:
        opts.append({
            'name': 'uri',
            'type': 'option',
            'value': 'DNS'
        })

    opts.append({
        'name': 'empty',
        'type': 'empty'
    })

    for filename in files:
        try:
            fstore.backup_file(filename)
            nslcdconf.newConf(filename, opts)
        except Exception as e:
            root_logger.error("Creation of %s failed: %s", filename, str(e))
            return (1, None, None)

    nslcd = services.knownservices.nslcd
    if nslcd.is_installed():
        try:
            nslcd.restart()
        except Exception as e:
            log_service_error(nslcd.service_name, 'restart', e)

        try:
            nslcd.enable()
        except Exception as e:
            root_logger.error(
                "Failed to enable automatic startup of the %s daemon: %s",
                nslcd.service_name, str(e))
    else:
        root_logger.debug(
            "%s daemon is not installed, skip configuration",
            nslcd.service_name)
        return (0, None, None)

    return (0, 'NSLCD', ', '.join(files))


def configure_openldap_conf(fstore, cli_basedn, cli_server):
    ldapconf = ipachangeconf.IPAChangeConf("IPA Installer")
    ldapconf.setOptionAssignment((" ", "\t"))

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' File modified by ipa-client-install'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' We do not want to break your existing configuration, '
                     'hence:'
        },
        # this needs to be kept updated if we change more options
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   URI, BASE and TLS_CACERT have been added if they '
                     'were not set.'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   In case any of them were set, a comment with '
                     'trailing note'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   "# modified by IPA" note has been inserted.'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' To use IPA server with openLDAP tools, please comment '
                     'out your'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' existing configuration for these options and '
                     'uncomment the'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' corresponding lines generated by IPA.'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'action': 'addifnotset',
            'name': 'URI',
            'type': 'option',
            'value': 'ldaps://{}'.format(cli_server[0])
        },
        {
            'action': 'addifnotset',
            'name': 'BASE',
            'type': 'option',
            'value': str(cli_basedn)
        },
        {
            'action': 'addifnotset',
            'name': 'TLS_CACERT',
            'type': 'option',
            'value': CACERT
        },
    ]

    target_fname = paths.OPENLDAP_LDAP_CONF
    fstore.backup_file(target_fname)

    error_msg = "Configuring {path} failed with: {err}"

    try:
        ldapconf.changeConf(target_fname, opts)
    except SyntaxError as e:
        root_logger.info("Could not parse {path}".format(path=target_fname))
        root_logger.debug(error_msg.format(path=target_fname, err=str(e)))
        return False
    except IOError as e:
        root_logger.info("{path} does not exist.".format(path=target_fname))
        root_logger.debug(error_msg.format(path=target_fname, err=str(e)))
        return False
    except Exception as e:  # we do not want to fail in an optional step
        root_logger.debug(error_msg.format(path=target_fname, err=str(e)))
        return False

    os.chmod(target_fname, 0o644)
    return True


def hardcode_ldap_server(cli_server):
    """
    DNS Discovery didn't return a valid IPA server, hardcode a value into
    the file instead.
    """
    if not file_exists(paths.LDAP_CONF):
        return

    ldapconf = ipachangeconf.IPAChangeConf("IPA Installer")
    ldapconf.setOptionAssignment(" ")

    opts = [
        {
            'name': 'uri',
            'type': 'option',
            'action': 'set',
            'value': 'ldap://{}'.format(ipautil.format_netloc(cli_server[0]))
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ]

    # Errors raised by this should be caught by the caller
    ldapconf.changeConf(paths.LDAP_CONF, opts)
    root_logger.info(
        "Changed configuration of /etc/ldap.conf to use "
        "hardcoded server name: %s", cli_server[0])

    return


def configure_krb5_conf(
        cli_realm, cli_domain, cli_server, cli_kdc, dnsok,
        options, filename, client_domain, client_hostname):

    krbconf = ipachangeconf.IPAChangeConf("IPA Installer")
    krbconf.setOptionAssignment((" = ", " "))
    krbconf.setSectionNameDelimiters(("[", "]"))
    krbconf.setSubSectionDelimiters(("{", "}"))
    krbconf.setIndent(("", "  ", "    "))

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        {
            'name': 'empty',
            'type': 'empty'
        },
        {
            'name': 'includedir',
            'type': 'option',
            'value': paths.COMMON_KRB5_CONF_DIR,
            'delim': ' '
        }
    ]

    # SSSD include dir
    if options.sssd:
        opts.extend([
            {
                'name': 'includedir',
                'type': 'option',
                'value': paths.SSSD_PUBCONF_KRB5_INCLUDE_D_DIR,
                'delim': ' '
            },
            {
                'name': 'empty',
                'type': 'empty'
            }
        ])

    # [libdefaults]
    libopts = [{
            'name': 'default_realm',
            'type': 'option',
            'value': cli_realm
        }]

    if not dnsok or not cli_kdc or options.force:
        libopts.extend([
            {
                'name': 'dns_lookup_realm',
                'type': 'option',
                'value': 'false'
            },
            {
                'name': 'dns_lookup_kdc',
                'type': 'option',
                'value': 'false'
            }
        ])
    else:
        libopts.extend([
            {
                'name': 'dns_lookup_realm',
                'type': 'option',
                'value': 'true'
            },
            {
                'name': 'dns_lookup_kdc',
                'type': 'option',
                'value': 'true'
            }
        ])

    libopts.extend([
        {
            'name': 'rdns',
            'type': 'option',
            'value': 'false'
        },
        {
            'name': 'ticket_lifetime',
            'type': 'option',
            'value': '24h'
        },
        {
            'name': 'forwardable',
            'type': 'option',
            'value': 'true'
        },
        {
            'name': 'udp_preference_limit',
            'type': 'option',
            'value': '0'
        }
    ])

    # Configure KEYRING CCACHE if supported
    if kernel_keyring.is_persistent_keyring_supported():
        root_logger.debug("Enabling persistent keyring CCACHE")
        libopts.append({
            'name': 'default_ccache_name',
            'type': 'option',
            'value': 'KEYRING:persistent:%{uid}'
        })

    opts.extend([
        {
            'name': 'libdefaults',
            'type': 'section',
            'value': libopts
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ])

    # the following are necessary only if DNS discovery does not work
    kropts = []
    if not dnsok or not cli_kdc or options.force:
        # [realms]
        for server in cli_server:
            kropts.extend([
                {
                    'name': 'kdc',
                    'type': 'option',
                    'value': ipautil.format_netloc(server, 88)
                },
                {
                    'name': 'master_kdc',
                    'type': 'option',
                    'value': ipautil.format_netloc(server, 88)
                },
                {
                    'name': 'admin_server',
                    'type': 'option',
                    'value': ipautil.format_netloc(server, 749)
                },
                {
                    'name': 'kpasswd_server',
                    'type': 'option',
                    'value': ipautil.format_netloc(server, 464)
                }
            ])

        kropts.append({
            'name': 'default_domain',
            'type': 'option',
            'value': cli_domain
        })

    kropts.append({
        'name': 'pkinit_anchors',
        'type': 'option',
        'value': 'FILE:{}'.format(CACERT)
    })

    ropts = [{
        'name': cli_realm,
        'type': 'subsection',
        'value': kropts
    }]

    opts.extend([
        {
            'name': 'realms',
            'type': 'section',
            'value': ropts
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ])

    # [domain_realm]
    dropts = [
        {
            'name': '.{}'.format(cli_domain),
            'type': 'option',
            'value': cli_realm
        },
        {
            'name': cli_domain,
            'type': 'option',
            'value': cli_realm
        },
        {
            'name': client_hostname,
            'type': 'option',
            'value': cli_realm
        }
    ]

    # add client domain mapping if different from server domain
    if cli_domain != client_domain:
        dropts.extend([
            {
                'name': '.{}'.format(client_domain),
                'type': 'option',
                'value': cli_realm
            },
            {
                'name': client_domain,
                'type': 'option',
                'value': cli_realm
            }
        ])

    opts.extend([
        {
            'name': 'domain_realm',
            'type': 'section',
            'value': dropts
        },
        {
            'name': 'empty',
            'type': 'empty'
        }
    ])

    root_logger.debug("Writing Kerberos configuration to %s:", filename)
    root_logger.debug("%s", krbconf.dump(opts))

    krbconf.newConf(filename, opts)
    os.chmod(filename, 0o644)

    return 0


def configure_certmonger(
        fstore, subject_base, cli_realm, hostname, options, ca_enabled):

    if not options.request_cert:
        return

    if not ca_enabled:
        root_logger.warning("An RA is not configured on the server. "
                            "Not requesting host certificate.")
        return

    principal = 'host/%s@%s' % (hostname, cli_realm)

    if options.hostname:
        # If the hostname is explicitly set then we need to tell certmonger
        # which principal name to use when requesting certs.
        certmonger.add_principal_to_cas(principal)

    cmonger = services.knownservices.certmonger
    try:
        cmonger.enable()
    except Exception as e:
        root_logger.error(
            "Failed to configure automatic startup of the %s daemon: %s",
            cmonger.service_name, str(e))
        root_logger.warning(
            "Automatic certificate management will not be available")

    # Request our host cert
    subject = str(DN(('CN', hostname), subject_base))
    passwd_fname = os.path.join(paths.IPA_NSSDB_DIR, 'pwdfile.txt')
    try:
        certmonger.request_cert(
            nssdb=paths.IPA_NSSDB_DIR,
            nickname='Local IPA host', subject=subject, dns=[hostname],
            principal=principal, passwd_fname=passwd_fname)
    except Exception as ex:
        root_logger.error(
            "%s request for host certificate failed: %s",
            cmonger.service_name, ex)


def configure_sssd_conf(
        fstore, cli_realm, cli_domain, cli_server, options,
        client_domain, client_hostname):
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
    except Exception as e:
        if os.path.exists(paths.SSSD_CONF) and options.preserve_sssd:
            # SSSD config is in place but we are unable to read it
            # In addition, we are instructed to preserve it
            # This all means we can't use it and have to bail out
            root_logger.error(
                "SSSD config exists but cannot be parsed: %s", str(e))
            root_logger.error(
                "Was instructed to preserve existing SSSD config")
            root_logger.info(
                "Correct errors in /etc/sssd/sssd.conf and re-run "
                "installation")
            return 1

        # SSSD configuration does not exist or we are not asked to preserve it,
        # create new one
        # We do make new SSSDConfig instance because IPAChangeConf-derived
        # classes have no means to reset their state and ParseError exception
        # could come due to parsing error from older version which cannot be
        # upgraded anymore, leaving sssdconfig instance practically unusable
        # Note that we already backed up sssd.conf before going into this
        # routine
        if isinstance(e, IOError):
            pass
        else:
            # It was not IOError so it must have been parsing error
            root_logger.error(
                "Unable to parse existing SSSD config. "
                "As option --preserve-sssd was not specified, new config "
                "will override the old one.")
            root_logger.info(
                "The old /etc/sssd/sssd.conf is backed up and "
                "will be restored during uninstall.")
        root_logger.info("New SSSD config will be created")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()

    try:
        domain = sssdconfig.new_domain(cli_domain)
    except SSSDConfig.DomainAlreadyExistsError:
        root_logger.info(
            "Domain %s is already configured in existing SSSD "
            "config, creating a new one.",
            cli_domain)
        root_logger.info(
            "The old /etc/sssd/sssd.conf is backed up and will be restored "
            "during uninstall.")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()
        domain = sssdconfig.new_domain(cli_domain)

    ssh_dir = services.knownservices.sshd.get_config_dir()
    ssh_config = os.path.join(ssh_dir, 'ssh_config')
    sshd_config = os.path.join(ssh_dir, 'sshd_config')

    if (
        (options.conf_ssh and file_exists(ssh_config)) or
        (options.conf_sshd and file_exists(sshd_config))
    ):
        try:
            sssdconfig.new_service('ssh')
        except SSSDConfig.ServiceAlreadyExists:
            pass
        except SSSDConfig.ServiceNotRecognizedError:
            root_logger.error(
                "Unable to activate the SSH service in SSSD config.")
            root_logger.info(
                "Please make sure you have SSSD built with SSH support "
                "installed.")
            root_logger.info(
                "Configure SSH support manually in /etc/sssd/sssd.conf.")

        sssdconfig.activate_service('ssh')

    if options.conf_sudo:
        # Activate the service in the SSSD config
        try:
            sssdconfig.new_service('sudo')
        except SSSDConfig.ServiceAlreadyExists:
            pass
        except SSSDConfig.ServiceNotRecognizedError:
            root_logger.error(
                "Unable to activate the SUDO service in SSSD config.")

        sssdconfig.activate_service('sudo')
        configure_nsswitch_database(
            fstore, 'sudoers', ['sss'],
            default_value=['files'])

    domain.add_provider('ipa', 'id')

    # add discovery domain if client domain different from server domain
    # do not set this config in server mode (#3947)
    if not options.on_master and cli_domain != client_domain:
        domain.set_option('dns_discovery_domain', cli_domain)

    if not options.on_master:
        if options.primary:
            domain.set_option('ipa_server', ', '.join(cli_server))
        else:
            domain.set_option(
                'ipa_server', '_srv_, %s' % ', '.join(cli_server))
    else:
        domain.set_option('ipa_server_mode', 'True')
        # the master should only use itself for Kerberos
        domain.set_option('ipa_server', cli_server[0])

        # increase memcache timeout to 10 minutes when in server mode
        try:
            nss_service = sssdconfig.get_service('nss')
        except SSSDConfig.NoServiceError:
            nss_service = sssdconfig.new_service('nss')

        nss_service.set_option('memcache_timeout', 600)
        sssdconfig.save_service(nss_service)

    domain.set_option('ipa_domain', cli_domain)
    domain.set_option('ipa_hostname', client_hostname)
    if cli_domain.lower() != cli_realm.lower():
        domain.set_option('krb5_realm', cli_realm)

    # Might need this if /bin/hostname doesn't return a FQDN
    # domain.set_option('ipa_hostname', 'client.example.com')

    domain.add_provider('ipa', 'auth')
    domain.add_provider('ipa', 'chpass')
    if not options.permit:
        domain.add_provider('ipa', 'access')
    else:
        domain.add_provider('permit', 'access')

    domain.set_option('cache_credentials', True)

    # SSSD will need TLS for checking if ipaMigrationEnabled attribute is set
    # Note that SSSD will force StartTLS because the channel is later used for
    # authentication as well if password migration is enabled. Thus set
    # the option unconditionally.
    domain.set_option('ldap_tls_cacert', CACERT)

    if options.dns_updates:
        domain.set_option('dyndns_update', True)
        if options.all_ip_addresses:
            domain.set_option('dyndns_iface', '*')
        else:
            iface = get_server_connection_interface(cli_server[0])
            domain.set_option('dyndns_iface', iface)
    if options.krb5_offline_passwords:
        domain.set_option('krb5_store_password_if_offline', True)

    domain.set_active(True)

    sssdconfig.save_domain(domain)
    sssdconfig.write(paths.SSSD_CONF)

    return 0


def change_ssh_config(filename, changes, sections):
    if not changes:
        return True

    try:
        f = open(filename, 'r')
    except IOError as e:
        root_logger.error("Failed to open '%s': %s", filename, str(e))
        return False

    change_keys = tuple(key.lower() for key in changes)
    section_keys = tuple(key.lower() for key in sections)

    lines = []
    in_section = False
    for line in f:
        line = line.rstrip('\n')
        pline = line.strip()
        if not pline or pline.startswith('#'):
            lines.append(line)
            continue
        option = pline.split()[0].lower()
        if option in section_keys:
            in_section = True
            break
        if option in change_keys:
            line = '#' + line
        lines.append(line)
    for option, value in changes.items():
        if value is not None:
            lines.append('%s %s' % (option, value))
    if in_section:
        lines.append('')
        lines.append(line)
    for line in f:
        line = line.rstrip('\n')
        lines.append(line)
    lines.append('')

    f.close()

    try:
        f = open(filename, 'w')
    except IOError as e:
        root_logger.error("Failed to open '%s': %s", filename, str(e))
        return False

    f.write('\n'.join(lines))

    f.close()

    return True


def configure_ssh_config(fstore, options):
    ssh_dir = services.knownservices.sshd.get_config_dir()
    ssh_config = os.path.join(ssh_dir, 'ssh_config')

    if not file_exists(ssh_config):
        root_logger.info("%s not found, skipping configuration", ssh_config)
        return

    fstore.backup_file(ssh_config)

    changes = {'PubkeyAuthentication': 'yes'}

    if options.sssd and file_exists(paths.SSS_SSH_KNOWNHOSTSPROXY):
        changes[
            'ProxyCommand'] = '%s -p %%p %%h' % paths.SSS_SSH_KNOWNHOSTSPROXY
        changes['GlobalKnownHostsFile'] = paths.SSSD_PUBCONF_KNOWN_HOSTS
    if options.trust_sshfp:
        changes['VerifyHostKeyDNS'] = 'yes'
        changes['HostKeyAlgorithms'] = 'ssh-rsa,ssh-dss'

    change_ssh_config(ssh_config, changes, ['Host', 'Match'])
    root_logger.info('Configured %s', ssh_config)


def configure_sshd_config(fstore, options):
    sshd = services.knownservices.sshd
    ssh_dir = sshd.get_config_dir()
    sshd_config = os.path.join(ssh_dir, 'sshd_config')

    if not file_exists(sshd_config):
        root_logger.info("%s not found, skipping configuration", sshd_config)
        return

    fstore.backup_file(sshd_config)

    changes = {
        'PubkeyAuthentication': 'yes',
        'KerberosAuthentication': 'no',
        'GSSAPIAuthentication': 'yes',
        'UsePAM': 'yes',
        'ChallengeResponseAuthentication': 'yes',
    }

    if options.sssd and file_exists(paths.SSS_SSH_AUTHORIZEDKEYS):
        authorized_keys_changes = None

        candidates = (
            {
                'AuthorizedKeysCommand': paths.SSS_SSH_AUTHORIZEDKEYS,
                'AuthorizedKeysCommandUser': 'nobody',
            },
            {
                'AuthorizedKeysCommand': paths.SSS_SSH_AUTHORIZEDKEYS,
                'AuthorizedKeysCommandRunAs': 'nobody',
            },
            {
                'PubKeyAgent': '%s %%u' % paths.SSS_SSH_AUTHORIZEDKEYS,
                'PubKeyAgentRunAs': 'nobody',
            },
        )

        for candidate in candidates:
            args = ['sshd', '-t', '-f', paths.DEV_NULL]
            for item in candidate.items():
                args.append('-o')
                args.append('%s=%s' % item)

            result = ipautil.run(args, raiseonerr=False)
            if result.returncode == 0:
                authorized_keys_changes = candidate
                break

        if authorized_keys_changes is not None:
            changes.update(authorized_keys_changes)
        else:
            root_logger.warning(
                "Installed OpenSSH server does not support dynamically "
                "loading authorized user keys. Public key authentication of "
                "IPA users will not be available.")

    change_ssh_config(sshd_config, changes, ['Match'])
    root_logger.info('Configured %s', sshd_config)

    if sshd.is_running():
        try:
            sshd.restart()
        except Exception as e:
            log_service_error(sshd.service_name, 'restart', e)


def configure_automount(options):
    root_logger.info('\nConfiguring automount:')

    args = [
        'ipa-client-automount', '--debug', '-U', '--location',
        options.location
    ]

    if options.server:
        args.extend(['--server', options.server[0]])
    if not options.sssd:
        args.append('--no-sssd')

    try:
        result = run(args)
    except Exception as e:
        root_logger.error('Automount configuration failed: %s', str(e))
    else:
        root_logger.info(result.output_log)


def configure_nisdomain(options, domain):
    domain = options.nisdomain or domain
    root_logger.info('Configuring %s as NIS domain.' % domain)

    nis_domain_name = ''

    # First backup the old NIS domain name
    if os.path.exists(paths.BIN_NISDOMAINNAME):
        try:
            result = ipautil.run(
                [paths.BIN_NISDOMAINNAME],
                capture_output=True)
        except CalledProcessError:
            pass
        else:
            nis_domain_name = result.output

    statestore.backup_state('network', 'nisdomain', nis_domain_name)

    # Backup the state of the domainname service
    statestore.backup_state(
        "domainname", "enabled",
        services.knownservices.domainname.is_enabled())

    # Set the new NIS domain name
    tasks.set_nisdomain(domain)

    # Enable and start the domainname service
    services.knownservices.domainname.enable()
    # Restart rather than start so that new NIS domain name is loaded
    # if the service is already running
    services.knownservices.domainname.restart()


def unconfigure_nisdomain():
    # Set the nisdomain permanent and current nisdomain configuration as it was
    if statestore.has_state('network'):
        old_nisdomain = statestore.restore_state('network', 'nisdomain') or ''

        if old_nisdomain:
            root_logger.info('Restoring %s as NIS domain.' % old_nisdomain)
        else:
            root_logger.info('Unconfiguring the NIS domain.')

        tasks.set_nisdomain(old_nisdomain)

    # Restore the configuration of the domainname service
    enabled = statestore.restore_state('domainname', 'enabled')
    if not enabled:
        services.knownservices.domainname.disable()


def get_iface_from_ip(ip_addr):
    for interface in netifaces.interfaces():
        if_addrs = netifaces.ifaddresses(interface)
        for family in [netifaces.AF_INET, netifaces.AF_INET6]:
            for ip in if_addrs.get(family, []):
                if ip['addr'] == ip_addr:
                    return interface
    else:
        raise RuntimeError("IP %s not assigned to any interface." % ip_addr)


def get_local_ipaddresses(iface=None):
    if iface:
        interfaces = [iface]
    else:
        interfaces = netifaces.interfaces()

    ips = []
    for interface in interfaces:
        if_addrs = netifaces.ifaddresses(interface)
        for family in [netifaces.AF_INET, netifaces.AF_INET6]:
            for ip in if_addrs.get(family, []):
                try:
                    ips.append(ipautil.CheckedIPAddress(ip['addr']))
                    root_logger.debug('IP check successful: %s' % ip['addr'])
                except ValueError as e:
                    root_logger.debug('IP check failed: %s' % e)
    return ips


def do_nsupdate(update_txt):
    root_logger.debug("Writing nsupdate commands to %s:", UPDATE_FILE)
    root_logger.debug("%s", update_txt)

    update_fd = open(UPDATE_FILE, "w")
    update_fd.write(update_txt)
    update_fd.flush()
    update_fd.close()

    result = False
    try:
        ipautil.run([paths.NSUPDATE, '-g', UPDATE_FILE])
        result = True
    except CalledProcessError as e:
        root_logger.debug('nsupdate failed: %s', str(e))

    try:
        os.remove(UPDATE_FILE)
    except Exception:
        pass

    return result


DELETE_TEMPLATE_A = """
update delete $HOSTNAME. IN A
show
send
"""

DELETE_TEMPLATE_AAAA = """
update delete $HOSTNAME. IN AAAA
show
send
"""

ADD_TEMPLATE_A = """
update add $HOSTNAME. $TTL IN A $IPADDRESS
show
send
"""

ADD_TEMPLATE_AAAA = """
update add $HOSTNAME. $TTL IN AAAA $IPADDRESS
show
send
"""

UPDATE_FILE = paths.IPA_DNS_UPDATE_TXT
CCACHE_FILE = paths.IPA_DNS_CCACHE


def update_dns(server, hostname, options):

    try:
        ips = get_local_ipaddresses()
    except CalledProcessError as e:
        root_logger.error("Cannot update DNS records. %s" % e)
        root_logger.debug("Unable to get local IP addresses.")

    if options.all_ip_addresses:
        update_ips = ips
    elif options.ip_addresses:
        update_ips = []
        for ip in options.ip_addresses:
            update_ips.append(ipautil.CheckedIPAddress(ip))
    else:
        try:
            iface = get_server_connection_interface(server)
        except RuntimeError as e:
            root_logger.error("Cannot update DNS records. %s" % e)
            return
        try:
            update_ips = get_local_ipaddresses(iface)
        except CalledProcessError as e:
            root_logger.error("Cannot update DNS records. %s" % e)
            return

    if not update_ips:
        root_logger.info("Failed to determine this machine's ip address(es).")
        return

    network_ip_address_warning(update_ips)
    broadcast_ip_address_warning(update_ips)

    update_txt = "debug\n"
    update_txt += ipautil.template_str(DELETE_TEMPLATE_A,
                                       dict(HOSTNAME=hostname))
    update_txt += ipautil.template_str(DELETE_TEMPLATE_AAAA,
                                       dict(HOSTNAME=hostname))

    for ip in update_ips:
        sub_dict = dict(HOSTNAME=hostname, IPADDRESS=ip, TTL=1200)
        if ip.version == 4:
            template = ADD_TEMPLATE_A
        elif ip.version == 6:
            template = ADD_TEMPLATE_AAAA
        update_txt += ipautil.template_str(template, sub_dict)

    if not do_nsupdate(update_txt):
        root_logger.error("Failed to update DNS records.")
    verify_dns_update(hostname, update_ips)


def verify_dns_update(fqdn, ips):
    """
    Verify that the fqdn resolves to all IP addresses and
    that there's matching PTR record for every IP address.
    """
    # verify A/AAAA records
    missing_ips = [str(ip) for ip in ips]
    extra_ips = []
    for record_type in [dns.rdatatype.A, dns.rdatatype.AAAA]:
        root_logger.debug('DNS resolver: Query: %s IN %s' %
                          (fqdn, dns.rdatatype.to_text(record_type)))
        try:
            answers = dns.resolver.query(fqdn, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            root_logger.debug('DNS resolver: No record.')
        except dns.resolver.NoNameservers:
            root_logger.debug('DNS resolver: No nameservers answered the'
                              'query.')
        except dns.exception.DNSException:
            root_logger.debug('DNS resolver error.')
        else:
            for rdata in answers:
                try:
                    missing_ips.remove(rdata.address)
                except ValueError:
                    extra_ips.append(rdata.address)

    # verify PTR records
    fqdn_name = dns.name.from_text(fqdn)
    wrong_reverse = {}
    missing_reverse = [str(ip) for ip in ips]
    for ip in ips:
        ip_str = str(ip)
        addr = dns.reversename.from_address(ip_str)
        root_logger.debug('DNS resolver: Query: %s IN PTR' % addr)
        try:
            answers = dns.resolver.query(addr, dns.rdatatype.PTR)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            root_logger.debug('DNS resolver: No record.')
        except dns.resolver.NoNameservers:
            root_logger.debug('DNS resolver: No nameservers answered the'
                              'query.')
        except dns.exception.DNSException:
            root_logger.debug('DNS resolver error.')
        else:
            missing_reverse.remove(ip_str)
            for rdata in answers:
                if not rdata.target == fqdn_name:
                    wrong_reverse.setdefault(ip_str, []).append(rdata.target)

    if missing_ips:
        root_logger.warning('Missing A/AAAA record(s) for host %s: %s.' %
                            (fqdn, ', '.join(missing_ips)))
    if extra_ips:
        root_logger.warning('Extra A/AAAA record(s) for host %s: %s.' %
                            (fqdn, ', '.join(extra_ips)))
    if missing_reverse:
        root_logger.warning('Missing reverse record(s) for address(es): %s.' %
                            ', '.join(missing_reverse))
    if wrong_reverse:
        root_logger.warning('Incorrect reverse record(s):')
        for ip in wrong_reverse:
            for target in wrong_reverse[ip]:
                root_logger.warning('%s is pointing to %s instead of %s' %
                                    (ip, target, fqdn_name))


def get_server_connection_interface(server):
    """Connect to IPA server, get all ip addresses of interface used to connect
    """
    for res in socket.getaddrinfo(
            server, 389, socket.AF_UNSPEC, socket.SOCK_STREAM):
        af, socktype, proto, _canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except socket.error as e:
            last_error = e
            s = None
            continue
        try:
            s.connect(sa)
            sockname = s.getsockname()
            ip = sockname[0]
        except socket.error as e:
            last_error = e
            continue
        finally:
            if s:
                s.close()
        try:
            return get_iface_from_ip(ip)
        except (CalledProcessError, RuntimeError) as e:
            last_error = e
    else:
        msg = "Cannot get server connection interface"
        if last_error:
            msg += ": %s" % (last_error)
        raise RuntimeError(msg)


def client_dns(server, hostname, options):

    try:
        verify_host_resolvable(hostname)
        dns_ok = True
    except errors.DNSNotARecordError:
        root_logger.warning("Hostname (%s) does not have A/AAAA record.",
                            hostname)
        dns_ok = False
    except errors.DNSResolverError as ex:
        root_logger.warning("DNS resolution for hostname %s failed: %s",
                            hostname, ex)
        dns_ok = False

    if (
        options.dns_updates or options.all_ip_addresses or
        options.ip_addresses or not dns_ok
    ):
        update_dns(server, hostname, options)


def check_ip_addresses(options):
    if options.ip_addresses:
        for ip in options.ip_addresses:
            try:
                ipautil.CheckedIPAddress(ip, match_local=True)
            except ValueError as e:
                root_logger.error(e)
                return False
    return True


def update_ssh_keys(hostname, ssh_dir, create_sshfp):
    if not os.path.isdir(ssh_dir):
        return

    pubkeys = []
    for basename in os.listdir(ssh_dir):
        if not basename.endswith('.pub'):
            continue
        filename = os.path.join(ssh_dir, basename)

        try:
            f = open(filename, 'r')
        except IOError as e:
            root_logger.warning("Failed to open '%s': %s", filename, str(e))
            continue

        for line in f:
            line = line[:-1].lstrip()
            if not line or line.startswith('#'):
                continue
            try:
                pubkey = SSHPublicKey(line)
            except (ValueError, UnicodeDecodeError):
                continue
            root_logger.info("Adding SSH public key from %s", filename)
            pubkeys.append(pubkey)

        f.close()

    try:
        # Use the RPC directly so older servers are supported
        api.Backend.rpcclient.forward(
            'host_mod',
            ipautil.fsdecode(hostname),
            ipasshpubkey=[pk.openssh() for pk in pubkeys],
            updatedns=False,
            version=u'2.26',  # this version adds support for SSH public keys
        )
    except errors.EmptyModlist:
        pass
    except Exception as e:
        root_logger.info("host_mod: %s", str(e))
        root_logger.warning("Failed to upload host SSH public keys.")
        return

    if create_sshfp:
        ttl = 1200

        update_txt = 'debug\n'
        update_txt += 'update delete %s. IN SSHFP\nshow\nsend\n' % hostname
        for pubkey in pubkeys:
            sshfp = pubkey.fingerprint_dns_sha1()
            if sshfp is not None:
                update_txt += 'update add %s. %s IN SSHFP %s\n' % (
                    hostname, ttl, sshfp)
            sshfp = pubkey.fingerprint_dns_sha256()
            if sshfp is not None:
                update_txt += 'update add %s. %s IN SSHFP %s\n' % (
                    hostname, ttl, sshfp)
        update_txt += 'show\nsend\n'

        if not do_nsupdate(update_txt):
            root_logger.warning("Could not update DNS SSHFP records.")


def print_port_conf_info():
    root_logger.info(
        "Please make sure the following ports are opened "
        "in the firewall settings:\n"
        "     TCP: 80, 88, 389\n"
        "     UDP: 88 (at least one of TCP/UDP ports 88 has to be open)\n"
        "Also note that following ports are necessary for ipa-client "
        "working properly after enrollment:\n"
        "     TCP: 464\n"
        "     UDP: 464, 123 (if NTP enabled)")


def cert_summary(msg, certs, indent='    '):
    if msg:
        s = '%s\n' % msg
    else:
        s = ''
    for cert in certs:
        s += '%sSubject:     %s\n' % (indent, cert.subject)
        s += '%sIssuer:      %s\n' % (indent, cert.issuer)
        s += '%sValid From:  %s\n' % (indent, cert.valid_not_before_str)
        s += '%sValid Until: %s\n' % (indent, cert.valid_not_after_str)
        s += '\n'
    s = s[:-1]

    return s


def get_certs_from_ldap(server, base_dn, realm, ca_enabled):
    conn = ipaldap.IPAdmin(server, sasl_nocanon=True)
    try:
        conn.do_sasl_gssapi_bind()
        certs = certstore.get_ca_certs(conn, base_dn, realm, ca_enabled)
    except errors.NotFound:
        raise errors.NoCertificateError(entry=server)
    except errors.NetworkError as e:
        raise errors.NetworkError(uri=conn.ldap_uri, error=str(e))
    except Exception as e:
        raise errors.LDAPError(str(e))
    finally:
        conn.unbind()

    return certs


def get_ca_certs_from_file(url):
    """
    Get the CA cert from a user supplied file and write it into the
    CACERT file.

    Raises errors.NoCertificateError if unable to read cert.
    Raises errors.FileError if unable to write cert.
    """

    try:
        parsed = urlparse(url, 'file')
    except Exception:
        raise errors.FileError(reason="unable to parse file url '%s'" % url)

    if parsed.scheme != 'file':
        raise errors.FileError(reason="url is not a file scheme '%s'" % url)

    filename = parsed.path

    if not os.path.exists(filename):
        raise errors.FileError(reason="file '%s' does not exist" % filename)

    if not os.path.isfile(filename):
        raise errors.FileError(reason="file '%s' is not a file" % filename)

    root_logger.debug("trying to retrieve CA cert from file %s", filename)
    try:
        certs = x509.load_certificate_list_from_file(filename)
    except Exception:
        raise errors.NoCertificateError(entry=filename)

    return certs


def get_ca_certs_from_http(url, warn=True):
    """
    Use HTTP to retrieve the CA cert and write it into the CACERT file.
    This is insecure and should be avoided.

    Raises errors.NoCertificateError if unable to retrieve and write cert.
    """

    if warn:
        root_logger.warning("Downloading the CA certificate via HTTP, " +
                            "this is INSECURE")

    root_logger.debug("trying to retrieve CA cert via HTTP from %s", url)
    try:

        result = run([paths.BIN_CURL, "-o", "-", url], capture_output=True)
    except CalledProcessError:
        raise errors.NoCertificateError(entry=url)
    stdout = result.output

    try:
        certs = x509.load_certificate_list(stdout)
    except Exception:
        raise errors.NoCertificateError(entry=url)

    return certs


def get_ca_certs_from_ldap(server, basedn, realm):
    """
    Retrieve th CA cert from the LDAP server by binding to the
    server with GSSAPI using the current Kerberos credentials.
    Write the retrieved cert into the CACERT file.

    Raises errors.NoCertificateError if cert is not found.
    Raises errors.NetworkError if LDAP connection can't be established.
    Raises errors.LDAPError for any other generic LDAP error.
    Raises errors.OnlyOneValueAllowed if more than one cert is found.
    Raises errors.FileError if unable to write cert.
    """

    root_logger.debug("trying to retrieve CA cert via LDAP from %s", server)

    try:
        certs = get_certs_from_ldap(server, basedn, realm, False)
    except Exception as e:
        root_logger.debug("get_ca_certs_from_ldap() error: %s", e)
        raise

    certs = [x509.load_certificate(c[0], x509.DER) for c in certs
             if c[2] is not False]

    return certs


def validate_new_ca_certs(existing_ca_certs, new_ca_certs, ask,
                          override=False):
    if existing_ca_certs is None:
        root_logger.info(
            cert_summary("Successfully retrieved CA cert", new_ca_certs))
        return

    existing_ca_certs = set(existing_ca_certs)
    new_ca_certs = set(new_ca_certs)
    if existing_ca_certs > new_ca_certs:
        root_logger.warning(
            "The CA cert available from the IPA server does not match the\n"
            "local certificate available at %s" % CACERT)
        root_logger.warning(
            cert_summary("Existing CA cert:", existing_ca_certs))
        root_logger.warning(
            cert_summary("Retrieved CA cert:", new_ca_certs))
        if override:
            root_logger.warning("Overriding existing CA cert\n")
        elif not ask or not user_input(
                "Do you want to replace the local certificate with the CA\n"
                "certificate retrieved from the IPA server?", True):
            raise errors.CertificateInvalidError(name='Retrieved CA')
    else:
        root_logger.debug(
                "Existing CA cert and Retrieved CA cert are identical")


def get_ca_certs(fstore, options, server, basedn, realm):
    """
    Examine the different options and determine a method for obtaining
    the CA cert.

    If successful the CA cert will have been written into CACERT.

    Raises errors.NoCertificateError if not successful.

    The logic for determining how to load the CA cert is as follow:

    In the OTP case (not -p and -w):

    1. load from user supplied cert file
    2. else load from HTTP

    In the 'user_auth' case ((-p and -w) or interactive):

    1. load from user supplied cert file
    2. load from LDAP using SASL/GSS/Krb5 auth
       (provides mutual authentication, integrity and security)
    3. if LDAP failed and interactive ask for permission to
       use insecure HTTP (default: No)

    In the unattended case:

    1. load from user supplied cert file
    2. load from HTTP if --force specified else fail

    In all cases if HTTP is used emit warning message
    """

    ca_file = CACERT + ".new"

    def ldap_url():
        return urlunparse(('ldap', ipautil.format_netloc(server),
                           '', '', '', ''))

    def file_url():
        return urlunparse(('file', '', options.ca_cert_file,
                           '', '', ''))

    def http_url():
        return urlunparse(('http', ipautil.format_netloc(server),
                           '/ipa/config/ca.crt', '', '', ''))

    interactive = not options.unattended
    otp_auth = options.principal is None and options.password is not None
    existing_ca_certs = None
    ca_certs = None

    if options.ca_cert_file:
        url = file_url()
        try:
            ca_certs = get_ca_certs_from_file(url)
        except errors.FileError as e:
            root_logger.debug(e)
            raise
        except Exception as e:
            root_logger.debug(e)
            raise errors.NoCertificateError(entry=url)
        root_logger.debug("CA cert provided by user, use it!")
    else:
        if os.path.exists(CACERT):
            if os.path.isfile(CACERT):
                try:
                    existing_ca_certs = x509.load_certificate_list_from_file(
                        CACERT)
                except Exception as e:
                    raise errors.FileError(reason=u"Unable to load existing" +
                                           " CA cert '%s': %s" % (CACERT, e))
            else:
                raise errors.FileError(reason=u"Existing ca cert '%s' is " +
                                       "not a plain file" % (CACERT))

        if otp_auth:
            if existing_ca_certs:
                root_logger.info("OTP case, CA cert preexisted, use it")
            else:
                url = http_url()
                override = not interactive
                if interactive and not user_input(
                    "Do you want to download the CA cert from " + url + " ?\n"
                    "(this is INSECURE)", False
                ):
                    raise errors.NoCertificateError(
                        message=u"HTTP certificate download declined by user")
                try:
                    ca_certs = get_ca_certs_from_http(url, override)
                except Exception as e:
                    root_logger.debug(e)
                    raise errors.NoCertificateError(entry=url)

                validate_new_ca_certs(existing_ca_certs, ca_certs, False,
                                      override)
        else:
            # Auth with user credentials
            try:
                url = ldap_url()
                ca_certs = get_ca_certs_from_ldap(server, basedn, realm)
                validate_new_ca_certs(existing_ca_certs, ca_certs, interactive)
            except errors.FileError as e:
                root_logger.debug(e)
                raise
            except (errors.NoCertificateError, errors.LDAPError) as e:
                root_logger.debug(str(e))
                url = http_url()
                if existing_ca_certs:
                    root_logger.warning(
                        "Unable to download CA cert from LDAP\n"
                        "but found preexisting cert, using it.\n")
                elif interactive and not user_input(
                    "Unable to download CA cert from LDAP.\n"
                    "Do you want to download the CA cert from " + url + "?\n"
                    "(this is INSECURE)", False
                ):
                    raise errors.NoCertificateError(
                        message=u"HTTP "
                        "certificate download declined by user")
                elif not interactive and not options.force:
                    root_logger.error(
                        "In unattended mode without a One Time Password "
                        "(OTP) or without --ca-cert-file\nYou must specify"
                        " --force to retrieve the CA cert using HTTP")
                    raise errors.NoCertificateError(
                        message=u"HTTP "
                        "certificate download requires --force")
                else:
                    try:
                        ca_certs = get_ca_certs_from_http(url)
                    except Exception as e:
                        root_logger.debug(e)
                        raise errors.NoCertificateError(entry=url)
                    validate_new_ca_certs(existing_ca_certs, ca_certs,
                                          interactive)
            except Exception as e:
                root_logger.debug(str(e))
                raise errors.NoCertificateError(entry=url)

        if ca_certs is None and existing_ca_certs is None:
            raise errors.InternalError(u"expected CA cert file '%s' to "
                                       u"exist, but it's absent" % (ca_file))

    if ca_certs is not None:
        try:
            ca_certs = [cert.der_data for cert in ca_certs]
            x509.write_certificate_list(ca_certs, ca_file)
        except Exception as e:
            if os.path.exists(ca_file):
                try:
                    os.unlink(ca_file)
                except OSError as e:
                    root_logger.error(
                        "Failed to remove '%s': %s", ca_file, e)
            raise errors.FileError(
                reason=u"cannot write certificate file '%s': %s" % (
                    ca_file, e)
            )

        os.rename(ca_file, CACERT)

    # Make sure the file permissions are correct
    try:
        os.chmod(CACERT, 0o644)
    except Exception as e:
        raise errors.FileError(reason=u"Unable set permissions on ca "
                               u"cert '%s': %s" % (CACERT, e))

# IMPORTANT: First line of FF config file is ignored
FIREFOX_CONFIG_TEMPLATE = """

/* Kerberos SSO configuration */
pref("network.negotiate-auth.trusted-uris", ".$DOMAIN");

/* These are the defaults */
pref("network.negotiate-auth.gsslib", "");
pref("network.negotiate-auth.using-native-gsslib", true);
pref("network.negotiate-auth.allow-proxies", true);
"""

FIREFOX_PREFERENCES_FILENAME = "all-ipa.js"
FIREFOX_PREFERENCES_REL_PATH = "browser/defaults/preferences"


def configure_firefox(options, statestore, domain):
    try:
        root_logger.debug("Setting up Firefox configuration.")

        preferences_dir = None

        # Check user specified location of firefox install directory
        if options.firefox_dir is not None:
            pref_path = os.path.join(options.firefox_dir,
                                     FIREFOX_PREFERENCES_REL_PATH)
            if dir_exists(pref_path):
                preferences_dir = pref_path
            else:
                root_logger.error("Directory '%s' does not exists.", pref_path)
        else:
            # test if firefox is installed
            if file_exists(paths.FIREFOX):

                # find valid preferences path
                for path in [paths.LIB_FIREFOX, paths.LIB64_FIREFOX]:
                    pref_path = os.path.join(path,
                                             FIREFOX_PREFERENCES_REL_PATH)
                    if dir_exists(pref_path):
                        preferences_dir = pref_path
                        break
            else:
                root_logger.error(
                    "Firefox configuration skipped (Firefox not found).")
                return

        # setting up firefox
        if preferences_dir is not None:

            # user could specify relative path, we need to store absolute
            preferences_dir = os.path.abspath(preferences_dir)
            root_logger.debug(
                "Firefox preferences directory found '%s'.", preferences_dir)
            preferences_fname = os.path.join(
                preferences_dir, FIREFOX_PREFERENCES_FILENAME)
            update_txt = ipautil.template_str(
                FIREFOX_CONFIG_TEMPLATE, dict(DOMAIN=domain))
            root_logger.debug(
                "Firefox trusted uris will be set as '.%s' domain.", domain)
            root_logger.debug(
                "Firefox configuration will be stored in '%s' file.",
                preferences_fname)

            try:
                with open(preferences_fname, 'w') as f:
                    f.write(update_txt)
                root_logger.info("Firefox sucessfully configured.")
                statestore.backup_state(
                    'firefox', 'preferences_fname', preferences_fname)
            except Exception as e:
                root_logger.debug(
                    "An error occured during creating preferences file: %s.",
                    e)
                root_logger.error("Firefox configuration failed.")
        else:
            root_logger.debug("Firefox preferences directory not found.")
            root_logger.error("Firefox configuration failed.")

    except Exception as e:
        root_logger.debug(str(e))
        root_logger.error("Firefox configuration failed.")


def install(options, env, fstore, statestore):
    dnsok = False

    cli_domain = None
    cli_server = None
    subject_base = None

    cli_domain_source = 'Unknown source'
    cli_server_source = 'Unknown source'

    if options.conf_ntp and not options.on_master and not options.force_ntpd:
        try:
            ntpconf.check_timedate_services()
        except ntpconf.NTPConflictingService as e:
            print("WARNING: ntpd time&date synchronization service will not"
                  " be configured as")
            print("conflicting service ({}) is enabled".format(
                e.conflicting_service))
            print("Use --force-ntpd option to disable it and force "
                  "configuration of ntpd")
            print("")

            # configuration of ntpd is disabled in this case
            options.conf_ntp = False
        except ntpconf.NTPConfigurationError:
            pass

    if options.unattended and (options.password is None and
                               options.principal is None and
                               options.keytab is None and
                               options.prompt_password is False and
                               not options.on_master):
        root_logger.error("One of password / principal / keytab is required.")
        return CLIENT_INSTALL_ERROR

    if options.hostname:
        hostname = options.hostname
        hostname_source = 'Provided as option'
    else:
        hostname = socket.getfqdn()
        hostname_source = "Machine's FQDN"
    if hostname != hostname.lower():
        root_logger.error(
            "Invalid hostname '%s', must be lower-case.", hostname)
        return CLIENT_INSTALL_ERROR
    if (hostname == 'localhost') or (hostname == 'localhost.localdomain'):
        root_logger.error("Invalid hostname, '%s' must not be used.", hostname)
        return CLIENT_INSTALL_ERROR

    # when installing with '--no-sssd' option, check whether nss-ldap is
    # installed
    if not options.sssd:
        if not os.path.exists(paths.PAM_KRB5_SO):
            root_logger.error("The pam_krb5 package must be installed")
            return CLIENT_INSTALL_ERROR

        (nssldap_installed, nosssd_files) = nssldap_exists()
        if not nssldap_installed:
            root_logger.error(
                "One of these packages must be installed: nss_ldap or "
                "nss-pam-ldapd")
            return CLIENT_INSTALL_ERROR

    if options.keytab and options.principal:
        root_logger.error(
            "Options 'principal' and 'keytab' cannot be used together.")
        return CLIENT_INSTALL_ERROR

    if options.keytab and options.force_join:
        root_logger.warning("Option 'force-join' has no additional effect "
                            "when used with together with option 'keytab'.")

    # Check if old certificate exist and show warning
    if (
        not options.ca_cert_file and
        get_cert_path(options.ca_cert_file) == CACERT
    ):
        root_logger.warning("Using existing certificate '%s'.", CACERT)

    if not check_ip_addresses(options):
        return CLIENT_INSTALL_ERROR

    # Create the discovery instance
    ds = ipadiscovery.IPADiscovery()

    ret = ds.search(
        domain=options.domain,
        servers=options.server,
        realm=options.realm_name,
        hostname=hostname,
        ca_cert_path=get_cert_path(options.ca_cert_file)
    )

    if options.server and ret != 0:
        # There is no point to continue with installation as server list was
        # passed as a fixed list of server and thus we cannot discover any
        # better result
        root_logger.error(
            "Failed to verify that %s is an IPA Server.",
            ', '.join(options.server))
        root_logger.error(
            "This may mean that the remote server is not up "
            "or is not reachable due to network or firewall settings.")
        print_port_conf_info()
        return CLIENT_INSTALL_ERROR

    if ret == ipadiscovery.BAD_HOST_CONFIG:
        root_logger.error("Can't get the fully qualified name of this host")
        root_logger.info("Check that the client is properly configured")
        return CLIENT_INSTALL_ERROR
    if ret == ipadiscovery.NOT_FQDN:
        root_logger.error("%s is not a fully-qualified hostname", hostname)
        return CLIENT_INSTALL_ERROR
    if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
            or not ds.domain:
        if ret == ipadiscovery.NO_LDAP_SERVER:
            if ds.server:
                root_logger.debug("%s is not an LDAP server" % ds.server)
            else:
                root_logger.debug("No LDAP server found")
        elif ret == ipadiscovery.NOT_IPA_SERVER:
            if ds.server:
                root_logger.debug("%s is not an IPA server" % ds.server)
            else:
                root_logger.debug("No IPA server found")
        else:
            root_logger.debug("Domain not found")
        if options.domain:
            cli_domain = options.domain
            cli_domain_source = 'Provided as option'
        elif options.unattended:
            root_logger.error(
                "Unable to discover domain, not provided on command line")
            return CLIENT_INSTALL_ERROR
        else:
            root_logger.info(
                "DNS discovery failed to determine your DNS domain")
            cli_domain = user_input(
                "Provide the domain name of your IPA server (ex: example.com)",
                allow_empty=False)
            cli_domain_source = 'Provided interactively'
            root_logger.debug(
                "will use interactively provided domain: %s", cli_domain)
        ret = ds.search(
            domain=cli_domain,
            servers=options.server,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file))

    if not cli_domain:
        if ds.domain:
            cli_domain = ds.domain
            cli_domain_source = ds.domain_source
            root_logger.debug("will use discovered domain: %s", cli_domain)

    client_domain = hostname[hostname.find(".")+1:]

    if ret in (ipadiscovery.NO_LDAP_SERVER, ipadiscovery.NOT_IPA_SERVER) \
            or not ds.server:
        root_logger.debug("IPA Server not found")
        if options.server:
            cli_server = options.server
            cli_server_source = 'Provided as option'
        elif options.unattended:
            root_logger.error("Unable to find IPA Server to join")
            return CLIENT_INSTALL_ERROR
        else:
            root_logger.debug("DNS discovery failed to find the IPA Server")
            cli_server = [
                user_input(
                    "Provide your IPA server name (ex: ipa.example.com)",
                    allow_empty=False)
            ]
            cli_server_source = 'Provided interactively'
            root_logger.debug(
                "will use interactively provided server: %s", cli_server[0])
        ret = ds.search(
            domain=cli_domain,
            servers=cli_server,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file))

    else:
        # Only set dnsok to True if we were not passed in one or more servers
        # and if DNS discovery actually worked.
        if not options.server:
            (server, domain) = ds.check_domain(
                ds.domain, set(), "Validating DNS Discovery")
            if server and domain:
                root_logger.debug("DNS validated, enabling discovery")
                dnsok = True
            else:
                root_logger.debug("DNS discovery failed, disabling discovery")
        else:
            root_logger.debug(
                "Using servers from command line, disabling DNS discovery")

    if not cli_server:
        if options.server:
            cli_server = ds.servers
            cli_server_source = 'Provided as option'
            root_logger.debug(
                "will use provided server: %s", ', '.join(options.server))
        elif ds.server:
            cli_server = ds.servers
            cli_server_source = ds.server_source
            root_logger.debug("will use discovered server: %s", cli_server[0])

    if ret == ipadiscovery.NOT_IPA_SERVER:
        root_logger.error("%s is not an IPA v2 Server.", cli_server[0])
        print_port_conf_info()
        root_logger.debug("(%s: %s)", cli_server[0], cli_server_source)
        return CLIENT_INSTALL_ERROR

    if ret == ipadiscovery.NO_ACCESS_TO_LDAP:
        root_logger.warning("Anonymous access to the LDAP server is disabled.")
        root_logger.info("Proceeding without strict verification.")
        root_logger.info(
            "Note: This is not an error if anonymous access "
            "has been explicitly restricted.")
        ret = 0

    if ret == ipadiscovery.NO_TLS_LDAP:
        root_logger.warning(
            "The LDAP server requires TLS is but we do not have the CA.")
        root_logger.info("Proceeding without strict verification.")
        ret = 0

    if ret != 0:
        root_logger.error(
            "Failed to verify that %s is an IPA Server.",
            cli_server[0])
        root_logger.error(
            "This may mean that the remote server is not up "
            "or is not reachable due to network or firewall settings.")
        print_port_conf_info()
        root_logger.debug("(%s: %s)", cli_server[0], cli_server_source)
        return CLIENT_INSTALL_ERROR

    cli_kdc = ds.kdc
    if dnsok and not cli_kdc:
        root_logger.error(
            "DNS domain '%s' is not configured for automatic "
            "KDC address lookup.", ds.realm.lower())
        root_logger.debug("(%s: %s)", ds.realm, ds.realm_source)
        root_logger.error("KDC address will be set to fixed value.")

    if dnsok:
        root_logger.info("Discovery was successful!")
    elif not options.unattended:
        if not options.server:
            root_logger.warning(
                "The failure to use DNS to find your IPA "
                "server indicates that your resolv.conf file is not properly "
                "configured.")
        root_logger.info(
            "Autodiscovery of servers for failover cannot work "
            "with this configuration.")
        root_logger.info(
            "If you proceed with the installation, services "
            "will be configured to always access the discovered server for "
            "all operations and will not fail over to other servers in case "
            "of failure.")
        if not user_input(
                "Proceed with fixed values and no DNS discovery?", False):
            return CLIENT_INSTALL_ERROR

    cli_realm = ds.realm
    cli_realm_source = ds.realm_source
    root_logger.debug("will use discovered realm: %s", cli_realm)

    if options.realm_name and options.realm_name != cli_realm:
        root_logger.error(
            "The provided realm name [%s] does not match discovered one [%s]",
            options.realm_name, cli_realm)
        root_logger.debug("(%s: %s)", cli_realm, cli_realm_source)
        return CLIENT_INSTALL_ERROR

    cli_basedn = ds.basedn
    cli_basedn_source = ds.basedn_source
    root_logger.debug("will use discovered basedn: %s", cli_basedn)
    subject_base = DN(('O', cli_realm))

    root_logger.info("Client hostname: %s", hostname)
    root_logger.debug("Hostname source: %s", hostname_source)
    root_logger.info("Realm: %s", cli_realm)
    root_logger.debug("Realm source: %s", cli_realm_source)
    root_logger.info("DNS Domain: %s", cli_domain)
    root_logger.debug("DNS Domain source: %s", cli_domain_source)
    root_logger.info("IPA Server: %s", ', '.join(cli_server))
    root_logger.debug("IPA Server source: %s", cli_server_source)
    root_logger.info("BaseDN: %s", cli_basedn)
    root_logger.debug("BaseDN source: %s", cli_basedn_source)

    # ipa-join would fail with IP address instead of a FQDN
    for srv in cli_server:
        try:
            socket.inet_pton(socket.AF_INET, srv)
            is_ipaddr = True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, srv)
                is_ipaddr = True
            except socket.error:
                is_ipaddr = False

        if is_ipaddr:
            print()
            root_logger.warning(
                "It seems that you are using an IP address "
                "instead of FQDN as an argument to --server. The "
                "installation may fail.")
            break

    print()
    if not options.unattended and not user_input(
            "Continue to configure the system with these values?", False):
        return CLIENT_INSTALL_ERROR

    if not options.on_master:
        # Try removing old principals from the keytab
        try:
            ipautil.run([
                paths.IPA_RMKEYTAB,
                '-k', paths.KRB5_KEYTAB, '-r', cli_realm
            ])
        except CalledProcessError as e:
            if e.returncode not in (3, 5):
                # 3 - Unable to open keytab
                # 5 - Principal name or realm not found in keytab
                root_logger.error(
                    "Error trying to clean keytab: "
                    "/usr/sbin/ipa-rmkeytab returned %s", e.returncode)
        else:
            root_logger.info(
                "Removed old keys for realm %s from %s",
                cli_realm, paths.KRB5_KEYTAB)

    if options.hostname and not options.on_master:
        # skip this step when run by ipa-server-install as it always configures
        # hostname
        tasks.backup_hostname(fstore, statestore)
        tasks.set_hostname(options.hostname)

    ntp_srv_servers = []
    if not options.on_master and options.conf_ntp:
        # Attempt to sync time with IPA server.
        # If we're skipping NTP configuration, we also skip the time sync here.
        # We assume that NTP servers are discoverable through SRV records
        # in the DNS.
        # If that fails, we try to sync directly with IPA server,
        # assuming it runs NTP
        root_logger.info('Synchronizing time with KDC...')
        ntp_srv_servers = ds.ipadns_search_srv(cli_domain, '_ntp._udp',
                                               None, break_on_first=False)
        synced_ntp = False
        ntp_servers = ntp_srv_servers

        # use user specified NTP servers if there are any
        if options.ntp_servers:
            ntp_servers = options.ntp_servers

        for s in ntp_servers:
            synced_ntp = ntpconf.synconce_ntp(s, options.debug)
            if synced_ntp:
                break

        if not synced_ntp and not options.ntp_servers:
            synced_ntp = ntpconf.synconce_ntp(cli_server[0], options.debug)
        if not synced_ntp:
            root_logger.warning(
                "Unable to sync time with NTP "
                "server, assuming the time is in sync. Please check "
                "that 123 UDP port is opened.")
    else:
        root_logger.info('Skipping synchronizing time with NTP server.')

    if not options.unattended:
        if (options.principal is None and options.password is None and
                options.prompt_password is False and options.keytab is None):
            options.principal = user_input("User authorized to enroll "
                                           "computers", allow_empty=False)
            root_logger.debug(
                "will use principal provided as option: %s", options.principal)

    host_principal = 'host/%s@%s' % (hostname, cli_realm)
    if not options.on_master:
        nolog = tuple()
        # First test out the kerberos configuration
        try:
            (krb_fd, krb_name) = tempfile.mkstemp()
            os.close(krb_fd)
            if configure_krb5_conf(
                    cli_realm=cli_realm,
                    cli_domain=cli_domain,
                    cli_server=cli_server,
                    cli_kdc=cli_kdc,
                    dnsok=False,
                    options=options,
                    filename=krb_name,
                    client_domain=client_domain,
                    client_hostname=hostname):
                root_logger.error("Test kerberos configuration failed")
                return CLIENT_INSTALL_ERROR
            env['KRB5_CONFIG'] = krb_name
            ccache_dir = tempfile.mkdtemp(prefix='krbcc')
            ccache_name = os.path.join(ccache_dir, 'ccache')
            join_args = [paths.SBIN_IPA_JOIN,
                         "-s", cli_server[0],
                         "-b", str(realm_to_suffix(cli_realm)),
                         "-h", hostname]
            if options.debug:
                join_args.append("-d")
                env['XMLRPC_TRACE_CURL'] = 'yes'
            if options.force_join:
                join_args.append("-f")
            if options.principal is not None:
                stdin = None
                principal = options.principal
                if principal.find('@') == -1:
                    principal = '%s@%s' % (principal, cli_realm)
                if options.password is not None:
                    stdin = options.password
                else:
                    if not options.unattended:
                        try:
                            stdin = getpass.getpass(
                                "Password for %s: " % principal)
                        except EOFError:
                            stdin = None
                        if not stdin:
                            root_logger.error(
                                "Password must be provided for %s.", principal)
                            return CLIENT_INSTALL_ERROR
                    else:
                        if sys.stdin.isatty():
                            root_logger.error(
                                "Password must be provided in "
                                "non-interactive mode.")
                            root_logger.info(
                                "This can be done via "
                                "echo password | ipa-client-install ... "
                                "or with the -w option.")
                            return CLIENT_INSTALL_ERROR
                        else:
                            stdin = sys.stdin.readline()

                try:
                    ipautil.kinit_password(principal, stdin, ccache_name,
                                           config=krb_name)
                except RuntimeError as e:
                    print_port_conf_info()
                    root_logger.error("Kerberos authentication failed: %s", e)
                    return CLIENT_INSTALL_ERROR
            elif options.keytab:
                join_args.append("-f")
                if os.path.exists(options.keytab):
                    try:
                        ipautil.kinit_keytab(host_principal, options.keytab,
                                             ccache_name,
                                             config=krb_name,
                                             attempts=options.kinit_attempts)
                    except gssapi.exceptions.GSSError as e:
                        print_port_conf_info()
                        root_logger.error("Kerberos authentication failed: %s"
                                          % e)
                        return CLIENT_INSTALL_ERROR
                else:
                    root_logger.error("Keytab file could not be found: %s"
                                      % options.keytab)
                    return CLIENT_INSTALL_ERROR
            elif options.password:
                nolog = (options.password,)
                join_args.append("-w")
                join_args.append(options.password)
            elif options.prompt_password:
                if options.unattended:
                    root_logger.error(
                        "Password must be provided in non-interactive mode")
                    return CLIENT_INSTALL_ERROR
                try:
                    password = getpass.getpass("Password: ")
                except EOFError:
                    password = None
                if not password:
                    root_logger.error("Password must be provided.")
                    return CLIENT_INSTALL_ERROR
                join_args.append("-w")
                join_args.append(password)
                nolog = (password,)

            env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = ccache_name
            # Get the CA certificate
            try:
                os.environ['KRB5_CONFIG'] = env['KRB5_CONFIG']
                get_ca_certs(fstore, options, cli_server[0], cli_basedn,
                             cli_realm)
                del os.environ['KRB5_CONFIG']
            except errors.FileError as e:
                root_logger.error(e)
                return CLIENT_INSTALL_ERROR
            except Exception as e:
                root_logger.error("Cannot obtain CA certificate\n%s", e)
                return CLIENT_INSTALL_ERROR

            # Now join the domain
            result = run(
                join_args, raiseonerr=False, env=env, nolog=nolog,
                capture_error=True)
            stderr = result.error_output

            if result.returncode != 0:
                root_logger.error("Joining realm failed: %s", stderr)
                if not options.force:
                    if result.returncode == 13:
                        root_logger.info(
                            "Use --force-join option to override the host "
                            "entry on the server and force client enrollment.")
                    return CLIENT_INSTALL_ERROR
                root_logger.info(
                    "Use ipa-getkeytab to obtain a host "
                    "principal for this server.")
            else:
                root_logger.info("Enrolled in IPA realm %s", cli_realm)

            start = stderr.find('Certificate subject base is: ')
            if start >= 0:
                start = start + 29
                subject_base = stderr[start:]
                subject_base = subject_base.strip()
                subject_base = DN(subject_base)

            if options.principal is not None:
                run(["kdestroy"], raiseonerr=False, env=env)

            # Obtain the TGT. We do it with the temporary krb5.conf, so that
            # only the KDC we're installing under is contacted.
            # Other KDCs might not have replicated the principal yet.
            # Once we have the TGT, it's usable on any server.
            try:
                ipautil.kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                                     CCACHE_FILE,
                                     config=krb_name,
                                     attempts=options.kinit_attempts)
                env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = CCACHE_FILE
            except gssapi.exceptions.GSSError as e:
                print_port_conf_info()
                root_logger.error("Failed to obtain host TGT: %s" % e)
                # failure to get ticket makes it impossible to login and bind
                # from sssd to LDAP, abort installation and rollback changes
                return CLIENT_INSTALL_ERROR

        finally:
            try:
                os.remove(krb_name)
            except OSError:
                root_logger.error("Could not remove %s", krb_name)
            try:
                os.rmdir(ccache_dir)
            except OSError:
                pass
            try:
                os.remove(krb_name + ".ipabkp")
            except OSError:
                root_logger.error("Could not remove %s.ipabkp", krb_name)

    # Configure ipa.conf
    if not options.on_master:
        configure_ipa_conf(fstore, cli_basedn, cli_realm, cli_domain,
                           cli_server, hostname)
        root_logger.info("Created /etc/ipa/default.conf")

    with certdb.NSSDatabase() as tmp_db:
        api.bootstrap(context='cli_installer',
                      debug=options.debug,
                      delegate=False,
                      nss_dir=tmp_db.secdir)
        if 'config_loaded' not in api.env:
            root_logger.error("Failed to initialize IPA API.")
            return CLIENT_INSTALL_ERROR

        # Always back up sssd.conf. It gets updated by authconfig --enablekrb5.
        fstore.backup_file(paths.SSSD_CONF)
        if options.sssd:
            if configure_sssd_conf(fstore, cli_realm, cli_domain, cli_server,
                                   options, client_domain, hostname):
                return CLIENT_INSTALL_ERROR
            root_logger.info("Configured /etc/sssd/sssd.conf")

        if options.on_master:
            # If on master assume kerberos is already configured properly.
            # Get the host TGT.
            try:
                ipautil.kinit_keytab(host_principal, paths.KRB5_KEYTAB,
                                     CCACHE_FILE,
                                     attempts=options.kinit_attempts)
                os.environ['KRB5CCNAME'] = CCACHE_FILE
            except gssapi.exceptions.GSSError as e:
                root_logger.error("Failed to obtain host TGT: %s" % e)
                return CLIENT_INSTALL_ERROR
        else:
            # Configure krb5.conf
            fstore.backup_file(paths.KRB5_CONF)
            if configure_krb5_conf(
                    cli_realm=cli_realm,
                    cli_domain=cli_domain,
                    cli_server=cli_server,
                    cli_kdc=cli_kdc,
                    dnsok=dnsok,
                    options=options,
                    filename=paths.KRB5_CONF,
                    client_domain=client_domain,
                    client_hostname=hostname):
                return CLIENT_INSTALL_ERROR

            root_logger.info(
                "Configured /etc/krb5.conf for IPA realm %s", cli_realm)

        # Clear out any current session keyring information
        try:
            delete_persistent_client_session_data(host_principal)
        except ValueError:
            pass

        # Add CA certs to a temporary NSS database
        ca_certs = x509.load_certificate_list_from_file(CACERT)
        ca_certs = [cert.der_data for cert in ca_certs]
        try:
            pwd_file = ipautil.write_tmp_file(ipautil.ipa_generate_password())
            tmp_db.create_db(pwd_file.name)

            for i, cert in enumerate(ca_certs):
                tmp_db.add_cert(cert, 'CA certificate %d' % (i + 1), 'C,,')
        except CalledProcessError as e:
            root_logger.info("Failed to add CA to temporary NSS database.")
            return CLIENT_INSTALL_ERROR

        api.finalize()

        # Now, let's try to connect to the server's RPC interface
        connected = False
        try:
            api.Backend.rpcclient.connect()
            connected = True
            root_logger.debug("Try RPC connection")
            api.Backend.rpcclient.forward('ping')
        except errors.KerberosError as e:
            if connected:
                api.Backend.rpcclient.disconnect()
            root_logger.info(
                "Cannot connect to the server due to Kerberos error: %s. "
                "Trying with delegate=True", e)
            try:
                api.Backend.rpcclient.connect(delegate=True)
                root_logger.debug("Try RPC connection")
                api.Backend.rpcclient.forward('ping')

                root_logger.info("Connection with delegate=True successful")

                # The remote server is not capable of Kerberos S4U2Proxy
                # delegation. This features is implemented in IPA server
                # version 2.2 and higher
                root_logger.warning(
                    "Target IPA server has a lower version than the enrolled "
                    "client")
                root_logger.warning(
                    "Some capabilities including the ipa command capability "
                    "may not be available")
            except errors.PublicError as e2:
                root_logger.warning(
                    "Second connect with delegate=True also failed: %s", e2)
                root_logger.error(
                    "Cannot connect to the IPA server RPC interface: %s", e2)
                return CLIENT_INSTALL_ERROR
        except errors.PublicError as e:
            root_logger.error(
                "Cannot connect to the server due to generic error: %s", e)
            return CLIENT_INSTALL_ERROR

    # Use the RPC directly so older servers are supported
    try:
        result = api.Backend.rpcclient.forward(
            'ca_is_enabled',
            version=u'2.107',
        )
        ca_enabled = result['result']
    except (errors.CommandError, errors.NetworkError):
        result = api.Backend.rpcclient.forward(
            'env',
            server=True,
            version=u'2.0',
        )
        ca_enabled = result['result']['enable_ra']
    if not ca_enabled:
        disable_ra()

    # Create IPA NSS database
    try:
        certdb.create_ipa_nssdb()
    except ipautil.CalledProcessError as e:
        root_logger.error("Failed to create IPA NSS database: %s", e)
        return CLIENT_INSTALL_ERROR

    # Get CA certificates from the certificate store
    try:
        ca_certs = get_certs_from_ldap(cli_server[0], cli_basedn, cli_realm,
                                       ca_enabled)
    except errors.NoCertificateError:
        if ca_enabled:
            ca_subject = DN(('CN', 'Certificate Authority'), subject_base)
        else:
            ca_subject = None
        ca_certs = certstore.make_compat_ca_certs(ca_certs, cli_realm,
                                                  ca_subject)
    ca_certs_trust = [(c, n, certstore.key_policy_to_trust_flags(t, True, u))
                      for (c, n, t, u) in ca_certs]

    # Add the CA certificates to the IPA NSS database
    root_logger.debug("Adding CA certificates to the IPA NSS database.")
    ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    for cert, nickname, trust_flags in ca_certs_trust:
        try:
            ipa_db.add_cert(cert, nickname, trust_flags)
        except CalledProcessError as e:
            root_logger.error(
                "Failed to add %s to the IPA NSS database.", nickname)
            return CLIENT_INSTALL_ERROR

    # Add the CA certificates to the platform-dependant systemwide CA store
    tasks.insert_ca_certs_into_systemwide_ca_store(ca_certs)

    if not options.on_master:
        client_dns(cli_server[0], hostname, options)
        configure_certmonger(fstore, subject_base, cli_realm, hostname,
                             options, ca_enabled)

    update_ssh_keys(hostname, services.knownservices.sshd.get_config_dir(),
                    options.create_sshfp)

    try:
        os.remove(CCACHE_FILE)
    except Exception:
        pass

    # Name Server Caching Daemon. Disable for SSSD, use otherwise
    # (if installed)
    nscd = services.knownservices.nscd
    if nscd.is_installed():
        save_state(nscd)

        try:
            if options.sssd:
                nscd_service_action = 'stop'
                nscd.stop()
            else:
                nscd_service_action = 'restart'
                nscd.restart()
        except Exception:
            root_logger.warning(
                "Failed to %s the %s daemon",
                nscd_service_action, nscd.service_name)
            if not options.sssd:
                root_logger.warning(
                    "Caching of users/groups will not be available")

        try:
            if options.sssd:
                nscd.disable()
            else:
                nscd.enable()
        except Exception:
            if not options.sssd:
                root_logger.warning(
                    "Failed to configure automatic startup of the %s daemon",
                    nscd.service_name)
                root_logger.info(
                    "Caching of users/groups will not be "
                    "available after reboot")
            else:
                root_logger.warning(
                    "Failed to disable %s daemon. Disable it manually.",
                    nscd.service_name)

    else:
        # this is optional service, just log
        if not options.sssd:
            root_logger.info(
                "%s daemon is not installed, skip configuration",
                nscd.service_name)

    nslcd = services.knownservices.nslcd
    if nslcd.is_installed():
        save_state(nslcd)

    retcode, conf = (0, None)

    if not options.no_ac:
        # Modify nsswitch/pam stack
        tasks.modify_nsswitch_pam_stack(sssd=options.sssd,
                                        mkhomedir=options.mkhomedir,
                                        statestore=statestore)

        root_logger.info("%s enabled", "SSSD" if options.sssd else "LDAP")

        if options.sssd:
            sssd = services.service('sssd')
            try:
                sssd.restart()
            except CalledProcessError:
                root_logger.warning("SSSD service restart was unsuccessful.")

            try:
                sssd.enable()
            except CalledProcessError as e:
                root_logger.warning(
                    "Failed to enable automatic startup of the SSSD daemon: "
                    "%s", e)

        if not options.sssd:
            tasks.modify_pam_to_use_krb5(statestore)
            root_logger.info("Kerberos 5 enabled")

        # Update non-SSSD LDAP configuration after authconfig calls as it would
        # change its configuration otherways
        if not options.sssd:
            for configurer in [configure_ldap_conf, configure_nslcd_conf]:
                (retcode, conf, filenames) = configurer(
                    fstore, cli_basedn, cli_realm,
                    cli_domain, cli_server, dnsok,
                    options, nosssd_files[configurer.__name__])
                if retcode:
                    return CLIENT_INSTALL_ERROR
                if conf:
                    root_logger.info(
                        "%s configured using configuration file(s) %s",
                        conf, filenames)

        if configure_openldap_conf(fstore, cli_basedn, cli_server):
            root_logger.info("Configured /etc/openldap/ldap.conf")
        else:
            root_logger.info("Failed to configure /etc/openldap/ldap.conf")

        # Check that nss is working properly
        if not options.on_master:
            n = 0
            found = False
            # Loop for up to 10 seconds to see if nss is working properly.
            # It can sometimes take a few seconds to connect to the remote
            # provider.
            # Particulary, SSSD might take longer than 6-8 seconds.
            while n < 10 and not found:
                try:
                    ipautil.run(["getent", "passwd", "admin@%s" % cli_domain])
                    found = True
                except Exception as e:
                    time.sleep(1)
                    n = n + 1

            if not found:
                root_logger.error(
                    "Unable to find 'admin' user with "
                    "'getent passwd admin@%s'!" % cli_domain)
                if conf:
                    root_logger.info("Recognized configuration: %s", conf)
                else:
                    root_logger.error(
                        "Unable to reliably detect "
                        "configuration. Check NSS setup manually.")

                try:
                    hardcode_ldap_server(cli_server)
                except Exception as e:
                    root_logger.error(
                        "Adding hardcoded server name to "
                        "/etc/ldap.conf failed: %s", str(e))

    if options.conf_ntp and not options.on_master:
        # disable other time&date services first
        if options.force_ntpd:
            ntpconf.force_ntpd(statestore)

        if options.ntp_servers:
            ntp_servers = options.ntp_servers
        elif ntp_srv_servers:
            ntp_servers = ntp_srv_servers
        else:
            root_logger.warning("No SRV records of NTP servers found. IPA "
                                "server address will be used")
            ntp_servers = cli_server

        ntpconf.config_ntp(ntp_servers, fstore, statestore)
        root_logger.info("NTP enabled")

    if options.conf_ssh:
        configure_ssh_config(fstore, options)

    if options.conf_sshd:
        configure_sshd_config(fstore, options)

    if options.location:
        configure_automount(options)

    if options.configure_firefox:
        configure_firefox(options, statestore, cli_domain)

    if not options.no_nisdomain:
        configure_nisdomain(options=options, domain=cli_domain)

    root_logger.info('Client configuration complete.')

    return 0


def uninstall(options, env):

    if not is_ipa_client_installed():
        root_logger.error("IPA client is not configured on this system.")
        return CLIENT_NOT_CONFIGURED

    server_fstore = sysrestore.FileStore(paths.SYSRESTORE)
    if server_fstore.has_files() and not options.on_master:
        root_logger.error(
            "IPA client is configured as a part of IPA server on this system.")
        root_logger.info("Refer to ipa-server-install for uninstallation.")
        return CLIENT_NOT_CONFIGURED

    try:
        run(["ipa-client-automount", "--uninstall", "--debug"])
    except Exception as e:
        root_logger.error(
            "Unconfigured automount client failed: %s", str(e))

    # Reload the state as automount unconfigure may have modified it
    fstore._load()
    statestore._load()

    hostname = None
    ipa_domain = None
    was_sssd_configured = False
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()
        all_domains = sssdconfig.list_domains()

        # we consider all the domains, because handling sssd.conf
        # during uninstall is dependant on was_sssd_configured flag
        # so the user does not lose info about inactive domains
        if len(all_domains) > 1:
            # There was more than IPA domain configured
            was_sssd_configured = True
        for name in domains:
            domain = sssdconfig.get_domain(name)
            try:
                provider = domain.get_option('id_provider')
            except SSSDConfig.NoOptionError:
                continue
            if provider == "ipa":
                try:
                    hostname = domain.get_option('ipa_hostname')
                except SSSDConfig.NoOptionError:
                    continue
                try:
                    ipa_domain = domain.get_option('ipa_domain')
                except SSSDConfig.NoOptionError:
                    pass
    except Exception as e:
        # We were unable to read existing SSSD config. This might mean few
        # things:
        # - sssd wasn't installed
        # - sssd was removed after install and before uninstall
        # - there are no active domains
        # in both cases we cannot continue with SSSD
        pass

    if hostname is None:
        hostname = socket.getfqdn()

    ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    sys_db = certdb.NSSDatabase(paths.NSS_DB_DIR)

    cmonger = services.knownservices.certmonger
    if ipa_db.has_nickname('Local IPA host'):
        try:
            certmonger.stop_tracking(paths.IPA_NSSDB_DIR,
                                     nickname='Local IPA host')
        except RuntimeError as e:
            root_logger.error("%s failed to stop tracking certificate: %s",
                              cmonger.service_name, e)

    client_nss_nickname = 'IPA Machine Certificate - %s' % hostname
    if sys_db.has_nickname(client_nss_nickname):
        try:
            certmonger.stop_tracking(paths.NSS_DB_DIR,
                                     nickname=client_nss_nickname)
        except RuntimeError as e:
            root_logger.error("%s failed to stop tracking certificate: %s",
                              cmonger.service_name, e)

    for filename in (os.path.join(ipa_db.secdir, 'cert8.db'),
                     os.path.join(ipa_db.secdir, 'key3.db'),
                     os.path.join(ipa_db.secdir, 'secmod.db'),
                     os.path.join(ipa_db.secdir, 'pwdfile.txt')):
        remove_file(filename)

    # Remove any special principal names we added to the IPA CA helper
    certmonger.remove_principal_from_cas()

    try:
        cmonger.stop()
    except Exception as e:
        log_service_error(cmonger.service_name, 'stop', e)

    try:
        cmonger.disable()
    except Exception as e:
        root_logger.error(
            "Failed to disable automatic startup of the %s service: %s",
            cmonger.service_name, str(e))

    if not options.on_master and os.path.exists(paths.IPA_DEFAULT_CONF):
        root_logger.info("Unenrolling client from IPA server")
        join_args = [paths.SBIN_IPA_JOIN, "--unenroll", "-h", hostname]
        if options.debug:
            join_args.append("-d")
            env['XMLRPC_TRACE_CURL'] = 'yes'
        result = run(join_args, raiseonerr=False, env=env)
        if result.returncode != 0:
            root_logger.error("Unenrolling host failed: %s", result.error_log)

    if os.path.exists(paths.IPA_DEFAULT_CONF):
        root_logger.info(
            "Removing Kerberos service principals from /etc/krb5.keytab")
        try:
            parser = RawConfigParser()
            fp = open(paths.IPA_DEFAULT_CONF, 'r')
            parser.readfp(fp)
            fp.close()
            realm = parser.get('global', 'realm')
            run([paths.IPA_RMKEYTAB, "-k", paths.KRB5_KEYTAB, "-r", realm])
        except CalledProcessError as err:
            if err.returncode != 5:
                # 5 means Principal name or realm not found in keytab
                # and can be ignored
                root_logger.error(
                    "Failed to remove Kerberos service principals: %s",
                    str(err))
        except Exception as e:
            root_logger.error(
                "Failed to remove Kerberos service principals: %s", str(e))

    root_logger.info("Disabling client Kerberos and LDAP configurations")
    was_sssd_installed = False
    was_sshd_configured = False
    if fstore.has_files():
        was_sssd_installed = fstore.has_file(paths.SSSD_CONF)

        sshd_config = os.path.join(
            services.knownservices.sshd.get_config_dir(), "sshd_config")
        was_sshd_configured = fstore.has_file(sshd_config)
    try:
        tasks.restore_pre_ipa_client_configuration(fstore,
                                                   statestore,
                                                   was_sssd_installed,
                                                   was_sssd_configured)
    except Exception as e:
        root_logger.error(
            "Failed to remove krb5/LDAP configuration: %s", str(e))
        return CLIENT_INSTALL_ERROR

    # Clean up the SSSD cache before SSSD service is stopped or restarted
    remove_file(paths.SSSD_MC_GROUP)
    remove_file(paths.SSSD_MC_PASSWD)

    if ipa_domain:
        sssd_domain_ldb = "cache_" + ipa_domain + ".ldb"
        sssd_ldb_file = os.path.join(paths.SSSD_DB, sssd_domain_ldb)
        remove_file(sssd_ldb_file)

        sssd_domain_ccache = "ccache_" + ipa_domain.upper()
        sssd_ccache_file = os.path.join(paths.SSSD_DB, sssd_domain_ccache)
        remove_file(sssd_ccache_file)

    # Next if-elif-elif construction deals with sssd.conf file.
    # Old pre-IPA domains are preserved due merging the old sssd.conf
    # during the installation of ipa-client but any new domains are
    # only present in sssd.conf now, so we don't want to delete them
    # by rewriting sssd.conf file. IPA domain is removed gracefully.

    # SSSD was installed before our installation and other non-IPA domains
    # found, restore backed up sssd.conf to sssd.conf.bkp and remove IPA
    # domain from the current sssd.conf
    if was_sssd_installed and was_sssd_configured:
        root_logger.info(
            "The original configuration of SSSD included other domains than "
            "the IPA-based one.")

        delete_ipa_domain()

        restored = False
        try:
            restored = fstore.restore_file(
                paths.SSSD_CONF, paths.SSSD_CONF_BKP)
        except OSError:
            root_logger.debug(
                "Error while restoring pre-IPA /etc/sssd/sssd.conf.")

        if restored:
            root_logger.info(
                "Original pre-IPA SSSD configuration file was "
                "restored to /etc/sssd/sssd.conf.bkp.")

        root_logger.info(
            "IPA domain removed from current one, restarting SSSD service")
        sssd = services.service('sssd')
        try:
            sssd.restart()
        except CalledProcessError:
            root_logger.warning("SSSD service restart was unsuccessful.")

    # SSSD was not installed before our installation, but other domains found,
    # delete IPA domain, but leave other domains intact
    elif not was_sssd_installed and was_sssd_configured:
        delete_ipa_domain()
        root_logger.info(
            "Other domains than IPA domain found, IPA domain was removed "
            "from /etc/sssd/sssd.conf.")

        sssd = services.service('sssd')
        try:
            sssd.restart()
        except CalledProcessError:
            root_logger.warning("SSSD service restart was unsuccessful.")

    # SSSD was not installed before our installation, and no other domains
    # than IPA are configured in sssd.conf - make sure config file is removed
    elif not was_sssd_installed and not was_sssd_configured:
        try:
            os.rename(paths.SSSD_CONF, paths.SSSD_CONF_DELETED)
        except OSError:
            root_logger.debug("Error while moving /etc/sssd/sssd.conf to %s" %
                              paths.SSSD_CONF_DELETED)

        root_logger.info(
            "Redundant SSSD configuration file "
            "/etc/sssd/sssd.conf was moved to /etc/sssd/sssd.conf.deleted")

        sssd = services.service('sssd')
        try:
            sssd.stop()
        except CalledProcessError:
            root_logger.warning("SSSD service could not be stopped")

        try:
            sssd.disable()
        except CalledProcessError as e:
            root_logger.warning(
                "Failed to disable automatic startup of the SSSD daemon: %s",
                e)

    tasks.restore_hostname(fstore, statestore)

    if fstore.has_files():
        root_logger.info("Restoring client configuration files")
        fstore.restore_all_files()

    unconfigure_nisdomain()

    nscd = services.knownservices.nscd
    nslcd = services.knownservices.nslcd

    for service in (nscd, nslcd):
        if service.is_installed():
            restore_state(service)
        else:
            # this is an optional service, just log
            root_logger.info(
                "%s daemon is not installed, skip configuration",
                service.service_name
            )

    ntp_configured = statestore.has_state('ntp')
    if ntp_configured:
        ntp_enabled = statestore.restore_state('ntp', 'enabled')
        ntp_step_tickers = statestore.restore_state('ntp', 'step-tickers')
        restored = False

        try:
            # Restore might fail due to file missing in backup
            # the reason for it might be that freeipa-client was updated
            # to this version but not unenrolled/enrolled again
            # In such case it is OK to fail
            restored = fstore.restore_file(paths.NTP_CONF)
            restored |= fstore.restore_file(paths.SYSCONFIG_NTPD)
            if ntp_step_tickers:
                restored |= fstore.restore_file(paths.NTP_STEP_TICKERS)
        except Exception:
            pass

        if not ntp_enabled:
            services.knownservices.ntpd.stop()
            services.knownservices.ntpd.disable()
        else:
            if restored:
                services.knownservices.ntpd.restart()

    try:
        ntpconf.restore_forced_ntpd(statestore)
    except CalledProcessError as e:
        root_logger.error('Failed to start chronyd: %s', e)

    if was_sshd_configured and services.knownservices.sshd.is_running():
        services.knownservices.sshd.restart()

    # Remove the Firefox configuration
    if statestore.has_state('firefox'):
        root_logger.info("Removing Firefox configuration.")
        preferences_fname = statestore.restore_state(
            'firefox', 'preferences_fname')
        if preferences_fname is not None:
            if file_exists(preferences_fname):
                try:
                    os.remove(preferences_fname)
                except Exception as e:
                    root_logger.warning(
                        "'%s' could not be removed: %s.",
                        preferences_fname, str(e))
                    root_logger.warning(
                        "Please remove file '%s' manually.", preferences_fname)

    rv = 0

    if fstore.has_files():
        root_logger.error('Some files have not been restored, see %s' %
                          paths.SYSRESTORE_INDEX)
    has_state = False
    for module in statestore.modules:
            root_logger.error(
                'Some installation state for %s has not been '
                'restored, see /var/lib/ipa/sysrestore/sysrestore.state',
                module)
            has_state = True
            rv = 1

    if has_state:
        root_logger.warning(
            'Some installation state has not been restored.\n'
            'This may cause re-installation to fail.\n'
            'It should be safe to remove /var/lib/ipa-client/sysrestore.state '
            'but it may\n mean your system hasn\'t been restored '
            'to its pre-installation state.')

    # Remove the IPA configuration file
    remove_file(paths.IPA_DEFAULT_CONF)

    # Remove the CA cert from the systemwide certificate store
    tasks.remove_ca_certs_from_systemwide_ca_store()

    # Remove the CA cert
    remove_file(CACERT)

    root_logger.info("Client uninstall complete.")

    # The next block of code prompts for reboot, therefore all uninstall
    # logic has to be done before

    if not options.unattended:
        root_logger.info(
            "The original nsswitch.conf configuration has been restored.")
        root_logger.info(
            "You may need to restart services or reboot the machine.")
        if not options.on_master:
            if user_input("Do you want to reboot the machine?", False):
                try:
                    run([paths.SBIN_REBOOT])
                except Exception as e:
                    root_logger.error(
                        "Reboot command failed to exceute: %s", str(e))
                    return CLIENT_UNINSTALL_ERROR

    # IMPORTANT: Do not put any client uninstall logic after the block above

    return rv
