# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import icalendar
from datetime import date
from ipalib import api, errors
from ipalib import Str, StrEnum, Bool, File, DeprecatedParam
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import (
    pkey_to_value,
    external_host_param,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPRetrieve,
    LDAPUpdate,
    LDAPSearch,
    LDAPQuery,
    LDAPAddMember,
    LDAPRemoveMember,
    LDAPAddAttribute,
    LDAPRemoveAttribute)
from ipalib import _, ngettext
from ipalib import output
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger


__doc__ = _("""
Host-based access control

Control who can access what services on what hosts. You
can use HBAC to control which users or groups can
access a service, or group of services, on a target host.

You can also specify a category of users and target hosts.
This is currently limited to "all", but might be expanded in the
future.

Target hosts in HBAC rules must be hosts managed by IPA.

The available services and groups of services are controlled by the
hbacsvc and hbacsvcgroup plug-ins respectively.

EXAMPLES:

 Create a rule, "test1", that grants all users access to the host "server" from
 anywhere:
   ipa hbacrule-add --usercat=all test1
   ipa hbacrule-add-host --hosts=server.example.com test1

 Display the properties of a named HBAC rule:
   ipa hbacrule-show test1

 Create a rule for a specific service. This lets the user john access
 the sshd service on any machine from any machine:
   ipa hbacrule-add --hostcat=all john_sshd
   ipa hbacrule-add-user --users=john john_sshd
   ipa hbacrule-add-service --hbacsvcs=sshd john_sshd

 Create a rule for a new service group. This lets the user john access
 the FTP service on any machine from any machine:
   ipa hbacsvcgroup-add ftpers
   ipa hbacsvc-add sftp
   ipa hbacsvcgroup-add-member --hbacsvcs=ftp --hbacsvcs=sftp ftpers
   ipa hbacrule-add --hostcat=all john_ftp
   ipa hbacrule-add-user --users=john john_ftp
   ipa hbacrule-add-service --hbacsvcgroups=ftpers john_ftp

 Disable a named HBAC rule:
   ipa hbacrule-disable test1

 Remove a named HBAC rule:
   ipa hbacrule-del allow_server
""")

register = Registry()

# AccessTime support is being removed for now.
#
# You can also control the times that the rule is active.
#
# The access time(s) of a host are cumulative and are not guaranteed to be
# applied in the order displayed.
#
# Specify that the rule "test1" be active every day between 0800 and 1400:
#   ipa hbacrule-add-accesstime --time='periodic daily 0800-1400' test1
#
# Specify that the rule "test1" be active once, from 10:32 until 10:33 on
# December 16, 2010:
#   ipa hbacrule-add-accesstime --time='absolute 201012161032 ~ 201012161033' test1


def validate_ical_component(comp, name):
    if comp.errors:
        ical_errors = ('{prop}: {err}'
                       .format(prop=prop, err=e) for prop, e in comp.errors)
        raise errors.ValidationError(
            name=name,
            error=_('There were errors parsing the iCalendar string:\n%(errs)s'
                    ) % {'errs': '\n'.join(ical_errors)}
            )

    for prop in comp.required:
        if prop not in comp.keys():
            raise errors.ValidationError(
                name=name,
                error=_('A required property "%(prop)s" not found '
                        'in "%(comp)s".') % {'prop': prop, 'comp': comp.name}
                )

    for prop in comp.keys():
        # TODO: comp.required might be removed when
        # https://github.com/collective/icalendar/pull/183 is merged
        if prop not in (comp.singletons + comp.multiple + comp.required):
            raise errors.ValidationError(
                name=name,
                error=_('A "%(comp)s" component can\'t contain '
                        'property "%(prop)s".'
                        ) % {'comp': comp.name, 'prop': prop}
                )

        if (prop in comp.singletons and isinstance(comp[prop], list)
                and len(comp[prop]) > 1):
            raise errors.ValidationError(
                name=name,
                error=_('A "%(comp)s" component can\'t have more than '
                        'one "%(prop)s" property."'
                        ) % {'comp': comp.name, 'prop': prop}
                )


def validate_icalfile(ugettext, ics):
    name = 'accesstime'

    try:
        vcal = icalendar.cal.Calendar().from_ical(ics)
    except ValueError as e:
        raise errors.ValidationError(
            name=name,
            error=_('Couln\'t parse iCalendar string: %s'
                    ) % (e, )
            )

    if(vcal.name != 'VCALENDAR'):  # pylint: disable=no-member
        raise errors.ValidationError(
            name=name,
            error=_('Received object is not a VCALENDAR')
            )

    validate_ical_component(vcal, name)

    # get a list of all components of a VCALENDAR
    for comp in vcal.subcomponents:  # pylint: disable=no-member
        if comp.name != 'VEVENT':
            root_logger.info(
                'Found "{comp}" but only VEVENT component is supported.'
                .format(comp=comp.name))
            continue

        validate_ical_component(comp, name)
        for sub in comp.subcomponents:
            if sub.name != 'VALARM':
                raise errors.ValidationError(
                    name=name,
                    error=_('A VEVENT component can\'t contain '
                            'subcomponent "%s".') % (sub.name, )
                    )
            else:
                root_logger.info(
                    'Found "{comp}" but only VEVENT component is '
                    'supported.'
                    .format(comp=sub.name))

        # we WILL require DTSTART for VEVENTs
        if 'DTSTART' not in comp.keys():
            raise errors.ValidationError(
                name=name,
                error=_('DTSTART property is required in VEVENT.')
                )

        if 'DTEND' in comp.keys():
            if 'DURATION' in comp.keys():
                raise errors.ValidationError(
                    name=name,
                    error=_('Both DURATION and DTEND set in a VEVENT.')
                )

            if type(comp['DTSTART'].dt) != type(comp['DTEND'].dt):
                raise errors.ValidationError(
                    name=name,
                    error=_('Different types of DTSTART and DTEND '
                            'component in VEVENT.')
                    )

        elif 'DURATION' in comp.keys() and isinstance(comp['DTSTART'].dt, date):
            """
            python-icalendar represents DURATION as datetime.timedelta. This,
            in some cases, blocks us from checking whether it was originally
            set correctly.

            Example: If DTSTART has value of type DATE, DURATION should be set
            only as dur-day or dur-week. However, DURATION:PT24H will evaluate
            as timedelta(1)
            """
            if comp['DURATION'].dt.seconds:
                raise errors.ValidationError(
                    name=name,
                    error=_('DURATION is not of type dur-day or dur-week '
                            'when DTSTART value type is DATE.')
                    )


topic = ('hbac', _('Host-based access control commands'))

def validate_type(ugettext, type):
    if type.lower() == 'deny':
        raise errors.ValidationError(name='type', error=_('The deny type has been deprecated.'))

def is_all(options, attribute):
    """
    See if options[attribute] is lower-case 'all' in a safe way.
    """
    if attribute in options and options[attribute] is not None:
        if type(options[attribute]) in (list, tuple):
            value = options[attribute][0].lower()
        else:
            value = options[attribute].lower()
        if value == 'all':
            return True
    else:
        return False


@register()
class hbacrule(LDAPObject):
    """
    HBAC object.
    """
    container_dn = api.env.container_hbac
    object_name = _('HBAC rule')
    object_name_plural = _('HBAC rules')
    object_class = ['ipaassociation', 'ipahbacrule']
    permission_filter_objectclasses = ['ipahbacrule']
    default_attributes = [
        'cn', 'ipaenabledflag',
        'description', 'usercategory', 'hostcategory',
        'servicecategory', 'ipaenabledflag',
        'memberuser', 'sourcehost', 'memberhost', 'memberservice',
        'externalhost',
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'sourcehost': ['host', 'hostgroup'],
        'memberservice': ['hbacsvc', 'hbacsvcgroup'],
    }
    managed_permissions = {
        'System: Read HBAC Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'accessruletype', 'accesstime', 'cn', 'description',
                'externalhost', 'hostcategory', 'ipaenabledflag',
                'ipauniqueid', 'memberhost', 'memberservice', 'memberuser',
                'servicecategory', 'sourcehost', 'sourcehostcategory',
                'usercategory', 'objectclass', 'member',
            },
        },
        'System: Add HBAC Rule': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Add HBAC rule";allow (add) groupdn = "ldap:///cn=Add HBAC rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Delete HBAC Rule': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Delete HBAC rule";allow (delete) groupdn = "ldap:///cn=Delete HBAC rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Manage HBAC Rule Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'externalhost', 'memberhost', 'memberservice', 'memberuser'
            },
            'replaces': [
                '(targetattr = "memberuser || externalhost || memberservice || memberhost")(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Manage HBAC rule membership";allow (write) groupdn = "ldap:///cn=Manage HBAC rule membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Modify HBAC Rule': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'accessruletype', 'accesstime', 'cn', 'description',
                'hostcategory', 'ipaenabledflag', 'servicecategory',
                'sourcehost', 'sourcehostcategory', 'usercategory'
            },
            'replaces': [
                '(targetattr = "servicecategory || sourcehostcategory || cn || description || ipaenabledflag || accesstime || usercategory || hostcategory || accessruletype || sourcehost")(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Modify HBAC rule";allow (write) groupdn = "ldap:///cn=Modify HBAC rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
    }

    label = _('HBAC Rules')
    label_singular = _('HBAC Rule')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Rule name'),
            primary_key=True,
        ),
        StrEnum('accessruletype', validate_type,
            cli_name='type',
            doc=_('Rule type (allow)'),
            label=_('Rule type'),
            values=(u'allow', u'deny'),
            default=u'allow',
            autofill=True,
            exclude='webui',
            flags=['no_option', 'no_output'],
        ),
        # FIXME: {user,host,service}categories should expand in the future
        StrEnum('usercategory?',
            cli_name='usercat',
            label=_('User category'),
            doc=_('User category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('hostcategory?',
            cli_name='hostcat',
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
            values=(u'all', ),
        ),
        DeprecatedParam('sourcehostcategory?'),
        StrEnum('servicecategory?',
            cli_name='servicecat',
            label=_('Service category'),
            doc=_('Service category the rule applies to'),
            values=(u'all', ),
        ),
        File('accesstime*', validate_icalfile,
             cli_name='time',
             label=_('Access time'),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
        Bool('ipaenabledflag?',
             label=_('Enabled'),
             flags=['no_option'],
        ),
        Str('memberuser_user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberuser_group?',
            label=_('User Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        DeprecatedParam('sourcehost_host?'),
        DeprecatedParam('sourcehost_hostgroup?'),
        Str('memberservice_hbacsvc?',
            label=_('Services'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberservice_hbacsvcgroup?',
            label=_('Service Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        external_host_param,
    )



@register()
class hbacrule_add(LDAPCreate):
    __doc__ = _('Create a new HBAC rule.')

    msg_summary = _('Added HBAC rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # HBAC rules are enabled by default
        entry_attrs['ipaenabledflag'] = 'TRUE'
        return dn



@register()
class hbacrule_del(LDAPDelete):
    __doc__ = _('Delete an HBAC rule.')

    msg_summary = _('Deleted HBAC rule "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        kw = dict(seealso=keys[0])
        _entries = api.Command.selinuxusermap_find(None, **kw)
        if _entries['count']:
            raise errors.DependentEntry(key=keys[0], label=self.api.Object['selinuxusermap'].label_singular, dependent=_entries['result'][0]['cn'][0])

        return dn



@register()
class hbacrule_mod(LDAPUpdate):
    __doc__ = _('Modify an HBAC rule.')

    msg_summary = _('Modified HBAC rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, attrs_list)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if is_all(options, 'usercategory') and 'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("user category cannot be set to 'all' while there are allowed users"))
        if is_all(options, 'hostcategory') and 'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("host category cannot be set to 'all' while there are allowed hosts"))
        if is_all(options, 'servicecategory') and 'memberservice' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("service category cannot be set to 'all' while there are allowed services"))
        return dn



@register()
class hbacrule_find(LDAPSearch):
    __doc__ = _('Search for HBAC rules.')

    msg_summary = ngettext(
        '%(count)d HBAC rule matched', '%(count)d HBAC rules matched', 0
    )



@register()
class hbacrule_show(LDAPRetrieve):
    __doc__ = _('Display the properties of an HBAC rule.')



@register()
class hbacrule_enable(LDAPQuery):
    __doc__ = _('Enable an HBAC rule.')

    msg_summary = _('Enabled HBAC rule "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['TRUE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )



@register()
class hbacrule_disable(LDAPQuery):
    __doc__ = _('Disable an HBAC rule.')

    msg_summary = _('Disabled HBAC rule "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )


@register()
class hbacrule_add_accesstime(LDAPAddAttribute):
    __doc__ = _('Add an access time to an HBAC rule.')
    msg_summary = _('Added allowed access times to the rule "%(value)s"')
    attribute = 'accesstime'


@register()
class hbacrule_remove_accesstime(LDAPRemoveAttribute):
    __doc__ = _('Remove access times from an HBAC Rule')
    msg_summary = _('Removed access times from the rule "%(value)s"')
    attribute = 'accesstime'


@register()
class hbacrule_add_user(LDAPAddMember):
    __doc__ = _('Add users and groups to an HBAC rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if 'usercategory' in entry_attrs and \
            entry_attrs['usercategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when user category='all'"))
        return dn



@register()
class hbacrule_remove_user(LDAPRemoveMember):
    __doc__ = _('Remove users and groups from an HBAC rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')



@register()
class hbacrule_add_host(LDAPAddMember):
    __doc__ = _('Add target hosts and hostgroups to an HBAC rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if 'hostcategory' in entry_attrs and \
            entry_attrs['hostcategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(
                reason=_("hosts cannot be added when host category='all'"))
        return dn



@register()
class hbacrule_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove target hosts and hostgroups from an HBAC rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')



@register()
class hbacrule_add_sourcehost(LDAPAddMember):
    NO_CLI = True

    member_attributes = ['sourcehost']
    member_count_out = ('%i object added.', '%i objects added.')

    def validate(self, **kw):
        raise errors.DeprecationError(name='hbacrule_add_sourcehost')



@register()
class hbacrule_remove_sourcehost(LDAPRemoveMember):
    NO_CLI = True

    member_attributes = ['sourcehost']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def validate(self, **kw):
        raise errors.DeprecationError(name='hbacrule_remove_sourcehost')



@register()
class hbacrule_add_service(LDAPAddMember):
    __doc__ = _('Add services to an HBAC rule.')

    member_attributes = ['memberservice']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if 'servicecategory' in entry_attrs and \
            entry_attrs['servicecategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(reason=_(
                "services cannot be added when service category='all'"))
        return dn



@register()
class hbacrule_remove_service(LDAPRemoveMember):
    __doc__ = _('Remove service and service groups from an HBAC rule.')

    member_attributes = ['memberservice']
    member_count_out = ('%i object removed.', '%i objects removed.')

