#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import six
import icalendar
from datetime import datetime

from ipaclient.frontend import MethodOverride
from ipalib import Str, File
from ipalib import errors
from ipalib.plugable import Registry
from ipalib import _

if six.PY3:
    unicode = str

register = Registry()


icalopts_docformat = _("The %(prop)s property of an iCalendar string")


ical_options = (
    Str('start?',
        label='DTSTART',
        doc=icalopts_docformat % {'prop': 'DTSTART'},
        ),
    Str('end?',
        label='DTEND',
        doc=icalopts_docformat % {'prop': 'DTEND'},
        ),
    Str('duration?',
        label='DURATION',
        doc=icalopts_docformat % {'prop': 'DURATION'},
        ),
    Str('dates?',
        label='RDATE',
        doc=icalopts_docformat % {'prop': 'RDATE'},
        ),
    Str('rrule?',
        label='RRULE',
        doc=icalopts_docformat % {'prop': 'RRULE'},
        ),
    Str('timezone?',
        label="Time Zone",
        doc="The time zone for the time rule, defaults to host-local time",
        )
)


def opts_to_icalstring(opts, name, domain):
    """
    We'll construct an iCalendar string here. There's no need to checking
    whether the options make for a valid combination to create such a string
    as the string is checked on the server side anyway
    """
    # pylint: disable=no-member
    timezone = opts.get('timezone', None)

    cal = icalendar.Calendar()
    cal['PRODID'] = '-//Red Hat, Inc.//FreeIPA iCalendar Creation//EN'
    cal['VERSION'] = '2.0'  # corresponds to RFC 5545
    event = icalendar.Event()
    event['UID'] = '{name}@{domain}'.format(name=name, domain=domain)
    event['DTSTAMP'] = datetime.strftime(datetime.now(), '%Y%m%dT%H%M%S')

    if not opts.get('start', False):
        raise errors.RequirementError(name='start')
    try:
        current_option = 'start'
        event['DTSTART'] = icalendar.vDDDTypes(
                icalendar.vDDDTypes.from_ical(opts['start'],
                                              timezone=timezone))

        if opts.get('end', False):
            current_option = 'end'
            event['DTEND'] = icalendar.vDDDTypes(
                icalendar.vDDDTypes.from_ical(opts['end'],
                                              timezone=timezone))

        if opts.get('duration', False):
            current_option = 'durattion'
            event['DURATION'] = icalendar.vDuration(
                icalendar.vDuration.from_ical(opts['duration']))

        if opts.get('dates', False):
            current_option = 'dates'
            event['RDATE'] = icalendar.vDDDLists(
                icalendar.vDDDLists.from_ical(opts['dates'],
                                              timezone=timezone))
            if event['RDATE']:
                value_type = event['RDATE'][0].params.get('VALUE', None)
                if value_type:
                    event['RDATE'].params['VALUE'] = value_type

        if opts.get('rrule', False):
            current_option = 'rrule'
            event['RRULE'] = icalendar.vRecur(
                icalendar.vRecur.from_ical(opts['rrule']))
    except ValueError as e:
        raise errors.ValidationError(name=current_option,
                                     err=str(e))

    cal.add_component(event)
    return unicode(cal.to_ical().encode('unicode-escape'))


def set_accesstime(options, rulename, domain):
    ical_opt_names = ('start', 'end', 'duration', 'dates', 'rrule', 'timezone')
    ical_opts_present = bool([opt for opt in ical_opt_names if opt in options])
    obtainable_ways = len([way for way in (ical_opts_present,
                                           'icalfile' in options,
                                           'accesstime' in options)
                           if way])
    if obtainable_ways == 0:
        raise errors.RequirementError(name='accesstime')
    if obtainable_ways > 1:
        raise errors.ValidationError(
            name='accesstime',
            err=_('Multiple ways of creating iCalendar string detected. '
                  'Please, choose only one (directly from string, from a file,'
                  ' or from options)'))
    if 'icalfile' in options:
        options['accesstime'] = unicode(
            options['icalfile'].encode('unicode-escape'))
        del(options['icalfile'])
    elif 'accesstime' not in options:
        options['accesstime'] = opts_to_icalstring(options, rulename, domain)
        # clean all the options not to confuse server
        for opt in ical_opt_names:
            if opt in options:
                del(options[opt])
    return options


@register(override=True, no_fail=True)
class timerule_add(MethodOverride):
    takes_options = (
        File('icalfile?',
             label=_("iCalendar file"),
             doc=_("File containing the iCalendar string"),
             ),
    ) + ical_options

    def forward(self, *args, **options):
        set_accesstime(options, args[0], self.api.env.domain)
        return super(timerule_add, self).forward(*args, **options)


@register(override=True, no_fail=True)
class timerule_mod(MethodOverride):
    takes_options = (
        File('icalfile?',
             label=_("iCalendar file"),
             doc=_("File containing the iCalendar string"),
             ),
    ) + ical_options

    def forward(self, *args, **options):
        try:
            set_accesstime(options, args[0], self.api.env.domain)
        except errors.RequirementError:
            pass
        return super(timerule_mod, self).forward(*args, **options)
