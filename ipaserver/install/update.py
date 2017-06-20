#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from ipalib import plugable
import ipaserver.install.plugins


class Updater(plugable.Plugable):
    """
    An LDAP update with an associated object (always update).

    All plugins that subclass from `Updater` will be automatically available
    as a server update function.

    Plugins that subclass from Updater are registered in the ``api.Updater``
    namespace. For example:

    >>> api = UpdateAPI()
    >>> class my(Object):
    ...     pass
    ...
    >>> api.add_plugin(my)
    >>> class my_update(Updater):
    ...     pass
    ...
    >>> api.add_plugin(my_update)
    >>> api.finalize()
    >>> list(api.Updater)
    [<class '__main__.my_update'>]
    >>> api.Updater.my_update # doctest:+ELLIPSIS
    ipaserver.install.ldapupdate.my_update()
    """
    def execute(self, **options):
        raise NotImplementedError('%s.execute()' % self.name)

    def __call__(self, **options):
        self.debug(
            'raw: %s', self.name
        )

        return self.execute(**options)


class UpdateAPI(plugable.API):
    bases = (Updater,)
    packages = (ipaserver.install.plugins,)

    def __init__(self, ipalib_api):
        self.__ipalib_api = ipalib_api

        super(UpdateAPI, self).__init__()

    def bootstrap(self, **overrides):
        self.__ipalib_api.bootstrap(**overrides)

        super(UpdateAPI, self).bootstrap(**overrides)

    def finalize(self):
        ipalib_api = self.__ipalib_api
        ipalib_api.finalize()
        for base in ipalib_api.bases:
            name = base.__name__
            setattr(self, name, getattr(ipalib_api, name))

        super(UpdateAPI, self).finalize()
