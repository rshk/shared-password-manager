import logging
import os

from cliff.command import Command

from password_manager import PasswordManager


class PMCommand(Command):
    def get_parser(self, prog_name):
        parser = super(PMCommand, self).get_parser(prog_name)
        parser.add_argument('--pm-home')
        return parser

    def _get_password_manager(self, parsed_args):
        pm_home = None
        if parsed_args.pm_home:
            pm_home = parsed_args.pm_home
        elif 'PM_HOME' in os.environ:
            pm_home = os.environ['PM_HOME']
        else:
            pm_home = os.getcwd()
        return PasswordManager(pm_home)


class Setup(PMCommand):
    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(Setup, self).get_parser(prog_name)
        parser.add_argument('identity', nargs='+')
        return parser

    def take_action(self, parsed_args):
        pm = self._get_password_manager(parsed_args)
        self.logger.info('Initializing password manager directory in {0}'
                         .format(pm.basedir))
        identities = parsed_args.identity
        self.logger.info('Initial identities: {0}'
                         .format(', '.join(identities)))
        pm.setup(identities)


class UserAdd(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class UserRemove(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class UserList(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class KeyRegen(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class KeyRecrypt(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class SecretPut(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class SecretGet(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass


class SecretDelete(PMCommand):
    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        pass
