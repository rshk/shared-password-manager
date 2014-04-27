import logging
import os

from cliff.command import Command
from cliff.lister import Lister

from password_manager import PasswordManager


class PMCommandMixin(object):
    def _get_password_manager(self, parsed_args):
        pm_home = None
        if parsed_args.pm_home:
            pm_home = parsed_args.pm_home
        elif 'PM_HOME' in os.environ:
            pm_home = os.environ['PM_HOME']
        else:
            pm_home = os.getcwd()
        return PasswordManager(pm_home)


class PMCommand(PMCommandMixin, Command):
    def get_parser(self, prog_name):
        parser = super(PMCommand, self).get_parser(prog_name)
        parser.add_argument('--pm-home')
        return parser


class PMLister(PMCommandMixin, Lister):
    def get_parser(self, prog_name):
        parser = super(PMLister, self).get_parser(prog_name)
        parser.add_argument('--pm-home')
        return parser


class Setup(PMCommand):
    """Setup a passwords repository"""

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
    """Add a user"""

    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(UserAdd, self).get_parser(prog_name)
        parser.add_argument('identity')
        return parser

    def take_action(self, parsed_args):
        identity = parsed_args.identity
        pm = self._get_password_manager(parsed_args)
        identity_fp = pm.get_key_fingerprint(identity)
        self.logger.info('Adding user: {0} ({1})'
                         .format(identity, identity_fp))
        pm.add_identity(identity_fp)


class UserRemove(PMCommand):
    """Remove a user"""

    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(UserRemove, self).get_parser(prog_name)
        parser.add_argument('identity')
        return parser

    def take_action(self, parsed_args):
        identity = parsed_args.identity
        pm = self._get_password_manager(parsed_args)
        # todo: refuse to remove last user!
        identity_fp = pm.get_key_fingerprint(identity)
        self.logger.info('Removing user: {0} ({1})'
                         .format(identity, identity_fp))
        pm.remove_identity(identity_fp)


class UserList(PMLister):
    """List users"""

    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(UserList, self).get_parser(prog_name)
        parser.add_argument('--full', action='store_true', default=False)
        return parser

    def _get_full(self, pm):
        header = ('Fingerprint', 'Other subkeys', 'User id')
        rows = []
        for identity in pm.list_identities():
            key = pm.gpg.get_key(identity)
            rows.append((
                identity,
                '\n'.join(sk.fpr for sk in key.subkeys),
                '\n'.join(
                    '{0} <{1}>'.format(u.name, u.email)
                    for u in key.uids)
            ))
        return header, rows

    def _get_compact(self, pm):
        header = ('Fingerprint', 'User id')
        rows = []
        for identity in pm.list_identities():
            key = pm.gpg.get_key(identity)
            rows.append((
                identity,
                '{0} <{1}>'.format(key.uids[0].name, key.uids[0].email)))
        return header, rows

    def take_action(self, parsed_args):
        pm = self._get_password_manager(parsed_args)
        if parsed_args.full:
            return self._get_full(pm)
        return self._get_compact(pm)


class KeyRegen(PMCommand):
    """Regenerate AES key"""

    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        self.logger.info("Regenerating AES key")
        pm = self._get_password_manager(parsed_args)
        pm.regenerate_aes_key()


class KeyRecrypt(PMCommand):
    """Re-encrypt key for all the users"""

    logger = logging.getLogger(__name__)

    def take_action(self, parsed_args):
        # todo: write this (we want to get the key and
        #       re-encrypt for all users)
        raise NotImplementedError("Not implemented yet")


class SecretPut(PMCommand):
    """Put contents to a secret file"""

    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(SecretPut, self).get_parser(prog_name)
        parser.add_argument('name')
        return parser

    def take_action(self, parsed_args):
        # Read secret from the standard input and write to file
        pm = self._get_password_manager(parsed_args)
        data = self.app.stdin.read()
        pm.write_secret(parsed_args.name, data)


class SecretGet(PMCommand):
    """Get contents of a secret file"""

    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(SecretGet, self).get_parser(prog_name)
        parser.add_argument('name')
        return parser

    def take_action(self, parsed_args):
        # Read secret from file input and write to stdout
        pm = self._get_password_manager(parsed_args)
        secret = pm.read_secret(parsed_args.name)
        self.app.stdout.write(secret)


class SecretDelete(PMCommand):
    """Delete a secret file"""

    logger = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(SecretDelete, self).get_parser(prog_name)
        parser.add_argument('name')
        return parser

    def take_action(self, parsed_args):
        pm = self._get_password_manager(parsed_args)
        pm.delete_secret(parsed_args.name)
