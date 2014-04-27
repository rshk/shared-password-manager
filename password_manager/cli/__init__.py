import logging
import sys

from cliff.app import App
from cliff.commandmanager import CommandManager

from password_manager import __version__


class PasswordManagerCLI(App):

    log = logging.getLogger(__name__)

    def __init__(self):
        super(PasswordManagerCLI, self).__init__(
            description='Password Manager command-line interface',
            version=__version__,
            command_manager=CommandManager('password_manager.cli'))


def main(argv=None):
    """Main entry point"""

    if argv is None:
        argv = sys.argv[1:]
    myapp = PasswordManagerCLI()
    return myapp.run(argv)
