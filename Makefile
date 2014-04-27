.PHONY: all tests

all:
	@echo "Use \`make tests' to run tests"

tests:
	@# Just to be safe, we set a dummy ``GNUPGHOME``
	GNUPGHOME=/tmp/dummy-gpg py.test -vvv ./tests
