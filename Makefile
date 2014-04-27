.PHONY: all tests

PYTESTARGS = -vvv --cov=password_manager --cov-report=term-missing --pep8

all:
	@echo "Use \`make tests' to run tests"

tests:
	@# Just to be safe, we set a dummy ``GNUPGHOME`` here..
	GNUPGHOME=/tmp/dummy-gpg py.test $(PYTESTARGS) ./tests
