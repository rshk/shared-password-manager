# Directory-based password manager

**Features:**

- allows sharing secrets between users, by encrypting them with a symmetric
  key, which is stored encrypted for each user.
- suitable for keeping the data under version control, eg. in git.


## Base concepts

- Secrets are stored in json files. They can be pretty much anything,
  not just passwords.
- Secrets are encrypted using a symmetric AES key
- The symmetric AES key itself is stored in the directory, encrypted
  using the public keys of all the users which are allowed to access
  the repo.


## Directory layout

```
|-- .keys
|   |-- user1.key   AES password encrypted for user 1
|   |-- user1.pub   GPG public key for user 1
|   |-- user2.key   AES password encrypted for user 2
|   '-- user2.pub   GPG public key for user 2
'-- *.json          Password files containing "secrets"
```

## Installing

Dependencies need to be installed from ``requirements.txt``,
as we need to install a fork for pygpgme which is not in pypi..

Plus, stevedore has some problems installing when listed
as dependency in ``setup.py``.

```
pip install -r requirements.txt .
```
