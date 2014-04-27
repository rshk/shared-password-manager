# Directory-based password manager

A way to share encrypted files between multiple users, via Git.

Basically, this program handles encrypting files with a symmetric
(256bit AES) key, which is stored along with the passwords,
encrypted using public keys (via GPG) of the users that are allowed
to access them.

## Installation

Unfortunately, there are some issues preventing the project from
being directly installable from tarball / git.

Instead, you need to manually install requirements file.

So, git clone / untar the source, enter the directory and:

```
pip install -r requirements.txt .
```

Also requiremes libgpgme, which should be packaged for most distros.


## Example usage

Create and enter a new directory.

```
mkdir ~/mypasswords && cd ~/mypasswords
```

Choose a key you would use to initialize the repository.

```
gpg -K
```
```
/home/user/.gnupg/secring.gpg
-----------------------------
sec   4096R/AAAA0000 2014-04-27
uid                  First Last (test) <first.last@example.com>
ssb   4096R/AAAA1111 2014-04-27
ssb   4096R/BBBB0000 2014-04-27
ssb   4096R/BBBB1111 2014-04-27
```

Let's use our (only) master key: ``AAAA0000``.

Setup the passwords repository:

```
password_manager setup AAAA0000
```

Create a secret:

```
echo "Hello world" | password_manager secret put hello.txt
```

Get the secret back:

```
password_manager secret get hello.txt
```

Add a contributor:

```
password_manager user add FFFF0000
```

Share on git:

```
git init
git add -A
git commit -m "Passwords are here!"
```


## Known limitations

### User deletion is quirky

(as in most cases involving cryptography-based access control).

We regenerate the AES key each time a user gets deleted, but
there is no way to make sure a user can no longer access old versions
of the files he ad access to in the past.

Of course, files encrypted with the new AES key wouldn't be accessible
by the deleted user. Remember to change all passwords if you stop trusting
a previous team member! :)


### Merges can be a pain

While there are plans to solve this, you should avoid having to merge
two branches that use different AES keys.

**Example:**

We start with a repo like this:

```text
Commit 0000
|-- .keys
|   |-- AES1#PK1
|   |-- AES1#PK2
|   |-- PK1
|   '-- PK2
|-- PW1#AES1
'-- PW2#AES1
```

Where "``...#...``" means "encrypted with key", ``AES<n>`` is a version
of the AES master key and ``PK<n>`` is the public key of user ``<n>``.


Now, user 1 decides to add a new ``PW3`` and make changes to ``PW2``:

```text
Commit 1111 (parent: 0000)
|-- .keys
|   |-- AES1#PK1
|   |-- AES1#PK2
|   |-- PK1
|   '-- PK2
|-- PW1#AES1
|-- PW2b#AES1
'-- PW3#AES1
```

In the meanwhile, user 2 adds ``PW4`` and decides to change the
AES master password:

```text
Commit 2222 (parent: 0000)
|-- .keys
|   |-- AES2#PK1
|   |-- AES2#PK2
|   |-- PK1
|   '-- PK2
|-- PW1#AES2
|-- PW2#AES2
'-- PW4#AES2
```

Then, they both attempt to push. The second one will get a conflict
and try to merge. But now the status would be something like:

```text
|-- .keys
|   |-- AES2#PK1           <--- The new key gets fastworwarded
|   |-- AES2#PK2                correctly, as it was changed in 2222
|   |-- PK1
|   '-- PK2
|-- PW1#AES2               <--- [OK] fast forward (from 2222)
|-- PW2b#AES1 | PW2#AES2   <--- [conflict] both modified (we want PW2b#AES2 !)
|-- PW3#AES1               <--- [error] merge ok, but enc. with old key!
'-- PW4#AES2               <--- [OK] added in 2222, with new key
```

To solve the issue, we'd need to do something like:

- figure out whether the AES key changed (if the file differ then yes!)
- in that case, decrypt all passwords with old key and recrypt with new
  one before merging.

**Note:** we'd probably still get differing files, as the IVs would
change! We need to decrypt old/new version of modified files and compare.

It would be nice to write a whole "encryption layer" based on Git,
to allow smarter management of merges, etc.. (we could even use a mergetool
on temporarily-decrypted versions of the file -- but we need to make sure
we keep them away from prying eyes!).
