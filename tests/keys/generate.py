import sys
import shutil
import gnupg
import tempfile

tmpdir = tempfile.mkdtemp()
destfile = sys.argv[1]

gpg = gnupg.GPG(gnupghome=tmpdir)

print("Generating key")
input_data = gpg.gen_key_input(key_type='RSA', key_length=1024)
key = gpg.gen_key(input_data)


print("Writing keys to {0}".format(destfile))

with open(destfile + '.pub', 'w') as f:
    f.write(gpg.export_keys(key.fingerprint))

with open(destfile + '.sec', 'w') as f:
    f.write(gpg.export_keys(key.fingerprint, True))

shutil.rmtree(tmpdir)
