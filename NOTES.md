# GPG Usage

import gnupg
gpg = gnupg.GPG()

gpg.list_keys()
gpg.list_keys(True)

## Encrypt data

enc = gpg.encrypt('Hello, world', '0123456789ABCDEF')
encdata = str(enc)
print encdata

## Decrypt data

dec = gpg.decrypt(encdata)
decdata = str(dec)
print decdata

## Export public key

gpg.export_keys('0123456789ABCDEF')

## Export private key

gpg.export_keys('0123456789ABCDEF', True)


## Generate + export some keys

```python
import gnupg
gpg = gnupg.GPG(gnupghome='/tmp/foo-gpg')

input_data = gpg.gen_key_input(key_type='RSA', key_length=1024)
key = gpg.gen_key(input_data)

with open('tests/key1.pub', 'w') as f:
    f.write(gpg.export_keys(key.fingerprint))

with open('tests/key1.sec', 'w') as f:
    f.write(gpg.export_keys(key.fingerprint, True))
```

# AES usage

```python
from Crypto.Cipher import AES
from Crypto import Random

# Generate a random 32-bit key
key = Random.new().read(32)

# Encrypt some data
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CFB, iv)
packed = iv + cipher.encrypt(b'This is some text')

# Decrypt the data
enc_iv = packed[:AES.block_size]
enc_msg = packed[AES.block_size:]
cipher2 = AES.new(key, AES.MODE_CFB, enc_iv)
cipher2.decrypt(enc_msg)
```
