from time import time
import gnupg, os.path
from urllib.parse import urlparse

from jsondb import Jsondb
from secret import CSV_FP, APP_FP, LIB_FP

_CIPHER_ALGO = 'RSA'
_CIPHER_BYTE = 2048

def import_csv(fp):
    '''
        @input: LastPass export csv file.
    '''

    store = {}
    i = 0
    with open(fp, 'r') as f:
        for line in f:
            i += 1
            x = line.split(',')
            if x.__len__() != 7:
                continue
            d = {
                'url': x[0],
                'username': x[1],
                'password': x[2]
            }   
            store[str(i)] = d
    return store

def b(str):
    return bytes(str, encoding='utf-8')

def rand_str(length=32):
    from string import ascii_letters, digits, punctuation
    from random import choice

    c = ''.join([ascii_letters, digits])
    text = ''

    for i in range(length):
        text += choice(c)

    return text

def encrypt_all(gpg, fingerprint):
    # Storage
    store = import_csv(fp=CSV_FP)
    db = Jsondb(f=LIB_FP, mode='w+')

    for key in store:
        fp = rand_str()
        d = store[key]

        password = d['password']
        username = d['username']
        url      = d['url']

        db.db[url] = fp

        file_data = '{password}\n{username}'.format(password=password, username=username)

        output_r = os.path.join(APP_FP, fp)
        gpg.encrypt(data = file_data, recipients = fingerprint, passphrase = 'x', output = output_r)

    db.save()

def decrypt_all(gpg, fingerprint):
    # Storage
    db = Jsondb(f=LIB_FP, mode='r')

    for key in db.db:
        fp = os.path.join(APP_FP, db.db[key])
        f = open(fp, 'rb')
        d = gpg.decrypt_file(f, passphrase = 'x')
        s = str(d)
        print(s.split('\n'), key)

def decrypt(key, gpg, fingerprint):
    # Storage.
    db = Jsondb(f=LIB_FP, mode='r')

    # Find file.
    fp = None
    netloc = urlparse(key).netloc
    for db_key in db.db:
        if netloc.lower() in db_key.lower():
            fp = os.path.join(APP_FP, db.db[db_key])

    if fp:
        with open(fp, 'rb') as f:
            d = gpg.decrypt_file(f, passphrase = 'x')
            s = str(d)
            print(s.split('\n'), key)

def main():
    # GPG
    gpg = gnupg.GPG(gnupghome='x')
    input_data = gpg.gen_key_input(key_type=_CIPHER_ALGO, key_length=_CIPHER_BYTE, passphrase='x')
    key = gpg.gen_key(input_data)
    fingerprint = key.fingerprint

    ascii_armored_public_keys = gpg.export_keys(fingerprint)
    ascii_armored_private_keys = gpg.export_keys(fingerprint, True) # True => private keys

    encrypt_all(gpg = gpg, fingerprint = fingerprint)
    decrypt(key = 'http://google.com', gpg = gpg, fingerprint = fingerprint)
    #decrypt_all(gpg = gpg, fingerprint = fingerprint)

if __name__ == '__main__':
    start = time()
    main()
    print(time() - start)
