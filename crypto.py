from oscrypto import symmetric, util

def decrypt(data, key, iv):
    return symmetric.aes_cbc_pkcs7_decrypt(data = data, key = key, iv = iv)

def encrypt(data = b'b', key = None, iv = None):
    if key is None:
        key = util.rand_bytes(length=32)
    if iv is None:
        iv = util.rand_bytes(length=16)

    e = symmetric.aes_cbc_pkcs7_encrypt(data = data, key = key, iv = iv)

    return {
        'data': e[1],
        'key': key,
        'iv': e[0]
    }

def test():
    e = encrypt()
    d = decrypt(data = e['data'], key = e['key'], iv = e['iv'])

    print(e, d)

if __name__ == '__main__':
    test()