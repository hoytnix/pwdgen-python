from time import time

from crypto import encrypt, decrypt
from jsondb import Jsondb
from secret import CSV_FP

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

def main():
    # url,username,password,extra,name,grouping,fav
    store = import_csv(fp=CSV_FP)
    
    #i = 0
    #with open('mmm.csv', 'w+') as f:
    for key in store:
        d = store[key]

        password = b(d['password'])
        username = b(d['username'])
        url      = b(d['url'])

        _password = encrypt(data = password)
        if username != '':
            _username = encrypt(data = username)
        else:
            _username = 'None'

        print(url, _username, _password)

if __name__ == '__main__':
    start = time()
    main()
    print(time() - start)
