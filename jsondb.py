#!/usr/bin/env python3.4
'''
    Jsondb - Persistent data-storage with Json.

    @version v0.x.1
    @python 3.4
    @author Michael Hoyt / pr0xmeh (github.com/pr0xmeh)
'''

import json

class FileNotFound(FileNotFoundError):
    def __init__(self, FileNotFoundError):
        print(FileNotFoundError)

class UnkownException(Exception):
    def __init__(self, Exception):
        print('Please send the following to me at gitgub.com/pr0xmeh')
        print('-' * 40)
        print(Exception)

class CriticalException(Exception):
    def __init__(self, Exception):
        print('Critical exception: unable to continue.')

class Jsondb:
    '''
        Critical errors will force self.db to None to let the program
        know that it can't continue.
    '''

    def __init__(self, f='db.json', mode='r', encoding=None):
        # Settings.
        self.f = f
        self.mode = mode
            
        # File-encoding.
        if encoding is None: # Default.
            self.encoding = 'utf-8'
        else:
            self.encoding = encoding

        # db-object.
        self.db = {}
        if not self.load():
            raise CriticalException(Exception("Error on load."))

    def load(self):
        if self.mode == 'w+': # Does not exist yet / over-write.
            with open(self.f, 'w+', encoding=self.encoding) as f:
                self.save()
                return True

        try:
            with open(self.f, 'r', encoding=self.encoding) as f:
                data = json.load(f)
                self.db = data
        except FileNotFoundError as e:
            raise FileNotFound(e)
            return False
        except Exception as e:
            raise UnkownException(e)
            return False

        return True

    def save(self):
        # Cast data for serialization.
        for key in self.db:
            row = self.db[key]
            if type(row) is bytes:
                self.db[key] = row.decode('cp1252')
            if type(row) is list or type(row) is tuple:
                self.db[key] = [x.decode('cp1252') if type(x) is bytes else x for x in row]

        # Write to file.
        with open(self.f, 'w') as _f:
            data = json.dump(obj=self.db, fp=_f, indent=0)
        return data

    def prettify(self):
        data = json.dumps(obj=self.db, indent=4)
        print(data)

def test():
    import os, os.path, string
    junk_file = 'huvvuahiahiahaabiaahxb'

    '''
        1) w+ mode.
    '''
    db = Jsondb(mode='w+')
    if not os.path.isfile(db.f):
        print('1) Broken.')
    else:
        os.remove(db.f)
        print('1) Works.')

    #input('Press any key to continue.')

    ''' 
        2) FileNotFoundError.
    '''
    b = True
    try:
        db = Jsondb(f=junk_file, mode='r')
        b = False
    except FileNotFound:
        print('2) Works.')
    if not b:
        print('2) Broken.')

    #input('Press any key to continue.')

    '''
        Data Types:
        3a)    Strings.
        3b)    Lists - Tuples.
        3c)    Bytes.
        3d)    Array of bytes.
        3e)    Mixed array.

    '''
    db = Jsondb(mode='w+')
    b = True

    # 3a) Strings.
    try:
        db.db['string'] = string.printable
    except Exception as e:
        b = False
        print('3a) Broken.')
        raise UnkownException(e)
    
    # 3b) Lists - Tuples.
    try:
        db.db['list']  = [x for x in range(10)]
        db.db['tuple'] = (1,2,3,4,5)
    except Exception as e:
        b = False
        print('3b) Broken.')
        raise UnkownException(e)

    # 3c) Bytes.
    try:
        db.db['bytes'] = b'\xcb\xa5\xce6\x91\xa1\xa5l\xf3J\xa8L\x19F}x\x87\x98\xa1^\xb5\xf2\xcf\xa7\x9f&7\x16u\x95c\t'
    except Exception as e:
        b = False
        print('3c) Broken.')
        raise UnkownException(e)

    # 3d) Array of bytes.
    try:
        db.db['list of bytes'] = [
            b'a',
            b'b',
            b'c,'
        ]
        db.db['tuple of bytes'] = (
            b'a',
            b'b',
            b'c,'
        )
    except Exception as e:
        b = False
        print('3d) Broken.')
        raise UnkownException(e)

    # 3e) A mix of both!
    try:
        db.db['mix'] = [
            b'a',
            'b',
            3
        ]
    except Exception as e:
        b = False
        print('3d) Broken.')
        raise UnkownException(e)

    if b:
        print('3) Works.')

    '''
        4) Json serialization.
    '''

    b = False
    try:
        db.save()
        b = True
    except Exception as e:
        print('4) Broken.')
        raise UnkownException(e)
    if b:
        print('4) Works.')
        print(db.db)

    os.remove(db.f)

if __name__ == '__main__':
    test()