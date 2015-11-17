#!/usr/bin/env python

'''
py3k: True
'''

import json

class Jsondb:
    def __init__(self, f='db.json', mode='r'):
        self.f    = f
        self.mode = mode
        self.db = self.load()

        if self.db == None:
            self.db = dict({})

    def load(self):
        try:
            with open(self.f, 'r') as _f:
                data = json.load(_f)
            return data
        except ValueError:
            if self.mode == 'w+':
                return None
            else:
                return False
        #except FileNotFoundError:
        #    #return {}
        #    return False
        #except:
        #    return False

    def save(self):
        with open(self.f, 'w') as _f:
            data = json.dump(obj=self.db, fp=_f, indent=0)
        return data

    def _print(self):
        data = json.dumps(obj=self.db, indent=4)
        print(data)

    def add_key(self, key='foo'):
        for o in self.db:
            try:
                self.db[o][key] = ''
            except:
                pass

def main():
    db = Jsondb(f='/opt/datas/db.json', mode='w+')
    json = db.db 

    if json == False:
        return False

    print( json.__len__() )

    json['foo'] = 'bar'

    print( json.__len__() )

    db.db = json
    db.save()

    return True

if __name__ == '__main__':
    print( main() )