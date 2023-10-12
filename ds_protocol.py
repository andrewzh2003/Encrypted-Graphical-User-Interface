# NAME Andrew Z. Ho
# EMAIL andrewzh@uci.edu
# STUDENT ID 11211101

from types import NoneType
import socket
import time
import json
from collections import namedtuple
from NaClProfile import NaClProfile

# Namedtuple to hold the values retrieved from json messages.
# TODO: update this named tuple to use DSP protocol keys
DataTuple = namedtuple('DataTuple', ['type','message', 'token'])

def extract_json(json_msg:str) -> DataTuple:
  '''
  Call the json.loads function on a json string and convert it to a DataTuple object
  
  TODO: replace the pseudo placeholder keys with actual DSP protocol keys
  '''
  conditions = False
  try:
    json_obj = json.loads(json_msg)
    foo = json_obj['type']
    baz = json_obj['message']
    conditions = True
  except json.JSONDecodeError:
    print("Json cannot be decoded.")
    return False
  if conditions:
    if foo == 'ok':
      bugh = json_obj['token']
      return DataTuple(foo, baz, bugh)
    else:
      return DataTuple(foo, baz, bugh)

def join(user, pwd, client: socket, key):
  join_msg = json.dumps({"join": {"username": user,"password": pwd,"token":key}})

  send = client.makefile('w')
  recv = client.makefile('r')

  send.write(join_msg + '\r\n')
  send.flush()

  resp = recv.readline()
  updated = json.loads(resp)
  return updated

def post(msg, client: socket, token):
  t = time.time()
  join_msg = json.dumps({"token": token, "post": {"entry": msg,"timestamp": t}})

  send = client.makefile('w')
  recv = client.makefile('r')

  send.write(join_msg + '\r\n')
  send.flush()

  resp = recv.readline()
  updated = json.loads(resp)
  return updated

def bioo(msg, client: socket, token):
  join_msg = json.dumps({"token": token, "bio": {"entry": msg,"timestamp": ''}})

  send = client.makefile('w')
  recv = client.makefile('r')

  send.write(join_msg)
  send.flush()

  resp = recv.readline()
  updated = json.loads(resp)
  return updated

def errorHandling(server, port, username, password, message:str, bio:str=None):
  ## point is to check everything to make sure whatever gets inputed is valid
  
  num = 0
  if type(server) == str and num == 0:
    num += 1
    pass
  else:
    return False
  if type(port) == int and num == 1:
    num += 1
    pass
  else:
    return False
  if type(username) == str and num == 2:
    num += 1
    pass
  else:
    return False
  if type(password) == str and num == 3:
    num += 1
    pass
  else:
    return False
  if type(message) == str and num == 4:
    num += 1
    pass
  else:
    return False
  if type(bio) == NoneType and num == 5:
    return True
  else:
    if type(bio) == str:
        return True
    else:
      return False