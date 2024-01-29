from itertools import product
import hashlib

alice_hash = "06acc75ba03a98566b00bda640bbf0ed7eddfd7d7d5a00f854c22309ffd98660"

pwd_dict = {} 
salt = "26678333"
possible_pwd = product('0123456789', repeat=6)

for pwd in list(possible_pwd):
    s = salt+''.join(pwd)
    h = hashlib.sha256(s.encode()).hexdigest()
    if h == alice_hash:
        print(f"Alice's password is: \n {''.join(pwd)}")
        break
    