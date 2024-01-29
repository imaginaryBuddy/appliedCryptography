from itertools import product
import hashlib 

alice_hash = "9b555812ca7685f971f53d119bd35c3c4faa1a48789b4eec535caba5745452a3"

with open('word_list.txt', 'r') as file: 
    word_list = file.read() 
    word_list = word_list.replace('\n', '.').split(".")
    word_list = word_list[:-1] # remove the last element, as it's just an empty string 

special = ["!", "?", "*", "$", "#", "&"]
salt = "64694016"
found = False 
num_hash_operations = 0 
for word in word_list: 
    num_chars = 12 
    capital = word[0].upper() + word[1:]
    num_chars_left = 12 - len(capital) -1 
    for special_char in special: 
        perms = product("0123456789", repeat=num_chars_left)
        for p in list(perms):
            s = salt+capital+''.join(p)+special_char
            h = hashlib.sha256(s.encode()).hexdigest()
            num_hash_operations += 1 
            if h == alice_hash:
                print("Alice's password: \n", capital+''.join(p)+special_char)
                found = True 
                print("Number of hash operations performed: ", num_hash_operations)
                break 

        if found:
            break 

    if found:
        break 
                

