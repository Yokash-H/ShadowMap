import random
from Secret import mySecretKey, SecretText                                              

def encrypt(pt):
    results = [str(ord(ch) % mySecretKey) for ch in pt]   
    
    with open('flag.enc', 'w') as f:
        f.write(" ".join(results))
    return mySecretKey

k = encrypt(SecretText)
print(k)                                     
