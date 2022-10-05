import requests
from math import ceil
from time import sleep

POSSIBLE_CHARS = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
URL      = "https://ia174.fi.muni.cz/hw01"
ENDPOINT = "encrypt"
UCO      = "492875"

def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")


#taken from minimal working example: https://ia174.fi.muni.cz/hw01/static/mwe.py
def encryptionRequest(url: str, endpoint: str, uco: str, data: bytes) -> bytes:
    sleep(0.2)  #so that we don't get blocked for spam
    response = requests.post(f"{url}/{endpoint}/{uco}", json={"data": data.hex()})
    if response.status_code != 200:
        print(f"Invalid status code: {response.status_code}")
        print(response.content.decode())
        return None
    
    data = response.json()
    return bytes.fromhex(data["ciphertext"])


initial_encrypted = encryptionRequest(URL, ENDPOINT, UCO, b"")
initial_len = len(initial_encrypted)
secret_len = 0

pad = ""

while True:
    encrypted = encryptionRequest(URL, ENDPOINT, UCO, bytes(pad, "ascii"))
    print(f"Pad len: {len(pad):02}:", end="")
    printHex(encrypted)
    new_len = len(encrypted)
    
    if (new_len != initial_len):
        secret_len = initial_len - (len(pad) - 1)
        print(f"Found secret len: {secret_len}")
        break

    pad += "9"

guess_data = "9" * initial_len
padding = guess_data
secret = ""

#try and guess all secret characters one by one
for i in range(0, secret_len):
    padding    = padding[1:]            #remove first character from padding
    guess_data = guess_data[1:] + "9"   #left "shift" our guess data
    
    #go through all possible characters
    for c in POSSIBLE_CHARS:
        guess_data = guess_data[:-1] + c    #replace last character with new one
        print(f"Guess:   {guess_data}")
        print(f"padding: {padding}")
        encrypted_guess = encryptionRequest(URL, ENDPOINT, UCO, bytes(guess_data + padding, "ascii"))   #get new data
        known   = encrypted_guess[:initial_len]                                                         #known cipher text that we created
        unknown = encrypted_guess[initial_len:initial_len * 2]                                          #unknown cipher text that we are trying to guess
        
        #loop to next character on match
        if known == unknown:
            print(f"Match!!! - {c}")
            secret += c
            break
    else:
        print("No match found!!!")
        exit(1)

print(f"The secret is: {secret}")
