# Uses the pycryptodome package.
from mimetypes import init
from Crypto.Cipher import AES

KEY = bytes("anythinganything", "ascii")
SECRET = bytes("cool symbol stuff rack", "ascii")

POSSIBLE = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")

def encrypt(data):
    # Create a cipher object.
    cipher = AES.new(key=KEY, mode=AES.MODE_ECB)
    # Pad the plaintext at the end with \x00 so that it is a multiple of AES block size.
    if len(data + SECRET) % AES.block_size != 0:
        pad = b"\0" * (AES.block_size - (len(data + SECRET) % AES.block_size))
    else:
        pad = b""
    padded = data + SECRET + pad
    # Encrypt the padded message
    encrypted = cipher.encrypt(padded)
    return encrypted

initial_encrypted = encrypt(b"")
initial_len = len(initial_encrypted)
secret_len = 0

pad = ""

while True:
    print(pad)
    encrypted = encrypt(bytes(pad, "ascii"))
    printHex(encrypted)
    new_len = len(encrypted)
    
    if (new_len != initial_len):
        secret_len = initial_len - (len(pad) - 1)
        print("Secret len found!")
        print(f"Pad size: {len(pad) - 1}")
        print(f"Secret size: {secret_len}")
        break
    pad += "9"

guess_data = "9" * initial_len
padding = guess_data
secret = ""

for i in range(0, secret_len):
    padding    = padding[1:]
    guess_data = guess_data[1:] + "9" # left "shift"
    for c in POSSIBLE:
        guess_data = guess_data[:-1] + c
        print(f"Guess:   {guess_data}")
        print(f"padding: {padding}")
        encrypted_guess = encrypt(bytes(guess_data + padding, "ascii"))
        known   = encrypted_guess[:initial_len]                 #known cipher text that we created
        unknown = encrypted_guess[initial_len:initial_len * 2]  #unknown cipher text that we are trying to guess
        
        if known == unknown:
            print(f"Match!!! - {c}")
            secret += c
            break
    else:
        print("No match found!!!")
        exit(1)

print(f"Probable secret: {secret}")
