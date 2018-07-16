from Cipher import * 

## THIS FILE IS FOR JUST A TEST, WILL BE REMOVED.
key = b'\xff'*32
nonce = b'\xff'*12

ploychacha1 = Chacha20Poly1305(key, nonce)
text = (b"hogehogehogehgoe"*10)[:64]
c = ploychacha1.encrypt(text)
print(c)

ploychacha2 = Chacha20Poly1305(key, nonce)
m = ploychacha2.decrypt(c)
print(m)

