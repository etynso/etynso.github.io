---
title: "Unsolved Challs from Local CTFs #1"
date: 2025-11-17
tags: ["ctf", "AES", "Block Cipher", "Subset Sum", "Subset Product"]
draft: false
showHero: true
heroStyle: "background"
---

{{< katex >}}

# Unsolved Challs from Local CTFs #1

Recently, two local CTFs were held which I didn't have the chance to participate in, it had some unsolved crypto challs which I decided to solve outside of the CTFs :)

## Wreck IT CTF 6.0

I didn't participate in Wreck IT CTF 6.0 which was open to public, but I "participated" via discord chat with the crypto legend `azuketto`. Until the end of the CTF only 1/4 crypto challs had any solve (and of course it had one solve). For this writeup I will be covering 2 challenges on AES CBC which I find to be a fresh breath of air amidst all the number theory stuff, as it had been a while since block cipher challenges appeared in local CTFs.

![Azuketto Gives Chall](/images/unsolved_1/wreckit-discord.png)

### Pharloom

Technically this challenge is not unsolved as it had 1 solve at the end of the CTF, but I'm covering it here since it relates with the next chall.

#### Source Code:

{{< details summary="chall.py" >}}

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import md5
import random
import os

KEY = os.urandom(16)
FLAG = open('flag.txt', 'rb').read()
K = 2

def encrypt(data: bytes, K: int = K):
    pt = pad(data, 16)
    iv = md5(pt).digest()[:16]
    ct = pt
    for _ in range(K):
        cipher = AES.new(KEY, AES.MODE_CBC, iv) 
        ct = cipher.encrypt(ct)
    return iv, ct

def decrypt(data: bytes, iv: bytes):
    pt = data
    for _ in range(K):
        cipher = AES.new(KEY, AES.MODE_CBC, iv) 
        pt = cipher.decrypt(pt)
    pt = unpad(pt, 16)
    return pt

def chall():
    global KEY
    IV, CT = encrypt(FLAG)
    while True:
        try:
            choice = int(input(">> "))
            if choice == 1:
                Encrypt
                data = bytes.fromhex(input("Data (hex): "))
                iv, ct = encrypt(data)
                print(ct.hex())
            elif choice == 2:
                data = bytes.fromhex(input("Data (hex): "))
                iv = bytes.fromhex(input("IV (hex): "))
                pt = decrypt(data, iv)
                print(ct.hex())
            elif choice == 3:
                Flag
                print(IV.hex())
                print(CT.hex())
            elif choice == 4:
                KEY = os.urandom(16)
                IV, CT = encrypt(FLAG)
                print("Done")
            else:
                print("Bye")
                exit(0)
        except Exception as e:
            print("Nope")

if __name__ == "__main__":
    chall()
```

{{< /details >}}

#### Problem Statement

The challenge exposes a simple AES-CBC service with two oracles and a flag dump. Everything is encrypted using a single global 16-byte AES key and **CBC applied twice** (`K = 2`). The important part is that the IV is not random — it is deterministically computed as:

```
IV = md5(pad(pt))[:16]
```

The service offers:

1. **Encrypt arbitrary data**  
   You provide a plaintext `data` in hex, it is padded, its IV is computed from that padded plaintext, and then the server returns the ciphertext after running **two rounds of AES-CBC with the same IV**.

2. **Decrypt arbitrary data**  
   You send any ciphertext and any IV you want, and the server decrypts it through the same two CBC layers and finally unpads it.

3. **Get the flag ciphertext**  
   The server prints:
   - the IV used for the flag  
   - the ciphertext of `FLAG` encrypted under the same double-CBC scheme.

4. **Reset the key**  
   Regenerates the AES key and re-encrypts the flag.

So the interaction model is: an **encrypt oracle with fixed deterministic IV**, a **decrypt oracle with user-controlled IV**, and the **flag encrypted once under the global key**.

#### Initial Thoughts

I noticed there's a clear padding oracle in decrypt, as exceptions are handled by printing `'Nope'` without terminating the script. The question now becomes: how do we leverage this padding oracle under this weird encryption scheme?

So I scribbled some things to figure out what it's doing and pretty quickly got this! (I cleaned it up a bit):

```py
iv pt1 pt2 pt3
E(pt1 ^ iv) == ct1 | E(ct1 ^ pt2) == ct2
E(ct1 ^ iv) == ctt1 | E(ctt1 ^ ct2) == ctt2

ivf ctt1 ctt2
D(ctt1) ^ ivf = ct1 ^ ivf | D(ctt2) ^ ctt1 = ct2
D(ct1 ^ ivf) ^ ivf | D(ct2) ^ ct1 ^ ivf = pt2 ^ ivf (This is Where the padding oracle is)
```

The scribbling describes itself! Here `ivf` is the forged IV, and the way to get a padding oracle is that this forged IV will eventually be XORed into the decryption result of the second block — the same way the previous block is XORed in a normal padding oracle attack.

But notice: we **cannot** use the padding oracle to decrypt the first block, because we require another block *before* the block we want to decrypt. I tried to find some trick because I thought I missed something, but after confirming with the author, the flag prefix is long and the remaining characters are hex. This means out of the 16 characters in the first block, we know:

```
WRECKIT60{
```

and the remaining 6 characters are lowercase hex chars:

```
16^6 = 16,777,216 possibilities
```

Which is brute-forceable using the IV and MD5 hash as validator.

{{< details summary="solve.py" >}}

```py
from pwn import *
from Crypto.Util.Padding import unpad
import itertools, hashlib

-------------------------
connect + helpers (yours)
-------------------------
target = remote("143.198.215.203", 8031)

def oracle(data, iv):
    target.sendlineafter(b">> ", b"2")
    target.sendlineafter(b"Data (hex): ", data.hex().encode())
    target.sendlineafter(b"IV (hex): ", iv.hex().encode())
    line = target.recvline()
    return b"Nope" not in line

def get_enc():
    target.sendlineafter(b">> ", b"3")
    IV = bytes.fromhex(target.recvline().strip().decode())
    CT = bytes.fromhex(target.recvline().strip().decode())
    return CT, IV

def prime_oracle():
    do one encrypt so menu 2 prints something on success
    target.sendlineafter(b">> ", b"1")
    target.sendlineafter(b"Data (hex): ", b"00")

-------------------------
K=2 CBC padding attack for P2..Pn (unchanged logic)
-------------------------
def chunk16(b):
    return [b[i:i+16] for i in range(0, len(b), 16)]

def recover_block(prev2, prev1, block):
    payload = prev1 + block
    plain = bytearray(16)
    for pad in range(1, 17):
        i = 16 - pad
        found = False
        for g in range(256):
            iv_try = bytearray(prev2)
            set already solved suffix to pad
            for j in range(1, pad):
                iv_try[-j] ^= plain[-j] ^ pad
            set guess on current byte
            iv_try[-pad] ^= g
            small guard to avoid trivial p==1 hit
            if pad == 1:
                iv_try[-2] ^= 1
            if oracle(payload, bytes(iv_try)):
                real plaintext byte = pad ⊕ orig_prev2 ⊕ forged_prev2
                plain[-pad] = pad ^ prev2[-pad] ^ iv_try[-pad]
                found = True
                break
        if not found:
            raise RuntimeError(f"no byte found at pad={pad}")
    return bytes(plain)

def recover_tail():
    prime_oracle()
    CT, IVF = get_enc()
    blocks = [IVF] + chunk16(CT)  C0=IVF, C1..Cn
    recovered = b""
    while len(blocks) >= 3:
        prev2, prev1, blk = blocks[-3], blocks[-2], blocks[-1]
        pblk = recover_block(prev2, prev1, blk)
        recovered = pblk + recovered
        print(recovered)
        blocks.pop()
    remaining [IVF, C1] — P1 not recoverable via oracle; return tail and IVF
    return recovered, IVF

-------------------------
Brute P1 using md5(P1||tail)[:16] == IVF
First block must be: b"WRECKIT60{" + six hex chars (lowercase)
-------------------------
def brute_first_block(ivf, tail):
    prefix = b"WRECKIT60{"
    assert len(prefix) == 10
    alphabet = b"0123456789abcdef"
    for tup in itertools.product(alphabet, repeat=6):  16^6 = 16,777,216
        p1 = prefix + bytes(tup)  10 + 6 = 16 bytes
        if hashlib.md5(p1 + tail).digest()[:16] == ivf:
            return p1
    return None

def main():
    tail, ivf = recover_tail()
    print(f"[+] Recovered tail length: {len(tail)} bytes (P2..Pn).")
    p1 = brute_first_block(ivf, tail)
    if not p1:
        print("[-] P1 not found in 16^6 space (unexpected for this flag format).")
        print(tail)
        return
    full_pt = p1 + tail
    try:
        flag = unpad(full_pt, 16).decode('utf-8', 'replace')
        print(f"[+] FLAG: {flag}")
    except Exception:
        print(f"[+] Full plaintext (hex): {(p1+tail).hex()}")

if __name__ == "__main__":
    main()
```

{{< /details >}}

### Abyss

#### Source Code:

{{< details summary="chall.py" >}}

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import md5
import random
import os

KEY = os.urandom(16)
FLAG = open('flag.txt', 'rb').read()
K = 2

ecb_encrypt = lambda x : AES.new(KEY, AES.MODE_ECB).encrypt(x)
ecb_decrypt = lambda x : AES.new(KEY, AES.MODE_ECB).decrypt(x)
to_blocks = lambda x : [x[i:i+16] for i in range(0, len(x), 16)]

def encrypt(data: bytes, iv: bytes = None):
    pt = pad(data, 16)
    if iv is None: iv = md5(pt).digest()[:16]
    ct = pt
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    for _ in range(K):
        ct = cipher.encrypt(ct)
    return iv, ct

def decrypt(data: bytes, iv: bytes):
    pt = data
    cipher = AES.new(KEY, AES.MODE_CBC, iv) 
    for _ in range(K):
        pt = cipher.decrypt(pt)
    pt = pt[-16:]
    return pt

def chall():
    global KEY
    IV, CT = encrypt(FLAG)
    while True:
        try:
            choice = int(input(">> "))
            if choice == 1:
                Encrypt
                data = bytes.fromhex(input("Data (hex): "))
                iv, ct = encrypt(data)
                print(ct.hex())
            elif choice == 2:
                data = bytes.fromhex(input("Data (hex): "))
                iv = bytes.fromhex(input("IV (hex): "))
                pt = decrypt(data, iv)
                print(pt.hex())
            elif choice == 3:
                Flag
                print(IV.hex())
                print(CT.hex())
            elif choice == 4:
                KEY = os.urandom(16)
                IV, CT = encrypt(FLAG)
                print("Done")
            else:
                print("Bye")
                exit(0)
        except Exception as e:
            print("Nope")

if __name__ == "__main__":
    chall()
```

{{< /details >}}

#### Problem Statement

This challenge exposes another AES-based oracle, again using a single global 16-byte key and **CBC applied twice** (`K = 2`), but with two major differences from *Pharloom*:

1. The cipher's IV isn't reset — meaning the IV for the second CBC pass begins as the **last ciphertext block** of the first pass.
2. The decryption oracle **never unpads**; instead, it returns **only the final 16-byte block** after the two-layer CBC decryption.
3. The encryption oracle lets you **optionally override the IV**, but when omitted it is once again:

```
IV = md5(pad(pt))[:16]
```

The service gives:

1. **Encrypt arbitrary data** — plaintext is padded, the IV is derived (or user-supplied), and ciphertext is produced via double CBC.
2. **Decrypt arbitrary data** — returns only the last block after double decryption.
3. **Flag ciphertext** — prints the flag IV and ciphertext.
4. **Reset key** — regenerates key + re-encrypts the flag.

Unlike *Pharloom*, there is **no padding oracle** here — the decrypt path never raises `unpad()`.

#### Initial Thoughts

This challenge initially seems a lot tougher as the vulnerability isn't obvious! Actually, there's an obvious vulnerability which LLM could figure out, that is the decryption actually yields the correct final block for number of block size >= 3. I wasted some time on this, but it turns out that this leads nowhere as the first and second blocks are still missing. So instead i turn my head to the **encryption** service and do some scribbling

```py
Encrypt
x
E(md5 ^ x)
E(E(md5 ^ x) ^ E(md5 ^ x))
gives encryption of zero
```

Okay, as it turns out when we encrypt only one block, we get encryption of zero! I knew, this would be big and we can leverage it in decrypt as such

```py
iv
E(0)
D(E(0)) ^ iv = iv
D(iv) ^ E(0)     (this is what decrypt returns)
```

So, by decrypting the encryption of zero, we get decryption of iv xored with encryption of zero. Since we know what the encryption of zero is, we can then xor it with the output to get the decryption of iv. Since we can choose our iv this effectively becomes an ECB decryption oracle! Then, everything else is easy.

{{< details summary="solve.py" >}}

```py
from pwn import *

LOCALHOST, PORT = "localhost", 1337
r = remote(LOCALHOST, PORT)

def menu(x) :
    r.sendlineafter(b">> ", str(x).encode())

def encrypt(data) :
    menu(1)
    r.sendlineafter(b"Data (hex): ", data.hex().encode())
    return bytes.fromhex(r.recvline(drop = True).decode())

def decrypt(data, iv) :
    menu(2)
    r.sendlineafter(b"Data (hex): ", data.hex().encode())
    r.sendlineafter(b"IV (hex): ", iv.hex().encode())
    return bytes.fromhex(r.recvline(drop = True).decode())

def get_flag() :
    menu(3)
    return bytes.fromhex(r.recvline(drop = True).decode()), bytes.fromhex(r.recvline(drop = True).decode())

iv, ct = get_flag()

zero_enc = encrypt(b"\x00")

def ecb_decrypt(data) :
    return xor(decrypt(zero_enc, data), zero_enc)

def cbc_decrypt_loop(data) :
    blocks = [data[i:i+16] for i in range(0, len(data), 16)][::-1]
    result = []

    for block, iv in zip(blocks[:-1], blocks[1:]) :
        result.append(xor(ecb_decrypt(block), iv))

    result.append(xor(ecb_decrypt(blocks[-1]), result[0]))

    return result[::-1]

def cbc_decrypt(data, iv) :
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    result = []
    last = iv

    for block in blocks :
        result.append(xor(ecb_decrypt(block), last))
        last = block

    return result

tmp1 = b"".join(cbc_decrypt_loop(ct))
tmp2 = cbc_decrypt(tmp1, iv)
print(b"".join(tmp2))
```

{{< /details >}}

## Schematics CTF 2025

Again, Schematics CTF 2025 is an event which i didn't participate in due to conflict with another CTF, the qualification stage challs weren't that interesting. I dm'd the author regarding the final stage challenge to ~~assert dominance~~ **learn from them** and i found one of them to be quite interesting

![etern1ty Gives Chall](/images/unsolved_1/schematics-discord.png)

### Fracture Ray

#### Source Code

{{< details summary="chall.py" >}}

```py
from Crypto.Util.number import *
from Crypto.Random import *
from gmpy2 import mpz
from sympy import *
from hashlib import *
import signal, sys

with open('flag.txt', 'rb') as f:
    flag = f.read().strip()

def H(tag, m: bytes) -> bytes:
    return sha3_256(tag + m).digest()[:8]

def sign(N, d, tag, m: bytes) -> int:
    h = H(tag, m)
    return pow(mpz(int.from_bytes(h, 'big')), d, N)

def verify(N, e, tag, m: bytes, s: int) -> bool:
    v = pow(s, e, N)
    vb = long_to_bytes(v)
    return vb[:8] == H(tag, m)

def main():
    a = getRandomInteger(2048)
    b = getRandomInteger(2048)
    p = nextprime(a)
    q = nextprime(b)
    N = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))
    tag = get_random_bytes(16)

    print(f"N = {N}")
    print(f"e = {e}")
    print(f"tag = {tag.hex()}")

    msgs = [get_random_bytes(3) for _ in range(96)]
    for m in msgs:
        s = sign(N, d, tag, m)
        print(m.hex(), format(s, "x"))

    target = b"https://www.youtube.com/watch?v=1v7WXxLWSrk"

    signal.alarm(67)
    try:
        s_hex = input("s: ").strip()
        s = int(s_hex, 16)
    except Exception:
        print("whuh")
        sys.exit(0)

    if verify(N, e, tag, target, s):
        print(f'yay!!!! here flag: {flag}')
    else:
        print('nuh uh')

if __name__ == "__main__":
    main()
```

{{< /details >}}

#### Problem Statement

This challenge implements a custom RSA signing scheme where messages are first hashed using:

$$ H(\text{tag}, m) = \text{SHA3-256}(\text{tag} \| m)[:8] $$

and the signature is computed as a plain RSA exponentiation:

$$ s = H(\text{tag}, m)^d \bmod N $$

The public verification process exponentiates the signature:

$$ v = s^e \bmod N $$

and checks whether the first 8 bytes of `v` match the 8-byte digest of the message under the same keyed hash.

At the start of the challenge, the server:

1. Generates two random 2048-bit integers `a` and `b`, takes their next primes `p = nextprime(a)` and `q = nextprime(b)`, and uses them to construct a 4096-bit RSA modulus:

   $$ N = p \cdot q $$

2. Samples a random 16-byte tag used for all hashing operations.  
3. Produces **96 message–signature pairs**, where each message is a random 3-byte string and each signature is correct under the unknown private key `d`.

Your goal is to forge a valid signature **on a specific target message**:

```
b"https://www.youtube.com/watch?v=1v7WXxLWSrk"
```

You must output a hexadecimal integer `s` such that:

```
pow(s, e, N)
```

begins with the 8-byte value:

```
H(tag, target)
```

If verification succeeds, the server reveals the flag.

The service provides:

- The RSA modulus `N` and public exponent `e`.  
- The secret per-session 16‑byte tag.  
- 96 challenge signatures `s_i` for random short messages `m_i`.  
- A single opportunity to submit one forged signature `s` for the fixed target message.

The problem thus reduces to constructing an integer `s` satisfying:

$$ s^e \equiv H(\text{tag}, \text{target}) \pmod{N} $$

without knowledge of the RSA private key.

#### Initial Thoughts

There is a clear vulnerability that sticks out! that is why would you only use 8 bytes of the hash equaling to a 64 bits integer for the verification?

Another common rsa signature trick is that rsa is a multiplicatively homomorphic scheme, which is a fancy way of saying \\(S(a) * S(b) = S(a * b)\\\), where a and b here are the hash of the respective message

So the win condition actually becomes rather loose, since the verification is done by decoding the signature, then converting it into bytes and checking only the first 8 bytes, this means it doesn't matter what the decoded signature size is as long as when it is converted to bytes the first 8 bytes is the same as the first 8 bytes of the message hash

Okay, combined with the fact that we're given 96 signatures from 64 bit integers, there has got to be a way to multiply them such that when converted to bytes they have the 8 bytes prefix that we want! This fact is rather obvious, what is not however is finding such product as subset product is not really an easily solvable problem especially under modulo N.

However, subset product (even under modulo N) can be turned into subset sum via logarithm, this is showcased in an obvious manner by `Zyan` on the chall [LoveLinhaLot](https://zayn.id.vn/posts/2024/2024-10-23-ascis-ctf/) on Vietnam ASCIS CTF Final 2024, as well as more recently by `Whale120` on chall [Republic of Geese](https://blog.whale-tw.com/2025/10/19/qnqsec-ctf-2025/#Republic-of-Geese) in QnQsec ctf 2025.

The difference however is that in both of those we're working with discrete logarithm, while in this challenge clearly it's impossible to solve discrete logarithm mod N. However, the trick is that we don't need to do discrete logarithm, as our prefix is only 64 bits, while the modulo is 4096 bits, this means we can set our target to be 4064 bits, and there should be many solutions such that the top 64 bits are the same

#### Subset Product → Subset Sum

Before going further, let me clarify the “subset product → subset sum using logarithms” thing a bit more. In any multiplicative group \\(G\\), if you have elements \\(g_i\\) and you want to pick a subset whose product equals some target \\(g\\), the natural way to linearize the problem is to take logarithms:

\\[
\log(g) = \log\left(\prod g_i^{c_i}\right) = \sum c_i \cdot \log(g_i)
\\]

Exactly the same structure: **subset product becomes subset sum**.  
The only difference is what kind of logarithm you are allowed to take.

- In finite fields or groups modulo a prime, this “log” is the **discrete logarithm**.  
- In \\(\mathbb{R}^+\\\), the log is the usual real-valued logarithm.

The *concept* is identical — the logarithm converts multiplication into addition — but discrete logs are usually computationally infeasible, while real logs are trivial.

In the previous CTF challenges (LoveLinhaLot and Republic of Geese), the trick worked because the challenge structure let you exploit discrete logs. But here, computing discrete log mod \\(N\\\) is impossible.

The key observation — and the reason we can still use the trick anyway — is that **we don’t need exact equality in the group**.  
The RSA verification only checks the **first 8 bytes** of the decoded value.  
So instead of solving:

\\[
\prod h_i^{c_i} = H_{\text{target}} \pmod{N}
\\]

we only need:

- the **top 64 bits** to match,
- the remaining ~4064 bits can be anything.

This huge slack means we can safely treat the \\(h_i\\\) values as regular integers and use **real-valued logarithms**:

\\[
\log(h_i) \in \mathbb{R}
\\]

Then solve the approximate subset sum:

\\[
\sum c_i \cdot \log(h_i) \approx \log(H_{\text{target}} \ll 4000)
\\]

The goal is simply to get the *magnitude* right.  
Once we find coefficients \\(c_i\\) making the real-valued sum land in the right interval, the actual modular product:

\\[
\prod h_i^{c_i} \bmod N
\\]

tends to fall in the range whose **top 64 bits** match the needed prefix, because many such integers exist.

So, we just have to solve the subset sum problem which can be done via lattice method! Initially, i tried to construct my own lattice and reducing that, but, i end up getting negative coefficients which sadly won't work since those negative coefficients correspond to division in real numbers which is an operation that we can't mirror mod n (at least in terms of keeping the prefix). After trying to configure the lattice for a bit using CVP to get all positive solutions and failing miserably, i decided to ACTUALLY learn the correct way to solve this problem which is by using Integer Linear Programming (ILP). Thankfully, we just use [Blupper's implementation](https://github.com/TheBlupper/linineq/) and find out it's super easy to use and after a bit of parameter tuning eventually gets a solution that works about 90% of the time and < 10 seconds in local :D

![Fracture Solve](/images/unsolved_1/solve-fracture.png)

{{< details summary="solve.py" >}}

```py
from sage.all import *
from pwn import *
from hashlib import sha3_256
from Crypto.Util.number import long_to_bytes
from time import time
from linineq import solve_bounded

start = time()

def H(tag, m: bytes) -> bytes:
    return sha3_256(tag + m).digest()[:8]

r = remote("localhost", 1337)

r.recvuntil(b"N = ")
N = int(r.recvline())
r.recvuntil(b"e = ")
e = int(r.recvline())
r.recvuntil(b"tag = ")
tag = bytes.fromhex(r.recvline().decode())

dim = 30
samples = []
for _ in range(dim) :
    m, s = list(map(lambda x : int(x, 16), r.recvline().strip().decode().split(' ')))
    samples.append((m, s, pow(s, e, N)))

R = RealField(3000)
log_s = [R(log_b(h)) for _, _, h in samples[:dim]]
sig_target = b"https://www.youtube.com/watch?v=1v7WXxLWSrk"
actual_h = H(tag, sig_target)
h_target = int.from_bytes(actual_h) << 4000
log_target = R(log_b(h_target))

scaler = 2**69
L = [ZZ(int(l * scaler)) for l in log_s]
L_target = ZZ(int(log_target * scaler))

M = matrix(ZZ, 1, dim+1, L + [1])
b = [L_target]

Kmax = 1000  
Emax = 100

lb = [0] * dim + [-Emax]
ub = [Kmax] * dim + [ Emax]

solution = solve_bounded(M, b, lb, ub)
coeffs = list(solution[:dim])
eps = solution[-1]

print("coeffs:", coeffs)
print("eps:", eps)

test = 1
for coeff, (m, s, h) in zip(coeffs, samples) :
    test = (test * pow(h, coeff, N))

assert long_to_bytes(test)[:8] == actual_h

forged = 1
for coeff, (m, s, h) in zip(coeffs, samples) :
    forged = (forged * pow(s, coeff, N)) % N

r.sendlineafter(b"s: ", hex(forged))

end = time() - start
print(f"That took {end} s")

r.interactive()
```

{{< /details >}}

After consulting with the author, turns out this is an unintended way of solving which i figured since i only used 30 of the 96 given output to solve it!

Although the author didn't intend for it, it turns out to be a great challenge and made me learn how to do Integer Linear Programming and add it to my toolkit! :D