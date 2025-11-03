---
title: "l3akctf2025 — Dual MT DRBG"
date: 2025-07-21
tags: ["ctf", "crypto", "MT19937", "linear algebra"]
draft: false
showHero: true
heroStyle: "background"
---

{{< katex >}}

# l3akctf2025 - Dual MT DRBG

Recently i participated in l3akctf2025, and during the CTF I mainly focused on doing the cryptography challenges. I managed to solve the least-solved challenge in this category, "Dual MT DRBG".

---
## Source Code:


{{< details summary="server.py" >}}

```python
from random import Random
from flag import FLAG
import os
r1 = Random()
r1.seed(os.urandom(32))
r2 = Random()
r2.seed(os.urandom(32))


print("Dual Mersenne Twister Deterministic Random Bit Generator")
num_words = int(input("n="))
if num_words > 100000:
    print("Network bandwidth doesnt grow on trees!")
    exit(1)

L = []
for i in range(num_words):
    v1 = r1.getrandbits(32)
    v2 = r2.getrandbits(32)
    # break symmetry by rotating v2
    L.append((v1 + (v2 ^ ((v2 >> 1) | (v2 & 1) << 31))) & 0xffffffff)
print("L="+str(L))

print("Recover the states of r1 and r2 to get the flag.")
print("Enter the next 624 outputs of r1:")
for i in range(624):
    v1 = int(input("v1="))
    if v1 != r1.getrandbits(32):
        print("Incorrect guess")
        exit(1)

print("Now enter the next 624 outputs of r2:")
for i in range(624):
    v2 = int(input("v2="))
    if v2 != r2.getrandbits(32):
        print("Incorrect guess")
        exit(1)

print("Congratulations, here is the flag:", FLAG)
```

{{< /details >}}

The core of the challenge involves two independent instances of Python's `Random`, which we can refer to as `r1` and `r2`.

The server provides us with a sequence of outputs. for each step, it generates an integer `a_i` from `r1` and another integer `b_i` from `r2`. These are then combined using the following formula to produce the output `o_i` that we receive:

$$ o_i = (a_i + (b_i \oplus \text{ROR}(b_i, 1))) \pmod{2^{32}} $$

Where:
* `a_i` is the i-th output of `r1`.
* `b_i` is the i-th output of `r2`.
* `\oplus` denotes the bitwise XOR operation.
* `\text{ROR}(b_i, 1)` represents a **32-bit circular right shift** of `b_i` by one position. The expression `(b_i >> 1) | (b_i & 1) << 31` in the source code is a common Python implementation of this operation.

We can query the server for up to 99,999 of these consecutive `o_i` values.

Given this stream of `o_i` values, our task is to predict the next 624 outputs from `r1` and `r2`.

## Initial Thoughts

This challenge actually seems rather straightforward to me, since Python's `random` under the hood uses MT19937, which is a linear PRNG. The challenge becomes how to actually get equations from the output, considering 32-bit integer addition is not linear over GF(2)

> Linear here means linear over the finite field GF(2). For the rest of this write-up, "addition" refers to the bitwise XOR operation, and "multiplication" refers to standard integer multiplication, unless stated otherwise.

## The Linearity of MT19937

Okay, but before going into the solver, I will first cover these points:
1. What does "linear" even mean?
2. How do we know MT19937 is linear?
3. How can we model it using linear algebra?

---

### What does "linear" even mean?

For this write-up, I will be referring to and using the Python MT19937 implementation from this GitHub repository: [tliston/mt19937](https://github.com/tliston/mt19937).

And for the rest of this writeup we will be mostly working with the 'state' which refers to the internal 624 * 32 bit state of the MT, not the output of the MT.

The concept of linearity is easy enough: a transformation `T` is linear if `T(a + b) = T(a) + T(b)` for all `a` and `b`. One nice thing about linear transformations is that they can be represented as matrices. Working with matrices is desirable because we can easily add, compose, or inverse them, among many other things. Another key property to note is that a composition of linear transformations is also linear.

In the context of a PRNG, when we say it is "linear," we mean that its outputs are generated via a linear transformation applied to its internal state.

### How do we know MT19937 is linear?

Well, we could just test it by generating a random state and verifying if `T(a + b) = T(a) + T(b)`. This can be confirmed with the following Python code:

```python
from mt19937 import mt19937
from tqdm import trange
import random

correct = True
for _ in trange(10000) :
    s1 = [random.getrandbits(32) for _ in range(624)]
    s2 = [random.getrandbits(32) for _ in range(624)]
    s3 = [a ^ b for a, b in zip(s1, s2)]

    r1, r2, r3 = mt19937(0), mt19937(0), mt19937(0)
    r1.MT = s1
    r2.MT = s2
    r3.MT = s3

    for i in range(624) :
        if r1.extract_number() ^ r2.extract_number() != r3.extract_number() :
            correct = False
print(correct)
```

Another way of looking at it is by examining the transformations themselves. In the MT19937 algorithm, there are two core transformations: the **twist** (for state transition) and the **temper** (part of `extract_number` in the example code). Both of these are composed of only XORs and bitwise shift instructions, which are linear operations over GF(2). Since the composition of linear operations is also linear, we can conclude that the entire process is linear.

### How can we model it using linear algebra?

Now that all that is done, how do we transform the bitwise mess into linear algebra? The way to do that is by first modeling each bitwise transformation as a matrix multiplication over GF(2), and then composing them by multiplying their corresponding matrices.

This process is modeled as such in SageMath, using vectors and matrices over GF(2). If you're confused on why the shift matrices is as it is, i advise you to print them out and do the matrix multiplication in your head, it should make sense.

{{< details summary="bitwise_sage.py" >}}

```python
from sage.all import GF, vector, Matrix, identity_matrix

F = GF(2)

def int_to_vec(n: int, num_bits: int = None):
    """Convert an integer to a GF(2) vector representation with optional bit width."""
    if num_bits is None:
        num_bits = n.bit_length() or 1
    bits = [(n >> i) & 1 for i in range(num_bits)]
    return vector(F, bits[::-1])

def vec_to_int(v):
    """Convert a GF(2) vector back to an integer."""
    bits = list(v)
    return sum(int(b) << (len(bits) - 1 - i) for i, b in enumerate(bits))

def xor(v1, v2):
    """Bitwise XOR (^) of two GF(2) vectors."""
    return v1 + v2  # In GF(2), addition is the same as XOR

def left_shift_matrix(n, shift_amount):
    """Generate the transformation matrix for a bitwise left shift operation by shift_amount."""
    M = Matrix(F, n, n)
    
    for i in range(n - shift_amount):
        M[i, i + shift_amount] = 1

    return M

def right_shift_matrix(n, shift_amount):
    """Generate the transformation matrix for a bitwise right shift operation by shift_amount with truncation."""
    M = Matrix(F, n, n)
    
    for i in range(shift_amount, n):
        M[i, i - shift_amount] = 1

    return M
```

{{</ details >}}

Okay, that's all good for the `temper` part, but what about the `twist`? Well, you probably could come up with the matrix by hand, but I'm too lazy to do that. Luckily, there's another way to do it using what I like to call the **bit contribution** concept.

The MT19937 internal state consists of 624 32-bit numbers, so we can model the entire state as a single vector of `624 * 32 = 19968` bits. When we multiply a vector by a matrix in GF(2), we can think of the columns of the matrix as the "contribution" of each input bit to the final output vector. For example, for a matrix `M`, the element at row 7, column 10 represents the contribution of the 10th input bit to the 7th output bit.

To formalize this, let **v** be the input state vector, **M** be the linear transformation (twist) matrix, and **w** be the resulting state vector. The operation is simply **w = Mv**.

To find a specific column of **M**, say the j-th column, we can feed the transformation function a standard basis vector **e<sub>j</sub>**. This is a vector that has only the j-th bit set to 1, and all other bits set to 0. The output of this operation will be the j-th column of the matrix **M**:

$$\text{column}_j(M) = M \cdot e_j = M \cdot \begin{pmatrix} 0 \\ \vdots \\ 1 \\ \vdots \\ 0 \end{pmatrix} \leftarrow \text{j-th position}$$

The problem we're facing is that we have a function that performs the transformation, but we want to model it as a matrix. We can do exactly what the math above describes: for each bit position, we create a vector with only that single bit active and transform it. The resulting vector is the "bit contribution" for that position, which gives us one column of the transformation matrix. By repeating this for every possible bit index (from 0 to 19967), we can recover the entire transformation matrix.

This is done using this C code:

{{< details summary="twist.c" >}}

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// MT19937 Constants
#define W 32
#define N 624
#define M 397
#define R 31
#define A 0x9908B0DF
#define UPPER_MASK 0x80000000
#define LOWER_MASK 0x7FFFFFFF

#define N_BITS (N * W) // 19968

void bitwise_twist(uint32_t mt[]) {
    for (int i = 0; i < N; ++i) {
        uint32_t x = (mt[i] & UPPER_MASK) + (mt[(i + 1) % N] & LOWER_MASK);
        uint32_t xA = x >> 1;
        if ((x % 2) != 0) {
            xA ^= A;
        }
        mt[i] = mt[(i + M) % N] ^ xA;
    }
}

void bitvec_to_numbers(const uint8_t bitvec[], uint32_t numbers[]) {
    for (int i = 0; i < N; ++i) {
        numbers[i] = 0;
        for (int k = 0; k < W; ++k) {
            if (bitvec[i * W + k]) {
                numbers[i] |= (1UL << (W - 1 - k));
            }
        }
    }
}

void numbers_to_bitvec(const uint32_t numbers[], uint8_t bitvec[]) {
    for (int i = 0; i < N; ++i) {
        for (int k = 0; k < W; ++k) {
            bitvec[i * W + k] = (numbers[i] >> (W - 1 - k)) & 1;
        }
    }
}

int main() {
    printf("Starting empirical recovery of the %dx%d MT19937 twist matrix in C.\n", N_BITS, N_BITS);
    printf("This will be significantly faster than Python...\n");

    size_t packed_row_size = N_BITS / 8;
    size_t matrix_size = N_BITS * packed_row_size;

    uint8_t *T = (uint8_t *)malloc(matrix_size);
    if (T == NULL) {
        perror("Failed to allocate memory for matrix T");
        return 1;
    }

    memset(T, 0, matrix_size);

    uint8_t *current_col = (uint8_t *)malloc(N_BITS);
    if (current_col == NULL) {
        perror("Failed to allocate memory for column vector");
        free(T);
        return 1;
    }

    uint32_t temp_mt_state[N];

    // --- Main Recovery Loop ---
    for (int j = 0; j < N_BITS; ++j) {
        memset(current_col, 0, N_BITS);
        current_col[j] = 1;

        bitvec_to_numbers(current_col, temp_mt_state);
        bitwise_twist(temp_mt_state);
        numbers_to_bitvec(temp_mt_state, current_col); // `current_col` now holds the output vector

        // Place this output column into the j-th column of the packed matrix T.
        for (int i = 0; i < N_BITS; ++i) {
            if (current_col[i] == 1) {
                // Calculate the position in the packed array for T[i][j]
                size_t byte_index = (size_t)i * packed_row_size + (j / 8);
                uint8_t bit_mask = (1 << (j % 8));
                T[byte_index] |= bit_mask;
            }
        }
        
        if ((j + 1) % 500 == 0) {
            double progress = (double)(j + 1) / N_BITS * 100.0;
            printf("Progress: %d / %d columns recovered (%.2f%%)\n", j + 1, N_BITS, progress);
        }
    }

    printf("Matrix recovery complete. Saving to 'matrix.txt'...\n");

    // --- Save Matrix to File ---
    FILE *fp = fopen("matrix.txt", "w");
    if (fp == NULL) {
        perror("Failed to open output file");
        free(T);
        free(current_col);
        return 1;
    }

    for (int i = 0; i < N_BITS; ++i) {
        for (int j = 0; j < N_BITS; ++j) {
            size_t byte_index = (size_t)i * packed_row_size + (j / 8);
            uint8_t bit_mask = (1 << (j % 8));
            fputc((T[byte_index] & bit_mask) ? '1' : '0', fp);
        }
        fputc('\n', fp);
    }

    fclose(fp);
    free(T);
    free(current_col);

    printf("Done. The matrix has been saved to 'matrix.txt'.\n");
    return 0;
}
```

{{</ details >}}

Finally, with the matrices for both the `temper` and `twist` operations recovered, we can create our own MT19937 implementation that works entirely through matrix multiplication.

{{< details summary="Matrix Mulitiplication MT19937" >}}

```python
from bitwise_sage import *
from tqdm import tqdm, trange

N_BITS = 19968
T = Matrix(F, N_BITS, N_BITS, sparse=True)

with open('../matrix.txt', 'r') as f:
    for i, line in enumerate(tqdm(f, total=N_BITS, desc="Processing Rows", unit=" rows")):
        for j, char in enumerate(line):
            if char == '1':
                T[i, j] = 1

BIT_SIZE = 32
class symbolic_mt19937():
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    n = 624 * BIT_SIZE

    def my_int32(self, x):
        return(x & 0xFFFFFFFF)

    def __init__(self, state):
        r = BIT_SIZE - 1
        self.m = 397
        self.a = 0x9908B0DF
        self.index = self.n + 1
        self.lower_mask = (1 << r) - 1
        self.upper_mask = self.my_int32(~self.lower_mask)
        self.lower_mask = int_to_vec(self.lower_mask, BIT_SIZE)
        self.upper_mask = int_to_vec(self.upper_mask, BIT_SIZE)
        self.MT = state
        self.temper_matrix = None
        self.untemper_matrix = None
        self.xa_matrix = None
        self.is_matrix = hasattr(state, "ncols")

    def get_temper_matrix(self) :

        if self.temper_matrix != None :
            return self.temper_matrix

        mat = xor(bitwise_identity_matrix(BIT_SIZE), and_transformation_matrix(int_to_vec(self.d, BIT_SIZE)) * right_shift_matrix(BIT_SIZE, self.u))
        mat = xor(bitwise_identity_matrix(BIT_SIZE), and_transformation_matrix(int_to_vec(self.b, BIT_SIZE)) * left_shift_matrix(BIT_SIZE, self.s)) * mat
        mat = xor(bitwise_identity_matrix(BIT_SIZE), and_transformation_matrix(int_to_vec(self.c, BIT_SIZE)) * left_shift_matrix(BIT_SIZE, self.t)) * mat
        mat = xor(bitwise_identity_matrix(BIT_SIZE), right_shift_matrix(BIT_SIZE, self.l)) * mat
        self.temper_matrix = mat
        return mat
    
    def get_untemper_matrix(self) :
        if self.untemper_matrix != None :
            return self.untemper_matrix
        else :
            self.untemper_matrix = self.get_temper_matrix().inverse()
            return self.get_untemper_matrix()
        
    def temper(self, V) :
        return self.get_temper_matrix() * V
    
    def untemper(self, V) :
        return self.get_untemper_matrix() * V

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
            self.index = 0
        y = vector(GF(2), self.MT[self.index : self.index + 32])
        self.index += 32
        return vec_to_int(self.get_temper_matrix() * y)

    def twist(self):
        self.MT = T * self.MT

    def twist_long(self) :
        for i in range(0, 624):
            bit_index = i * 32
            mdexed = (bit_index + self.m * BIT_SIZE) % self.n
            bitdex = (bit_index + 33) % self.n
            if self.is_matrix :
                x = self.MT.matrix_from_columns([bit_index]).augment(self.MT.matrix_from_columns(list(range(bitdex, bitdex + 31))))
                xA = self.xA_matrix() * x.T
                xA = xA.T
                self.MT[:, bit_index:bit_index+32] = self.MT[:, mdexed : mdexed + 32] + xA
            else :
                x = self.MT[bit_index:bit_index+1].concatenate(self.MT[bitdex : bitdex + 31])
                xA = self.xA_matrix() * x
                self.MT[bit_index:bit_index + 32] = self.MT[mdexed : mdexed + 32] + xA
        
        if self.is_matrix :
            self.MT = self.MT.T

    def xA_matrix(self) :
        if self.xa_matrix :
            return self.xa_matrix
        else :
            transformation_matrix = Matrix(F, 32, 32)
            for i in range(32) :
                x = 1 << (31 - i)
                xA = x >> 1
                if(x & 1) == 1:
                    xA = xA ^ self.a
                transformation_matrix[:, i] = int_to_vec(xA, 32)
            self.xa_matrix = transformation_matrix
            return self.xA_matrix()
                
    def numbers_to_bitvec(numbers) :
        res = []
        for num in numbers :
            res.extend(list(int_to_vec(num, 32)))
        return vector(F, res)
```

{{</ details >}}

Awesome! Now all that's left is to deal with the tangled output equation:

$$o_i = (a_i + (b_i \oplus \text{ROR}(b_i, 1))) \pmod{2^{32}}$$

Let's simplify the inner term by defining `b'_i = b_i ⊕ ROR(b_i, 1)`. As we've established, this `b'_i` term is a linear transformation of `b_i` and can be represented by a matrix. The equation becomes `o_i = (a_i + b'_i) mod 2^32`. The real problem is the standard integer addition (`+`).

The problem with integer addition essentially is that the value of `o_i` at the k-th bit isn't just determined by the k-th bit of `a_i` and `b'_i`, rather it is also determined by the **carry** from the preceding bit. However, if there is no carry bit, then the operation is essentially just **XOR**. This condition of no carry bit clearly applies for the **LSB** (Least Significant Bit), meaning we can absolutely construct an equation using the output's LSB. However, for reasons I'm not 100% sure of either, getting a leak from a single position like this doesn't actually allow you to recover the whole state rather during testing, it only recovered about half of the bits.

Now, what I came up with is that if the LSB of the output is 1, then we know the carry bit is 0. Because the carry bit is 0, this means that the 2nd LSB is essentially just XOR of the 2nd LSB of `a_i` and `b'_i` as well. Then, if the output's 2nd bit is also 1, we know for sure that the carry will also be 0. This chain of logic goes on up to the MSB.

Basically, consecutive set bits from the LSB guarantee that the bits at those positions are the XORs of the `a_i` and `b'_i` bits. This allows us to recover on average 2 bits per output, and since the positions will be somewhat diverse, it does allow us to recover the state completely.

## State Recovery

For the state recovery itself, I did it by initializing the symbolic MT with an **identity matrix**. Essentially, this allows us to represent a bit from the MT output as a linear equation in terms of variables `bit0` to `bit19967` of the initial state. So in the solver, the columns of our large matrix represent each initial state bit, and the rows represent a linear combination of those bits that equals a known output bit. In other words: `row[i] • initial_state = MT_output_bit[i]`. This gives us a system of linear equations in variables `bit_0` to `bit_19967` for both the MT1 and MT2 states.

Now, one thing I haven't mentioned is that there are 31 bits from the initial state that are essentially "discarded" and not used to generate the *next* state. This is why it's called **MT19937** (since `19968 - 31 = 19937`). These 31 discarded bits just so happen to be used only in the tempering of the very first 32-bit output. This means the only way we could recover these specific bits is from the very first output of the PRNG, but this is impossible since we can only infer a few bits from that single output.

This, however, poses no problem since our goal is to **predict future outputs**, not recover the exact initial state. As long as we can recover the 19937 bits that are propagated to the next state, we can predict all future outputs. In total, this requires our system of equations to produce a matrix with a rank of **(19937 * 2)** to solve for both PRNGs.

Well, there is one problem though: `19968 x 19968` matrix multiplication is kinda slow. My symbolic `twist` function takes around 3.5 minutes to run once. Given that we recover about 2 bits per output, it would require around 20,000 outputs, which means we'd have to perform the twist operation about 32 times. The total time for twisting alone would be around 108 minutes.

During the competition, I ran with it anyway because 108 minutes really isn't *that* long. I was worried that maybe the server had some sort of timeout or rate limit, but whatever i just ran the script, prayed for no timeout and got the flag :)

{{< details summary="solve.py" >}}

```python
from sage.all import *
from pwn import *
from bitwise_sage import F, xor, right_rot_matrix
from random import getrandbits
from symbolicmt import symbolic_mt19937
from tqdm import trange, tqdm

# # Testing Code
# s1 = symbolic_mt19937.numbers_to_bitvec([getrandbits(32) for _ in range(624)])
# s2 = symbolic_mt19937.numbers_to_bitvec([getrandbits(32) for _ in range(624)])
# r1 = symbolic_mt19937(s1.__copy__())
# r2 = symbolic_mt19937(s2.__copy__())
# r1.index = 0
# r2.index = 0

# c1 = []
# c2 = []
# c3 = []
# L = []

# for i in trange(90000):
#     v1 = r1.extract_number()
#     v2 = r2.extract_number()
#     # break symmetry by rotating v2
#     L.append((v1 + (v2 ^ ((v2 >> 1) | (v2 & 1) << 31))) & 0xffffffff)
#     c1.append(v1)
#     c2.append(v2)
#     c3.append(((v2 ^ ((v2 >> 1) | (v2 & 1) << 31))) & 0xffffffff)

target = remote("34.59.96.214", 11002)
target.sendlineafter(b"n=", b"25000")
target.recvuntil(b"L=")

L = eval(target.recvline().strip().decode())

smt1 = symbolic_mt19937(identity_matrix(F, 19968))

eqmat = matrix(F, [0 for _ in range(19968 * 2)])
result = [0]

twist_count = 0

# val1 = []
# val2 = []
# val3 = [0]

rottemp = right_rot_matrix(32, 1) * smt1.get_temper_matrix()

for i, c in tqdm(list(enumerate(L))) :

    if i % 624 == 0 and i > 0 :
        print(f"Twisting for the {twist_count + 1} time")
        smt1.twist()
        twist_count += 1

    base_part = smt1.MT.submatrix(i * 32 - twist_count * 19968, 0, 32, 19968)
    current_part1 = smt1.get_temper_matrix() * base_part
    current_part2 = xor(smt1.get_temper_matrix() * base_part, rottemp * base_part)

    # val1.append(vec_to_int(current_part1 * s1))
    # val2.append(vec_to_int(current_part2 * s2))
    # val3.append(vector(list(current_part1[31]) + list(current_part2[31])).dot_product(vector(list(s1) + list(s2))))

    bits = list(map(int, bin(c)[2:].zfill(32)))

    for bit_pos in range(31, -1, -1) :
        eqmat = eqmat.stack(vector(list(current_part1[bit_pos]) + list(current_part2[bit_pos])))
        result.append(bits[bit_pos])

        if bits[bit_pos] == 0 :
            break

    if i % 1000 == 0 :
        print(eqmat.rank())
        if eqmat.rank() >= (19937) * 2 :
            break

eqech = eqmat.augment(vector(F, result)).echelon_form()

print("\n--- Analyzing the Echelon Form ---")

solution_part = eqech.column(-1)
eq_part = eqech.matrix_from_columns(range(eqech.ncols() - 1))

matrank = eq_part.rank()
num_vars = eq_part.ncols()
bits_missing = num_vars - matrank

print(f"System Rank: {matrank}")
print(f"Total Variables: {num_vars}")
print(f"Undetermined Bits (Degrees of Freedom): {bits_missing}")

pivots = eq_part.pivots()
non_pivots = sorted(list(set(range(num_vars)) - set(pivots)))

# We assume the free variables (non-pivots) are all 0
s_recovered_partial = vector(F, num_vars)

for i in trange(matrank - 1, -1, -1):
    pivot_col = pivots[i]
    val = solution_part[i]
    s_recovered_partial[pivot_col] = val

print("\n--- Verifying the Recovered State ---")

# Split the combined solution vector back into two separate state vectors
s1_recovered = s_recovered_partial[:19968]
s2_recovered = s_recovered_partial[19968:]

# Create new MT instances from the recovered states
r1_recovered = symbolic_mt19937(s1_recovered)
r2_recovered = symbolic_mt19937(s2_recovered)
r1_recovered.index = 0
r2_recovered.index = 0

print("\nGenerating outputs from the recovered state...")
recovered_outputs1 = []
recovered_outputs2 = []
test_outputs = []

for _ in range(624):
    r1_recovered.extract_number()
    r2_recovered.extract_number() 

for _ in trange(25000-624, desc="Generating from recovered state"):
    v1 = r1_recovered.extract_number()
    v2 = r2_recovered.extract_number()
    recovered_outputs1.append(v1)
    recovered_outputs2.append(v2)
    test_outputs.append((v1 + (v2 ^ ((v2 >> 1) | (v2 & 1) << 31))) & 0xffffffff)

if test_outputs == L[624:]:
    print("\nSUCCESS!")
else:
    print(f"\nFAILURE")

for i in range(624) :
    target.sendlineafter(b"v1=", str(r1_recovered.extract_number()).encode())

for i in range(624) :
    target.sendlineafter(b"v2=", str(r2_recovered.extract_number()).encode())

target.interactive()
```

{{</ details >}}