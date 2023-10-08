#### Challenge Name: baby-rsa
#### Author Name: Sumit Al Khan

The problem can be summarized in two parts. The first part is applying the **GCD attack** twice to recover two pairs of `(message_reduced, modulus)`. Then those pairs are used in **Chinese Remainder Theorem** to find the actual `message`. 

Let us analyze the server script.
```python
#!/usr/local/bin/python
from Crypto.Util.number import getPrime, bytes_to_long as b2l, long_to_bytes as l2b

print("Welcome to delphi's query service!!")

primes = [getPrime(512) for _ in range(10)]

with open('flag.txt', 'rb') as f:
    flag = f.read()
    
m = b2l(flag)
assert(m.bit_length() > 1200 and m.bit_length() < 2000)

used_indices = set()
for _ in range(5):
    print('Enter 2 indices for primes to be used for RSA (eg. 0 4): ')
    i, j = map(int, input().split())
    if i in used_indices or j in used_indices or i < 0 or j < 0 or i == j:
        print('Illegal values given!!')
        exit(2)
        
    i, j = i % 10, j % 10
    
    used_indices.add(i)
    used_indices.add(j)
    
    p, q = primes[i], primes[j]
    n = p * q
    e = 0x10001
    
    ct = pow(m, e, n)
    print('n = ', n)
    print('ct = ', ct)
```

We see that the server initially generates 10 primes that are 512 bits each. Then we can interact with the server 5 times. Each interaction is of the following type : we give the server 2 indices `i, j` and the server uses $primes_i$ and $primes_j$ to use as primes for RSA to encrypt our flag. 

There is a catch though, we can't reuse any indices. Nor can we use negative indices. What benefit would have negative indices given us anyway? We know that negative indices wraps around the list in python, that is, for an array of size `n`, the index `-k` actually denotes the index `n - k`.  In that way we can reuse indices in our query. 

But is that the only way we can reuse indices? There is no checking in our code whether `i > n`. Rather the input is taken modulo `n`. In that way, we can reuse the same index `i` using `i` and `i + n` since both of them becomes `i` when reduced by `n`. 

Now that we understand how to use the same prime in two different queries, how does that help us? It helps us to factorize the RSA modulus. Let's say we use the following queries: `0 1` and `11 2`. The second query actually translates to `1 2` after being reduced modulo `n`. 
$$ n_1 = primes_0 * primes_1$$
$$ n_2 = primes_1 * primes_2$$
If we take the `GCD` of those two modulus, we get $primes_1$. 
$$ GCD(n_1, n_2) = GCD(primes_0 * primes_1, \ \ primes_1 * primes_2) = primes_1$$
Using $primes_1$, we can factorize both $n_1$ and $n_2$.  With the RSA modulus being cracked, we can now easily recover our flag ^^.

To spoil the mood, you would actually get a gibberish. Notice the following line in our server script:

```python
assert(m.bit_length() > 1200 and m.bit_length() < 2000)
```

Our RSA modulus is of 1024 bits. It means there will be losses of bits, that is, we would actually get `flag % modulus` instead of the original `flag`. That is why you got gibberish. 

What can we do in this situation? We need a modulus that is greater than 2000 bits. `Chinese Remainder Theorem` is the way to go. If we use the following pair in our `CRT`, 

$$reducedMessage_1 = flag \mod modulus_1$$
$$reducedMessage_2 = flag \mod modulus_2$$

`Chinese Remainder Thoerem` will combine the two modulus and give us a 2048 bits modulus. We are going to get $flag \mod modulus_1 * modulus_2$. This is enough as the new modulus (which is the product of previous two modulus) is more than the upper limit of flag size. 

With the idea ready at hand, the solution script can be coded easily. 

```python
from functools import reduce
from pwn import *
from Crypto.Util.number import long_to_bytes as l2b, GCD, isPrime

io = remote('45.76.177.238', 5001)

io.recvline()
io.recvline()
io.sendline(b'0 1')

n1 = int(io.recvline().decode().strip().split('= ')[1])
ct1 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'11 2')

n2 = int(io.recvline().decode().strip().split('= ')[1])
ct2 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'3 4')

n3 = int(io.recvline().decode().strip().split('= ')[1])
ct3 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'14 5')

n4 = int(io.recvline().decode().strip().split('= ')[1])
ct4 = int(io.recvline().decode().strip().split('= ')[1])

print('[+] Params collection done')

def crack(N1, N2):
    p1 = GCD(N1, N2)
    p2 = p1
    q1 = N1 // p1
    q2 = N2 // p2
    assert(isPrime(p1) and isPrime(p2)  and isPrime(q1) and isPrime(q2))
    phi1, phi2 = (p1 - 1) * (q1 - 1), (p2 - 1) * (q2 - 1)
    e = 0x10001
    d1, d2 = pow(e, -1, phi1), pow(e, -1, phi2)
    return d1, d2

d1, d2 = crack(n1, n2)
m1, m2 = pow(ct1, d1, n1), pow(ct2, d2, n2)

d3, d4 = crack(n3, n4)
m3, m4 = pow(ct3, d3, n3), pow(ct4, d4, n4)

print('[+] Cracking done.. Will start doing the CRT')

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * pow(p, -1, n_i) * p
    return sum % prod

def mul_inv(a, b):
    return pow(a, -1, b)

msg = chinese_remainder([n1, n3], [m1, m3])
flag = l2b(msg)
print(flag)
```

> Flag : **CTF_BD{i_made_this_flag_purposefully_bigger_so_that_u_are_forced_to_use_the_chinese_remainder_theorem_otherwise_it_would_be_too_easy_if_it_was_just_the_gcd_attackxD}**



