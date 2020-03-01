'''
變數命名:
message: x
signature: (r,s)
public key: (p,q,alpha,beta)
private key: (d) 
'''
import random
import math
import hashlib

random.seed()

#費曼質數測試
def miller_rabin_test(num, round):
    if num == 2:
        return True
    if num % 2 == 0:
        return False

    r, s = 0, num - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(round):
        a = random.randrange(2, num - 1)
        x = square_and_Multiply(a, s, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(r - 1):
            x = square_and_Multiply(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True

def random_prime_generator(bit_num):
    prime = ''
    while(True):
        prime = '1'
        for i in range(bit_num-2):
            prime = prime + str(random.randint(0,1))
        prime = prime + '1'
        prime = int(prime,2)    #轉換為10進位
        #Prime test
        if miller_rabin_test(prime,10):
            break
    return prime

#加速計算 y = x^h mod n
def square_and_Multiply(x, h, n):
    y = x # initial setting
    hh = bin(h)[2:]
    for i in hh[1:]:
        y = (y ** 2) % n
        if int(i) == 1:
            y = (y * x) % n
    return y

#輾轉相除法
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

#找同mod下的乘法反元素
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g == 1:
        return x % m

'''Key generation'''
#generate prime q(160bits, 頭尾皆1, 中間158bits為0或1隨機生成)
q = random_prime_generator(160)

p = 0
#generate prime p, p = q * n +1
#compute n's minimum and maximum
minimum = '1' 
minimum += ''.join(['0' for i in range(1024 - 160)])
minimum = int(minimum, 2)
maximum = '1' 
maximum += ''.join(['1' for i in range(1024 - 160)])
maximum = int(maximum, 2)

# 算n、求p 
n = None
while(True):
    n = random.randint(minimum, maximum)
    p = q * n + 1
    if(miller_rabin_test(p, 10) == True):
        break
alpha = 0
for i in range(2, p - 2):
    alpha = square_and_Multiply(i,n, p)  #alpha = h^((p − 1)/q) mod p, h用2
    if alpha != 1:
        break
d = random.randint(1,q-1)   #choose private key d(0 < d < q) in random
beta = square_and_Multiply(alpha, d, p)     #beta = alpha^d mod p
print('\npublic key:\n', 'p=',p,'\nq=',q,'\na=',alpha,'\nB=',beta)
print('\nprivate key:', d)

'''SA signature generation'''
x = input('\nEnter a message:')
KE = random.randint(1,q-1)
r = square_and_Multiply(alpha, KE, p) % q
#H(x)為40bits 16進制的str
s = hashlib.sha1(x.encode('utf-8')).hexdigest()
#H(x)轉160bits 2進制
s = bin(int(s, 16))
s = s[2:]
#H(x)轉10進制
s = int(s,2)
s = modinv(KE,q) * (s + d * r) % q
s = int(s)
print('\nsignature:\n','r = ',r,'\ns = ',s)

'''Signature verification'''
w = modinv(s,q)
#H(x)為40bits 16進制的str
s = hashlib.sha1(x.encode('utf-8')).hexdigest()
#H(x)轉160bits 2進制
s = bin(int(s, 16))
s = s[2:]
#H(x)轉10進制
s = int(s,2)
u1 = (w * s) % q
u2 = (w *r) % q
v = (square_and_Multiply(alpha,u1,p) * square_and_Multiply(beta,u2,p) % p) % q
print('\nSignature verification:')
if v == (r % q):
    print('signature is valid.')
else:
    print('signature is invalid.')
