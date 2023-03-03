#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
@Project ：Xidian-code
@File    ：RSA_attack.py
@IDE     ：PyCharm 
@Author  ：小豪
@Date    ：2022/11/3 9:58 
'''
import json

import gmpy2
from gmpy2 import invert

#读取所有的数据
def read_and_save():
    list_all = []

    for i in range(21):
        file_name = './datas/frame' + str(i)
        with open(file_name, 'r') as f:
            d = {}
            data = f.read()
            print(len(data[0:256]))
            print(len(data[256:256 * 2]))
            print(len(data[256 * 2:]))
            d['n'] = (data[0:256])
            d['e'] = (data[256:256 * 2])
            d['c'] = (data[256 * 2:])
            list_all.append(d)
    with open('data.json', 'w') as f:
        json.dump(list_all, f)


# 欧几里得算法
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# 公共模数攻击
def same_modulus(list_all):
    # 寻找公共模数
    print('公共模数攻击')
    for i in range(21):
        for j in range(i + 1, 21):
            if list_all[i]['n'] == list_all[j]['n']:
                print(i, j)
                e1 = int(list_all[i]['e'], 16)
                e2 = int(list_all[j]['e'], 16)
                n = int(list_all[j]['n'], 16)
                c1 = int(list_all[i]['c'], 16)
                c2 = int(list_all[j]['c'], 16)
                s = egcd(e1, e2)
                s1 = s[1]
                s2 = s[2]
                # 求模反元素
                if s1 < 0:
                    s1 = - s1
                    c1 = gmpy2.invert(c1, n)
                elif s2 < 0:
                    s2 = - s2
                    c1 = gmpy2.invert(c2, n)
                m = pow(c1, s1, n) * pow(c2, s2, n) % n
                result = bytes.fromhex(hex(m)[-16:]).decode()
                print(result)


# Pollard‘s p-1素数分解算法

def pp1(n):
    B = 2 ** 20
    a = 2
    for i in range(2, B + 1):
        a = pow(a, i, n)
        d = gmpy2.gcd(a - 1, n)
        if (d >= 2) and (d <= (n - 1)):
            q = n // d
            n = q * d
    return d


def pollard_resolve(list_all):
    print('Pollard法')
    index_list = [2, 6, 19]
    for i in range(3):
        N = int(list_all[index_list[i]]['n'], 16)
        c = int(list_all[index_list[i]]['c'], 16)
        e = int(list_all[index_list[i]]['e'], 16)
        p = pp1(N)
        q = N // p
        phi_of_frame = (p - 1) * (q - 1)
        d = gmpy2.invert(e, phi_of_frame)
        m = gmpy2.powmod(c, d, N)
        print('Frame', index_list[i], ':', (bytes.fromhex(hex(m)[-16:])).decode('ascii'))
    return 0


# 低指数加密

# 经过输出检测,发现Frame3,Frame8,Frame12,Frame16,Frame20采用低加密指数e=5进行加密
# 前置函数中国剩余定理
def chinese_remainder_theorem(items):
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N // n
        d, r, s = egcd(n, m)
        if d != 1:
            N = N // n
            continue
        result += a * s * m
    return result % N, N


# 低加密指数e == 5


def low_e_5(list_all):
    print('低加密指数法')
    sessions = [{"c": int(list_all[3]['c'], 16), "n": int(list_all[3]['n'], 16)},
                {"c": int(list_all[8]['c'], 16), "n": int(list_all[8]['n'], 16)},
                {"c": int(list_all[12]['c'], 16), "n": int(list_all[12]['n'], 16)},
                {"c": int(list_all[16]['c'], 16), "n": int(list_all[16]['n'], 16)},
                {"c": int(list_all[20]['c'], 16), "n": int(list_all[20]['n'], 16)}, ]
    data = []
    for session in sessions:
        data = data + [(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开五次方根
    plaintext3_8_12_16_20 = gmpy2.iroot(gmpy2.mpz(x), 5)
    print('Frame3:', bytes.fromhex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame8:', bytes.fromhex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame12:', bytes.fromhex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame16:', bytes.fromhex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame20:', bytes.fromhex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')


# 因数碰撞法
def same_factor(list_all):
    print('因数碰撞法')
    for i in range(21):
        for j in range(i + 1, 21):
            if list_all[i]['n'] == list_all[j]['n']:
                continue
            n1 = int(list_all[i]['n'], 16)
            n2 = int(list_all[j]['n'], 16)
            p = gmpy2.gcd(n1, n2)
            if p != 1:
                q1 = n1 // p
                q2 = n2 // p
                e1 = int(list_all[i]['e'], 16)
                e2 = int(list_all[j]['e'], 16)
                # print(e1, '\n',(p - 1) * (q1 - 1))
                d1 = gmpy2.invert(e1, (p - 1) * (q1 - 1))
                d2 = gmpy2.invert(e2, (p - 1) * (q2 - 1))
                c1 = int(list_all[i]['c'], 16)
                c2 = int(list_all[j]['c'], 16)
                m1 = gmpy2.powmod(c1, d1, n1)
                m2 = gmpy2.powmod(c2, d2, n2)
                print('Frame', i, ':', bytes.fromhex(hex(m1)[-16:]).decode('ascii'), sep='')
                print('Frame', j, ':', bytes.fromhex(hex(m2)[-16:]).decode('ascii'), sep='')

#Fermat攻击
import math
def pq(n):
    B = math.factorial(2 ** 14)
    u = 0
    v = 0
    i = 0
    u0 = gmpy2.iroot(n, 2)[0] + 1
    while (i <= (B - 1)):
        u = (u0 + i) * (u0 + i) - n
        if gmpy2.is_square(u):
            v = gmpy2.isqrt(u)
            break
        i = i + 1
    p = u0 + i + v
    return p


def fermat_resolve(list_all):
    for i in range(10, 14):
        N = int(list_all[i]['n'], 16)
        p = pq(N)
        print('Frame:',i,',and p=',p)


def get_content_of_frame10():
    print('Fermat法')
    p = 9686924917554805418937638872796017160525664579857640590160320300805115443578184985934338583303180178582009591634321755204008394655858254980766008932978699
    n = int(list_all[10]['n'], 16)
    c = int(list_all[10]['c'], 16)
    e = int(list_all[10]['e'], 16)
    q = n // p
    phi_of_frame10 = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi_of_frame10)
    m = gmpy2.powmod(c, d, n)
    final_plain = bytes.fromhex(hex(m)[-16:]).decode('ascii')
    print('Frame10:', final_plain, sep='')
    return 0

if __name__ == '__main__':
    with open('data.json', 'r') as f:
        list_all = json.load(f)
    # same_modulus(list_all)
    pollard_resolve(list_all)
    # low_e_5(list_all)
    #same_factor(list_all)
    # fermat_resolve(list_all)
    #get_content_of_frame10()
