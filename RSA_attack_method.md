# RSA大礼包

## 一 摘要

有人制作了一个 RSA 加解密软件来加密数据，假设我们截取了所有的数据帧，题目要求我们根据这些加密帧和关于RSA加密得基本原理以及数论知识，分析出这些数据帧中存在的加密漏洞，求解出原数据以及RSA参数。我们在分析过加密帧后决定使用RSA共模攻击、pollard、低加密指数法、因数碰撞法、Fermat攻击来对RSA加密进行攻击。

## 二 题目描述

Rsa是使用最为广泛的公钥密码体制，加解密过程简单易实现。但是如果使用不当，还是会带来被破译的风险。本题中假设有一个能够使用RSA加密的软件，Alice使用这个软件去进行RSA加密，当然由于Alice是初次使用，因此会造成一些漏洞，现给出Alice所有的加密帧1024bit模数*N* **|** 1024bit加密指数*e* **|** 1024bit密文*m* *e* mod *N，*而我们要做的就是分析这些加密帧来实现原文的破译以及相关参数的破译，题目给出的提示为Alice可能会重复发送同一明文分片。具体的加密方法：首先将密文分为8个字符的分片，即64bit，其次将每段分片填充为512bit，*填充规则为高位 添加 64 比特标志位，随后加上 32 比特通信序号，再添加若干 个 0，最后 64 比特为明文分片字符对应的 ASCII 码。

## 三 解密过程

### 1.数据预处理

首先将所有的加密帧数据都读取并提取出三部分*模数*N、加密指数e、以及密文，转化成列表里包含三元组的形式，接着将其保存为data.json文件以供后面读取。

```python
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
```

### 2.因数碰撞法

#### 方法原理&操作方法：

对于截取的21个数据帧，我们两两计算它们的最大公因数,若结果不唯一，得出的结果则为两个N的其中一个大质数之一，之后我们使用相应的N1、N2即可算出另外的大质数，这样就得到了p和g,紧接着根据rsa原理还原出d即可对相应的加密帧进行解密。

```python
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
                print(e1, '\n',(p - 1) * (q1 - 1))
                d1 = gmpy2.invert(e1, (p - 1) * (q1 - 1))
                d2 = gmpy2.invert(e2, (p - 1) * (q2 - 1))
                c1 = int(list_all[i]['c'], 16)
                c2 = int(list_all[j]['c'], 16)
                m1 = gmpy2.powmod(c1, d1, n1)
                m2 = gmpy2.powmod(c2, d2, n2)
                print('Frame', i, ':', bytes.fromhex(hex(m1)[-16:]).decode('ascii'), sep='')
                print('Frame', j, ':', bytes.fromhex(hex(m2)[-16:]).decode('ascii'), sep='')
```

#### 结果

```python
因数碰撞法：
Frame1:. Imagin
Frame18:m A to B
```

### 3.共模攻击

#### 方法原理&操作方法：

若两个相同的明文加密时使用了相同n，但是使用的不同的e，则会出现以下情况：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps1.jpg) 

当e1于e2互素时，根据欧几里得原理，我么能够相应的s1与s2使得：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps2.jpg) 

之后就可利用c1^s1与c2^s2计算得到m，即：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps3.jpg) 

####  具体代码：

```python
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
```

#### 结果

```
代码结果：
共模攻击
Frame0:My secre
Frame4:My secre
```

### 4.低指数加密

#### 方法原理&操作方法：

在 RSA 中 e 也称为加密指数。由于 e 是可以随意选取的，选取小一点的 e 可以缩短加密时间（比如 3），但是选取不当的话，就会造成安全问题。当 e=3 时，如果明文过小，导致明文的三次方仍然小于 n，那么通过直接对密文三次开方，即可得到明文。通过我们的观察发现，Frame3,Frame8,Frame12,Frame16,Frame20采用低加密指数e=5进行加密。假定它们发送的明文是相同的，我们能得到：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps4.jpg) 

根据中国剩余定理，我们能计算出：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps5.jpg) 

明文m一定小于每个n，所以把求得的结果直接开5次方根就能得到明文m了。

#### 具体代码

```python
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

# 中国剩余定理
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
```

#### 代码结果：

```
低加密指数法
Frame3:t is a f
Frame8:t is a f
Frame12:t is a f
Frame16:t is a f
Frame20:t is a f
```

### 5.Fermat攻击

#### 原理&操作方法：

#### 当我们使用RSA时，选取的p和q相差不是特别大的话，譬如|p-q| < N^(1/4)，我们可以通过费马分解把p、q求出来，原理如下：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps6.jpg) 

由于p、q相差不大，所以p-q相对于n和（p+q）^2来说可以忽略不计，所以有：

![img](file:///C:\Users\豪哥\AppData\Local\Temp\ksohtml4900\wps7.jpg) 

#### 具体代码：

```python
def get_content_of_frame10(p):
    print('Fermat法')
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
```

#### 结果：

```
Fermat攻击
Frame10: will get
```

### 6.Pollard p-1 分解法

#### 原理

设P|N，假设gcd（a，p）=1，由费马小定理，我们有 a^(p-1)=1 mod p,如果p-1是一些小素数的乘积，那么可以选取合适的指数B，使得a^B = 1 mod p,计算gcd（a^(B-1),N）可能得到一个因子。

#### 具体代码

```python
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
```

#### 代码结果：

```
Pollard法
Frame 2 :  That is
Frame 6 :  "Logic 
Frame 19 : instein.
```

## 总结

1. #### 首先是自己刚开始对各种进制之间的转换不是特别熟练，再用多了之后自然也就记住了

2. #### 其次各种方法的理论推导还是难度挺大的，虽然原理内容不对，但是想要理解还是花了不少时间，当然也是在网上参考了很多的博客才最终搞懂。

3. #### 根据我之前对于RSA的理解，这应该是一个非常安全的加密方法，但是在做完这个大作业之后我有了新的改观，对于任何一种加密方案我们在使用时都不能掉以轻心，都要谨慎使用。

## 参考文献

[**https://blog.csdn.net/pigeon_1/article/details/114371456**

[**https://blog.csdn.net/Mitchell_Donovan/article/details/120771960（****关于pollard算法的讲解****）**](https://blog.csdn.net/Mitchell_Donovan/article/details/120771960（关于pollard算法的讲解）)

[**https://blog.csdn.net/weixin_45859850/article/details/109785669（****低指数加密攻击的讲解****）**](https://blog.csdn.net/weixin_45859850/article/details/109785669（低指数加密攻击的讲解）)

Don Coppersmith: Finding a Small Root of a Univariate Modular 

Equation. EUROCRYPT 1996 (LNCS 1070, Springer): 155-165. 

Magma Computational Algebra System,http://magma.maths.usyd.edu.au/magma/