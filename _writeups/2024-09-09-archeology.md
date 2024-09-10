---
layout: post
title: Archeology
subtitle: CSAW QUALS 2024
tags: [writeups,Reversing,CSAW QUALS 2024]
comments: true

ctf: CSAW QUALS 2024
level: 8 
date: 2024-09-07      
category: Reversing
note: VM              
---

# 문제 소개
이집트 상형기호로 암호화된 ``message.txt``가 존재하며 복호화를 요구하는 문제이다.
![message.txt](/assets/img/writeups/202409/1egypt.jpg)


# 코드 해석
사용자에게 입력을 받아 크게 3단계의 암호화 단계를 거치므로, 각 과정을 역산하면 ``Flag``를 구할 수 있다.
1. ``washing_machine``
2. ``key`` 생성 -> ``runnnn(key)``
3. ``washing_machine``
~~~cpp
if ( argc == 2 )
  {
    v18 = 0xDDCCBBAA;
    v19 = 0xEE;
    s = (char *)argv[1];
    s_len = strlen(s);
    index = 0;
    printf("Encrypted data: ");
    washing_machine(s, s_len);
    for ( i = 0; i < s_len; ++i )
    {
      key[index] = 0;
      key[index + 1] = 1;
      ...
    }
    key[index] = 7;
    runnnn((__int64)key);                       // vm
    washing_machine((char *)memory, s_len);
    stream = fopen("hieroglyphs.txt", "r");
    if ( stream )
    {
      for ( k = 0; fgets(&egypt_chars[256 * (__int64)k], 256, stream) && k <= 255; ++k )
        *((_BYTE *)&savedregs + 256 * (__int64)k + strcspn(&egypt_chars[256 * (__int64)k], "\n") - 75568) = 0;
      fclose(stream);
      for ( m = 0; m < s_len; ++m )
        printf("%s", &egypt_chars[256 * (unsigned __int64)memory[m]]);
      ...
~~~

# PoC

## Washing Machine
``Washing_machine``의 경우 배열에 대한 간략한 순서 치환 알고리즘이므로 아래와 같이 역산 코드를 작성할 수 있다.

~~~python
def washing_machine(s,s_len):
    for j in range((s_len>>1) - 1, -1, -1):
        s[j], s[s_len - j - 1] = s[s_len - j - 1], s[j]
    for i in range(s_len-1, 0, -1):
        s[i] = s[i] ^ s[i-1]
    return s
~~~
## runnnn(key)
이 함수는 일종의 ``VM``으로, 먼저 생성된 ``key``를 2바이트, 3바이트씩 읽으며 값에 따라 연산을 한 후, 그 값을 ``memory`` 배열에 ``return``한다.  
~~~cpp
i = 0;
  boolean_t = 1;
  while ( boolean_t )
  {
    ii = i++;
    chr = *(_BYTE *)(ii + key);
    LODWORD(v2) = chr;
    switch ( chr )
    {
      case 0u:
        v14 = *(_BYTE *)(i + key);
        v3 = i + 1;
        i += 2;
        v4 = *(_BYTE *)(key + v3);
        LODWORD(v2) = v14;
        regs[v14] = v4;
        break;
      case 1u:
        v15 = *(_BYTE *)(i + key);
        v5 = i + 1;
        i += 2;
        v23 = *(_BYTE *)(v5 + key);
        LODWORD(v2) = v15;
        regs[v15] ^= regs[v23];
        break;
        ...
      case 4u:
        v17 = *(_BYTE *)(i + key);
        v8 = i + 1;
        i += 2;
        v2 = *(unsigned __int8 *)(v8 + key);
        memory[v2] = regs[v17];
        break;
      case 5u:
        v18 = *(_BYTE *)(i + key);
        v9 = i + 1;
        i += 2;
        v22 = *(_BYTE *)(v9 + key);
        LODWORD(v2) = v18;
        regs[v18] = memory[v22];
        break;
      ...
    }
~~~   

그러므로 이러한 방식으로 디스어셈블리를 작성하여 어떻게 작동하는지 파악한다. 

~~~python
def vm(key):
    i =0
    while i<len(key)-1:
        v0 = key[i+0]
        v1 = key[i+1]
        v2 = key[i+2]
        print(v0,end =' : ')
        match v0:
            case 0:
                print(f"regs[{v1}] = {v2}")
            case 1:
                print(f"regs[{v1}] ^= regs[{v2}]")
            case 2:
                print(f"regs[{v1}] << {v2}")
            case 3:
                print(f"regs[{v1}] = sbox[regs[{v1}]]")
                i = i - 1
            case 4:
                print(f"memory[{v2}] = regs[{v1}]")
            case 5:
                print(f"regs[{v1}] = memory[{v2}]")
            case 6:
                print("putchar")
            case 7:
                print("break")
            case 8:
                print(f"regs[{v1}] >> {v2}")
            case _:
                print("error")
        i +=3
key = generate_key(v18)
vm(key)
~~~  
각 ``i``에 대해 아래와 유사한 동작을 반복하므로, 근거하여 역산 코드를 작성할 수 있다. (부록 참조)
~~~python
memory[i] = regs[1]
regs[1] = s[61]
regs[0] = 170
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 187
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 204
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 221
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 238
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 170
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 187
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 204
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 221
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
regs[0] = 238
regs[1] >> 3
regs[1] = sbox[regs[1]]
regs[1] ^= regs[0]
regs[1] << 3
~~~

# 부록
## opcode.py
~~~python
def generate_key(v18):
    key = []
    s_len = 74 #74
    index = 0

    for i in range(s_len):
        key.append(0)        # key[index] = 0
        key.append(1)        # key[index + 1] = 1
        inndex2 = index + 2
        index3 = index + 3

        key.append(f"s[{i}]")  # key[inndex2] = s[i]

        for j in range(10):
            key.extend([0, 0])  # key[index3] = 0, key[index3 + 1] = 0
            
            # Simulate the v18 access like *((_BYTE *)&v18 + (10 * i + j) % 5)
            v18_byte = v18[(10 * i + j) % 5]
            key.append(v18_byte)

            # Fixed values from the pattern in the inner loop
            key.extend([8, 1, 3, 3, 1, 1, 1, 0, 2, 1])

            index3 += 14
            key.append(3)  # key[v5] = 3

        key.append(4)        # key[index3] = 4
        key.append(1)        # key[index3 + 1] = 1
        v6 = index3 + 2
        index = index3 + 3

        key.append(f"i:{i}")        # key[v6] = i

    key.append(7)            # key[index] = 7

    return key

def vm(key):
    i =0
    while i<len(key)-1:
        v0 = key[i+0]
        v1 = key[i+1]
        v2 = key[i+2]
        print(v0,end =' : ')
        match v0:
            case 0:
                print(f"regs[{v1}] = {v2}")
            case 1:
                print(f"regs[{v1}] ^= regs[{v2}]")
            case 2:
                print(f"regs[{v1}] << {v2}")
            case 3:
                print(f"regs[{v1}] = sbox[regs[{v1}]]")
                i = i - 1
            case 4:
                print(f"memory[{v2}] = regs[{v1}]")
            case 5:
                print(f"regs[{v1}] = memory[{v2}]")
            case 6:
                print("putchar")
            case 7:
                print("break")
            case 8:
                print(f"regs[{v1}] >> {v2}")
            case _:
                print("error")
        i +=3

v18 = [0xaa,0xbb,0xcc,0xdd,0xee]  
key = generate_key(v18)
vm(key)
~~~
## PoC.py
~~~python
def rotate_right(value, shift, bit_size=8):
    return ((value >> shift) | (value << (bit_size - shift))) & ((1 << bit_size) - 1)

def rotate_left(value, shift, bit_size=8):
    return ((value << shift) | (value >> (bit_size - shift))) & ((1 << bit_size) - 1)

def read_file(file):
    with open(file,'r',encoding='utf-8') as f:
        data = f.read()
    return data

def get_memory(dict, msg):
    result = []
    for i in range(len(msg)):
        for j in range(len(dict)):
            if msg[i] == dict[j]:
                result.append(j)
    return result

def washing_machine(s,s_len):
    for j in range((s_len>>1) - 1, -1, -1):
        s[j], s[s_len - j - 1] = s[s_len - j - 1], s[j]
    for i in range(s_len-1, 0, -1):
        s[i] = s[i] ^ s[i-1]
    return s

def vm(memory):
    regs = [0,0]
    s = [0] * 74
    with open('sbox.dump','rb') as f:
        data = f.read()
    sbox = {i:data[i] for i in range(256)}
    inverse_sbox = {v: k for k, v in sbox.items()}

    for i in range(73,-1,-1):
        regs[1] = memory[i]
        for _ in range(2):  
                for value in [238, 221, 204, 187, 170]:
                    regs[0] = value
                    regs[1] = rotate_right(regs[1], 3) 
                    regs[1] ^= regs[0]
                    regs[1] = inverse_sbox[regs[1]]
                    regs[1] = rotate_left(regs[1], 3)
                    
        s[i] = regs[1]
    return s
     
if __name__=="__main__":
    s_len = 74
    egypt_dictionary_raw = read_file('hieroglyphs.txt')
    egypt_dictionary = []
    for line in egypt_dictionary_raw:
        if line!='\n':
            egypt_dictionary.append(line) # 256
    message = read_file('message.txt') # 74
    
    memory = get_memory(egypt_dictionary,message)
    memory = washing_machine(memory,s_len)
    s = vm(memory)
    s = washing_machine(s,s_len)
    for ss in s:
        print(chr(ss),end='')
~~~