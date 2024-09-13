---
layout: post
title: CSAW CTF QUALS 2024 
subtitle: Archeology, Obfuscation, Magic Tricks
thumbnail-img: /assets/img/writeups/202409/1egypt.jpg
tags: [Writeup, Reversing]
comments: true
ctf: CSAW QUALS 2024
color: #e6e6fa
date: September 6 2024
probs:
  - [Magic Tricks, 1, Reversing, Golang]
  - [Alcheology, 8, Reversing, VM]
---

2024년 9월 6일부터 7일까지 48시간 간 진행된 `CSAW CTF QUALS 2024`에 `Team jejufork`로 참여하였다.
{% include problems.html probs=writeup.probs %}

# Magic Tricks
어떤 입력값을 주어야 문제에 주어진 `output.txt`을 만들 수 있는지 찾는 문제이다. Golang 리버싱을 요구한다.

![gopher](/assets/img/writeups/202409/2gopher.jpg)

</br>

## 코드 분석
`main` 함수가 존재하지 않고 `start` 또한 메인 로직과 크게 관련이 없다. 이외에도 기타 함수의 수와 종류를 보았을 때 `Golang`으로 작성한 파일로 추정된다. 
`Enter any data...`를 `String Search`하면 `sub_48BA80`이 메인 로직임을 알 수 있다. ~~라고 생각했는데 `ida` 최신 버전을 사용하니까 main.main으로 바로 매칭도 해주고 서브루틴 분석도 구 버전과 차이가 많이 난다.~~
사용자 입력 값에 대하여 각각 연산을 한 후 ``output.txt``를 작성하는 로직임을 확인할 수 있다.
~~~cpp
// main.main
void __fastcall main_main()
{
  ...
  fmt_Fprint(
    (unsigned int)off_4CA118,
    qword_541A90,
    (unsigned int)v81,
    1,
    1,
    (unsigned int)&off_4C9C28,                  // "Enter data: "
    v20,
    v21,
    v22,
    v70,
    v71);
  len_str = bufio__ptr_Reader_ReadString(v88, 10LL);
  str = runtime_stringtoslicerune((unsigned int)&v76, len_str, 9, 1, 1, v24, v25, v26, v27, v70, v71, (__int64)v72.ptr);
  for ( i = 0LL; len_str > i; ++i )
  {
    str_char = *(_DWORD *)(str + 4 * i);        // 입력 글자 한글자 당 4바이트 단위로 저장
    n0 = str_char;
    n1 = (2LL * (str_char - 1)) ^ (str_char + 23LL);
    n2 = (n1 + ((unsigned __int64)(n1 >> 63) >> 62)) & 0xFFFFFFFFFFFFFFFCLL;
    n3 = n1 % 4 + 2 * n0 - 32;
    *(_DWORD *)(str + 4 * i) = n3;
  }
  
  ...
  v64 = os_WriteFile((int)"output.txt", 10, v58, v53, v59, 420, v61, v62, v63, v70, v71, v72, v73);
  ...
}
~~~

</br>

## PoC
~~~python
def decode(data):
    dictionary = []
    for i in range(0,255):
        n0 = i
        n1 = (2 * (i - 1)) ^ (i + 23);
        #n2 = (n1 + ((n1 >> 63) >> 62)) & 0xFFFFFFFFFFFFFFF;
        n3 = n1 % 4 + 2 * n0 - 32
        dictionary.append(n3)  
    result  = ''
    for ch in data:
        print(ch)
        for i in range(0,255):
            if ord(ch)==dictionary[i]:
                result += (chr(i))
    return result
if __name__=='__main__':
    with open('output.txt','r',encoding='utf-8') as f:
        data = f.read()
    flag = decode(data)
    print(flag)
~~~

</br>

# Archeology
이집트 상형기호로 암호화된 ``message.txt``가 존재하며 복호화를 요구하는 문제이다. 암호화 로직에 VM이 포함되어 있다.

![message.txt](/assets/img/writeups/202409/1egypt.jpg)

</br>

## 코드 해석
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

</br>

## PoC

### Washing Machine
``Washing_machine``의 경우 배열에 대한 간략한 순서 치환 알고리즘이므로 아래와 같이 역산 코드를 작성할 수 있다.

~~~python
def washing_machine(s,s_len):
    for j in range((s_len>>1) - 1, -1, -1):
        s[j], s[s_len - j - 1] = s[s_len - j - 1], s[j]
    for i in range(s_len-1, 0, -1):
        s[i] = s[i] ^ s[i-1]
    return s
~~~

</br>

### runnnn(key)
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

</br>

VM의 케이스 별 `opcode`는 각각 아래의 `case {n}` 으로 표현 가능하며, 이를 이용하여 디스어셈블리를 작성한다. 

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

</br>

작성한 디스어셈블리를 보고, 각 ``i``에 대해 아래와 유사한 동작을 반복하는 것을 확인하였다. 근거하여 역산 코드를 작성할 수 있다. (부록 참조)
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
</br>

## 부록
### opcode.py
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
</br>

### PoC.py
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