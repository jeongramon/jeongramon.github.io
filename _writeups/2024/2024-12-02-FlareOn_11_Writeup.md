---
layout: post
title: Flare-On 11 Writeup (1-5)
subtitle: sshd, Meme Maker 3000, aray, checksum, frog
thumbnail-img: /assets/img/writeups/202411/4.png
tags: [Writeup, Reversing]
comments: true
ctf: Flare-On 11
color: FFB6B6
ctf_date: 2024-10-27
probs:
  - [1 frog, 1, Reversing, Warming Up]
  - [2 checksum, 2, Reversing, Golang]
  - [3 aray, 3, Reversing, Yara Rule]
  - [4 Meme Maker 3000, 4, Reversing, JavaScript Obfuscation]
  - [5 sshd, 5, Reversing, CoreDump]
---

2024년 10월 27일부터 6주 간 개최된 `Flare-On 11`에 참여하였다. `Flare-On`은 `Maindiant`에서 매년 주최하는 리버싱 챌린지로, 모든 문제를 해결하면 기념 코인(메달)을 준다고 한다. 올해는 모든 문제를 해결하지 못해 아쉽고, 내년에 다시 참여해서 기념 코인을 챙겨보고 싶다.

이 글은 총 10문제 중 1번부터 5번까지를 다루며, 6번 이상부터는 [Flare-On 11 Writeup (6-8)](https://blog.jeongramon.dev/2024/2024-12-26-FlareOn_11_Writeup2/)을 참조 바란다.

{% include problems.html probs=page.probs %}

<br />

# 1. frog

`PyGame`으로 만들어진 게임 내에서 개구리를 조작하여 `11` 에 위치 시키면 플래그를 출력한다고 설명되어 있다.

![image.png](/assets/img/writeups/202411/1frog.png)

<br />

## 문제 분석 및 PoC

`flag` 출력 관련 함수 및 동작 조건이 매우 직관적이다.

```python
...
victory_tile = pygame.Vector2(10, 10)
...
def GenerateFlagText(x, y):
    key = x + y*20
    encoded = "\xa5\xb7\xbe\xb1\xbd\xbf\xb7\x8d\xa6\xbd\x8d\xe3\xe3\x92\xb4\xbe\xb3\xa0\xb7\xff\xbd\xbc\xfc\xb1\xbd\xbf"
    return ''.join([chr(ord(c) ^ key) for c in encoded])
...
		if not victory_mode:
            # are they on the victory tile? if so do victory
            if player.x == victory_tile.x and player.y == victory_tile.y:
                victory_mode = True
                flag_text = GenerateFlagText(player.x, player.y)
                flag_text_surface = flagfont.render(flag_text, False, pygame.Color('black'))
                print("%s" % flag_text)
```

<br />

필요한 부분만 발췌하여 간단히 `PoC`를 작성할 수 있다.

```python
def GenerateFlagText(x, y):
    key = x + y*20
    encoded = "\xa5\xb7\xbe\xb1\xbd\xbf\xb7\x8d\xa6\xbd\x8d\xe3\xe3\x92\xb4\xbe\xb3\xa0\xb7\xff\xbd\xbc\xfc\xb1\xbd\xbf"
    return ''.join([chr(ord(c) ^ key) for c in encoded])

flag_text = GenerateFlagText(10,10)
print("%s" % flag_text)
```

<br />

`welcome_to_11@flare-on.com`

<br />

# 2. checksum

`Go`로 작성된 것으로 보이는 `exe`가 제공되며, 실행 시 아래와 같이 사용자의 입력을 요구한다.

![image.png](/assets/img/writeups/202411/2_1.png)

<br />

## 코드 분석

메인 코드는 대략 세 부분으로 나눌 수 있다.

1. `Math Problem`
2. `Check Function`
3. `Print Flag`

<br />

### 1. Math Problem

메인 코드의 첫 부분을 보면, `for statement`가 존재하고 `a+b=?` 을 묻는. 사용자가 올바른 정답을 입력하면 `Good Math!!`를 출력 후 반복하고, 틀린 답변을 입력하면 `Try again!`을 출력하고 종료한다. 

```java
void __fastcall main_main()
{
  ...
  for ( i = 0LL; ; i = v104 + 1 )
  {
    ...
    fmt_Fprintf(21LL, &v125, (const char *)(v111 + v110), "Check sum: %d + %d = ", 2LL, 2LL);
    v124[0] = &RTYPE__ptr_int;
    v124[1] = p_int;
    fmt_Fscanf(
      3LL,
      v124,
      (const char *)p_int,
      "%d\n%s\nnil01_\\\\?adxaesshaavxfmaEOF m=125625nanNaNintmapptr...finobjgc %: gp  *(in  n= )\n -   P  MPC= < end > ]:\n???pc=  Gopenread",
      1LL,
      1LL);
    v22 = v21;
    v0 = 21;
    v24 = main_b(21LL, v124, v23, "Not a valid answer...");
    if ( *(_QWORD *)p_int != v111 + v110 )
    {
      runtime_printlock(v24, v22);
      v30 = runtime_printstring(
              (unsigned int)"Try again! ;)\nis a directoryunexpected EOFinvalid syntax1907348632812595367431640625unsafe.Pointer on zero Valueunknown methodOpenSCManagerWModule32FirstWuserArenaStateread mem statsallocfreetracegcstoptheworldGC assist waitfinalizer waitsync.Cond.Waits.allocCount= nil elem type! to finalizer GC worker initruntime: full=runtime: want=MB; allocated timeEndPeriod",
		...
    v8 = runtime_printstring(
           (unsigned int)"Good math!!!\n------------------------------\n",
    ...
  }
```

<br />

### 2. Check Function

사용자에게 새로운 입력값을 받고, 길이가 `32`인지 체크한다. 이 값은 `p_string→ptr`에 저장된다. 이 함수의 가장 중요한 부분은 `v75 = main_a(p_string->ptr, len);` 로, 사용자의 입력값이 `main_a` 내 체크 로직을 통과하여야 `1`을 `return`한다.

```cpp
...
  fmt_Fscanf(
    3LL,
    v122,
    v31,
    "%s\nnil01_\\\\?adxaesshaavxfmaEOF m=125625nanNaNintmapptr...finobjgc %: gp  *(in  n= )\n -   P  MPC= < end > ]:\n???pc=  Gopenread",
    1LL,
    1LL);
  main_b(30LL, v122, v32, "Fail to read checksum input...");
  ptr = p_string->ptr;
  ...
  if ( v45 == 32 ) //check length
  {
    p_chacha20poly1305_xchacha20poly1305 = (chacha20poly1305_xchacha20poly1305 *)runtime_newobject(&RTYPE_chacha20poly1305_xchacha20poly1305);
    if ( p_chacha20poly1305_xchacha20poly1305 != v115 )
    {
      v116 = p_chacha20poly1305_xchacha20poly1305;
      runtime_memmove(p_chacha20poly1305_xchacha20poly1305, v115, 32LL, 23LL, v46);
      p_chacha20poly1305_xchacha20poly1305 = v116;
    }
    v48 = go_itab__golang_org_x_crypto_chacha20poly1305_xchacha20poly1305_crypto_cipher_AEAD;
    v49 = 0LL;
    v50 = p_chacha20poly1305_xchacha20poly1305;
    v51 = 0LL;
  }
  ...
  if ( len == p_string->len )
  {
    len = (__int64)p_string->ptr;
    if ( (unsigned __int8)runtime_memequal(v74, p_string->ptr) )
    {
      len = p_string->len;
      v75 = main_a(p_string->ptr, len);
    }
    else
    {
      v75 = 0;
    }
  }
  else
  {
    v75 = 0;
  }
  if ( !v75 )
  {
    v120[0] = &RTYPE_string;
    v120[1] = &off_10DDAC0;
    len = os_Stdout;
    v67 = 1LL;
    fmt_Fprintln(go_itab__os_File_io_Writer, os_Stdout, v120, 1LL, 1LL);
  }
	...
```

<br />


`main_a` 은 `for statement` 안에서 사용자의 입력값에 특정 연산을 거친 다음, `base64`로 인코딩한 값이 특정 값과 같은지 확인한다.

```cpp
// main.a
__int64 __golang main_a(_BYTE *ptr, __int64 a2, __int64 a3, int a4, __int64 a5, int a6, int a7, int a8, int a9)
{
...
  for ( i = 0LL; a2 > i; ++i )
  {
    a5 = output;
    v17 = input;
    v18 = i - 11 * ((__int64)((unsigned __int128)(i * (__int128)0x5D1745D1745D1746LL) >> 64) >> 2);
    v19 = input[i];
    if ( v18 >= 0xB )
      runtime_panicIndex(v18, i, 11LL, v17);
    v10 = "FlareOn2024bad verb '%0123456789_/dev/stdout/dev/stderrCloseHandleOpenProcessGetFileTypeshort write30517578125bad argSizemethodargs(reflect.SetProcessPrngMoveFileExWNetShareAddNetShareDeluserenv.dllassistQueuenetpollInitreflectOffsglobalAllocmSpanManualstart traceclobberfreegccheckmarkscheddetailcgocall nilunreachable s.nelems=   of size  runtime: p  ms clock,  nBSSRoots=runtime: P  exp.) for minTrigger=GOMEMLIMIT=bad m value, elemsize= freeindex= span.list=, npages = tracealloc( p->status= in status  idleprocs= gcwaiting= schedtick= timerslen= mallocing=bad timedivfloat64nan1float64nan2float64nan3float32nan2GOTRACEBACK) at entry+ (targetpc= , plugin: runtime: g : frame.sp=created by broken pipebad messagefile existsbad addressRegCloseKeyCreateFileWDeleteFileWExitProcessFreeLibrarySetFileTimeVirtualLockWSARecvFromclosesocketgetpeernamegetsocknamecrypt32.dllmswsock.dllsecur32.dllshell32.dlli/o timeoutavx512vnniwavx512vbmi2LocalAppDatashort buffer152587890625762939453125OpenServiceWRevertToSelfCreateEventWGetConsoleCPUnlockFileExVirtualQueryadvapi32.dlliphlpapi.dllkernel32.dllnetapi32.dllsweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan receivelfstack.push span.limit= span.state=bad flushGen MB stacks, worker mode  nDataRoots= nSpanRoots= wbuf1=<nil> wbuf2=<nil> gcscandone runtime: gp= found at *( s.elemsize= B (";
    v11 = (unsigned __int8)aTrueeeppfilepi[v18 + 3060];
    *(_BYTE *)(a5 + i) = v11 ^ v19;
    output = a5;
    input = v17;
  }
  v20 = output;
  v21 = encoding_base64__ptr_Encoding_EncodeToString(
          runtime_bss,
          output,
          a2,
          a2,
          a5,
          (_DWORD)v10,
          v11,
          v12,
          v13,
          v24,
          v26);
  if ( v20 == 88 )
    return runtime_memequal(
             v21,
             "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==");
  else
    return 0LL;
}
```

<br />

### 3. Print Flag

특정 `path`에 `REAL_FLAREON_FLAG.JPG`를 생성하며, 이것이 `flag`와 관련 있을 것으로 유추할 수 있다.

```cpp
...
  v118.len = os_UserCacheDir();
  v108 = len;
  main_b(19LL, v67, v76, "Fail to get path...");
  length = v118.len;
  path = runtime_concatstring2(
           0,
           v118.len,
           v108,
           (unsigned int)"\\REAL_FLAREON_FLAG.JPG",
           22,
           v78,
           v79,
           v80,
           v81,
           v91,
           v96,
           v98);
  v83 = v107;
  os_WriteFile(path, length, v118.ptr, v106, v107, 420LL);
  main_b(21LL, v83, v84, "Fail to write file...");
  v119[0] = &RTYPE_string;
  v119[1] = &off_10DDAD0;
  fmt_Fprintln(go_itab__os_File_io_Writer, os_Stdout, v119, 1LL, 1LL);
}
```

<br />

## PoC

`PoC` 또한 세 단계로 나눌 수 있다.

1. `Math Problem` 우회
2. `Check Function` 통과
3. `Find Flag` 

<br />

### 1. Math Problem 우회

`Math Problem`을 포함한 `for statement`가 실행되지 않도록 한다. 아래 `cmp rcx, rsi` 에 `bp`를 설치한 다음, `rcx`와 `rsi`를 같은 값으로 패치하면 탈출이 가능하다.

```cpp
.text:000000000109791F loc_109791F:                            ; CODE XREF: main_main+4F↑j
.text:000000000109791F                 mov     rdx, [rsp+248h+var_148]
.text:0000000001097927                 lea     rsi, [rdx+3]
.text:000000000109792B                 cmp     rcx, rsi
.text:000000000109792E                 jge     loc_1097ACE
```

<br />

### 2. Check Function 통과

`main_a` 의 `Check Function`을 역산하면 올바른 입력값을 계산할 수 있다. 사용자 입력값 입력 시에 아래 역산 코드의 결과를 입력한다.

```python
import base64

encoded_string = "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="
decoded_bytes = base64.b64decode(encoded_string)
result = []
  
with open("key.dump","rb") as f:
    key = f.read()
    
for i in range(0x40):
    v18 = i - 11 * (((i * 0x5D1745D1745D1746) >> 64) >> 2)
    result.append(key[v18] ^ decoded_bytes[i])

for r in result:
    print(chr(r),end = '')
#7fd7dd1d0e959f74c133c13abb740b9faa61ab06bd0ecd177645e93b1e3825dd
```

<br />

### 3. Find Flag

`os_WriteFile(path, length, v118.ptr, v106, v107, 420LL);` 가 실행될 때 디버깅하면, `REAL_FLAREON_FLAG.JPG`가 생성되는 `path`를 확인할 수 있다. 파일을 열어보면 플래그가 있다.

![image.png](/assets/img/writeups/202411/2_2.jpg)

<br />

# 3. aray

`yara rule`이 담긴 파일이 제공된다. `rule`을 모두 만족하는 `byte array`를 구하면 `flag`를 찾을 수 있다.

```python
import "hash"

rule aray
{
    meta:
        description = "Matches on b7dc94ca98aa58dabb5404541c812db2"
    condition:
        filesize == 85 and hash.md5(0, filesize) == "b7dc94ca98aa58dabb5404541c812db2" and filesize ^ uint8(11) != 107 and uint8(55) & 128 == 0 and uint8(58) + 25 == 122 and uint8(7) & 128 == 0 and uint8(48) % 12 < 12 and uint8(17) > 31 and uint8(68) > 10 and uint8(56) < 155 and uint32(52) ^ 425706662 == 1495724241 and uint8(0) % 25 < 25 and filesize ^ uint8(75) != 25
        ...
```

<br />

## PoC

`filesize`가 `85`인 `bytearray`를 가정하고, 모든 조건을 만족하도록 한다.

```python
import re
import zlib
import hashlib

def possible32(possible_bytes,index,num):
    possible_bytes[index+3] = [num >> 24]
    possible_bytes[index+2] = [(num >> 16) & 0xFF]
    possible_bytes[index+1] = [(num >> 8) & 0xFF]
    possible_bytes[index+0] = [num & 0xFF]
def solve_uint32_condition(possible_bytes):
    #uint32(52) ^ 425706662 == 1495724241 
    possible32(possible_bytes, 52, 1495724241 ^ 425706662)
    #uint32(17) - 323157430 == 1412131772
    possible32(possible_bytes, 17, 1412131772 + 323157430)
    #uint32(59) ^ 512952669 == 1908304943
    possible32(possible_bytes, 59, 1908304943 ^ 512952669) 
    #uint32(28) - 419186860 == 959764852
    possible32(possible_bytes, 28, 959764852 + 419186860)
    #uint32(66) ^ 310886682 == 849718389 
    possible32(possible_bytes, 66, 849718389 ^ 310886682)
    #uint32(10) + 383041523 == 2448764514
    possible32(possible_bytes, 10, 2448764514 - 383041523)
    #uint32(37) + 367943707 == 1228527996
    possible32(possible_bytes, 37, 1228527996 - 367943707)
    #uint32(22) ^ 372102464 == 1879700858
    possible32(possible_bytes, 22, 1879700858 ^ 372102464)
    #uint32(46) - 412326611 == 1503714457
    possible32(possible_bytes, 46, 1503714457 + 412326611) 
    #uint32(70) + 349203301 == 2034162376
    possible32(possible_bytes, 70, 2034162376 - 349203301) 
    #uint32(80) - 473886976 == 69677856
    possible32(possible_bytes, 80, 69677856 + 473886976) 
    #uint32(3) ^ 298697263 == 2108416586 
    possible32(possible_bytes, 3, 2108416586 ^ 298697263)
    #uint32(41) + 404880684 == 1699114335 
    possible32(possible_bytes, 41, 1699114335 - 404880684)
    

def read_condition(file):
    with open(file,'r') as f:
        data = f.read()
    return data

def check_condition_8(possible_bytes,condition):
    result = []
    pattern = r'uint8\((\d+)\)'
    indices = re.findall(pattern, condition)
    indices = [int(index) for index in indices]
    if len(indices) !=1:
        return False
    index = indices[0]
    
    condition = condition.replace('(','[').replace(')',']').replace("filesize","85")
    for i in possible_bytes[index]:
        current_condition = condition.replace(f'uint8[{index}]', str(i))
        if eval(current_condition):
            result.append(i)
    possible_bytes[index] = result     
    return True

def calculate_crc32(possible_bytes,index,num):
    for i in possible_bytes[index]:
        for j in possible_bytes[index+1]:
            data = bytes([i,j])
            if zlib.crc32(data) & 0xFFFFFFFF == num:
                possible_bytes[index] = [i]
                possible_bytes[index+1] = [j]
                return True
    return False

def calculate_md5(possible_bytes,index,num):
    for i in possible_bytes[index]:
        for j in possible_bytes[index+1]:
            data = bytes([i,j])
            if hashlib.md5(data).hexdigest() == num:
                possible_bytes[index] = [i]
                possible_bytes[index+1] = [j]
                return True
    return False

def calculate_sha256(possible_bytes,index,num):
    for i in possible_bytes[index]:
        for j in possible_bytes[index+1]:
            data = bytes([i,j])
            if hashlib.sha256(data).hexdigest() == num:
                possible_bytes[index] = [i]
                possible_bytes[index+1] = [j]
                return True
    return False

def solve_hash_condition(possible_bytes):
    # hash.crc32(8, 2) == 0x61089c5c
    calculate_crc32(possible_bytes,8,0x61089c5c)
    #hash.crc32(34, 2) == 0x5888fc1b
    calculate_crc32(possible_bytes,34,0x5888fc1b)
    #hash.crc32(63, 2) == 0x66715919
    calculate_crc32(possible_bytes,63,0x66715919)
    #hash.sha256(14, 2) == "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f"
    calculate_sha256(possible_bytes,14,"403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f")
    #hash.sha256(56, 2) == "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6"
    calculate_sha256(possible_bytes, 56, "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6")
    #hash.md5(0, 2) == "89484b14b36a8d5329426a3d944d2983"
    calculate_md5(possible_bytes, 0, "89484b14b36a8d5329426a3d944d2983")
    #hash.crc32(78, 2) == 0x7cab8d64
    calculate_crc32(possible_bytes,78,0x7cab8d64)
    #hash.md5(76, 2) == "f98ed07a4d5f50f7de1410d905f1477f" 
    calculate_md5(possible_bytes,76,"f98ed07a4d5f50f7de1410d905f1477f")
    #hash.md5(50, 2) == "657dae0913ee12be6fb2a6f687aae1c7" 
    calculate_md5(possible_bytes,50,"657dae0913ee12be6fb2a6f687aae1c7")
    #hash.md5(32, 2) == "738a656e8e8ec272ca17cd51e12f558b" 
    calculate_md5(possible_bytes,32,"738a656e8e8ec272ca17cd51e12f558b")
    
    
if __name__=='__main__':
    data = read_condition('./aray.txt')
    hash_condition=[]
    arr = [i for i in range(256)]
    possible_bytes = []
    filesize = 85
    for i in range(filesize):
        possible_bytes.append(arr) 
    conditions = data.split("and")
    
    solve_uint32_condition(possible_bytes)
    
    for condition in conditions:
        if "hash" in condition:
            continue
        elif "uint32" in condition:
            continue
        elif "uint8" in condition:
            if check_condition_8(possible_bytes,condition):
                continue
            else:
                print(condition) #uint8 원소가 2개 이상 선언된 경우 => 없음
        else:
            print(condition) # => 없음
                
    solve_hash_condition(possible_bytes)
    
    for i in range(filesize):
        if len(possible_bytes[i])==1:
            print(chr(possible_bytes[i][0]),end='')
        else:
            print()
            print(i,end = ' : ')
            print(possible_bytes[i])
```

<br />

`rule flareon { strings: $f = "1RuleADayK33p$Malw4r3Aw4y@flare-on.com" condition: $f }`

<br />

# 4. Meme Maker 3000

`html`이 제공되고, 실행 시 여러 `meme`을 관람할 수 있다.

![image.png](/assets/img/writeups/202411/4.png)

<br />

## 난독화된 JavaScript

개발자 도구로 `html`을 살펴보면 `<script>`태그로 둘러싸인 난독화된 `JavaScript`를 발견할 수 있다. 

[Deobfuscater](https://deobfuscate.relative.im/)을 이용하여 난독화 해제하면 아래와 같다. 이 중 중요한 함수는 a0k로, 특정 조건을 만족하면 `Congratulations! + f` 를 `alert`하도록 되어 있다.

```javascript
const a0c = [
    'When you find a buffer overflow in legacy code',
		...
    'Security Expert',
  ],
  a0d = {
    doge1: [
      ['75%', '25%'],
      ['75%', '82%'],
    ],
    ...
    aliens: [['5%', '50%']],
  },
  a0e = {
    'doge1.png': ...
    'draw.jpg': ...
    'aliens.jpg': ...
    ...
  }
function a0f() {
  document.getElementById('caption1').hidden = true
  document.getElementById('caption2').hidden = true
  document.getElementById('caption3').hidden = true
  const a = document.getElementById('meme-template')
  var b = a.value.split('.')[0]
  a0d[b].forEach(function (c, d) {
    var e = document.getElementById('caption' + (d + 1))
    e.hidden = false
    e.style.top = a0d[b][d][0]
    e.style.left = a0d[b][d][1]
    e.textContent = a0c[Math.floor(Math.random() * (a0c.length - 1))]
  })
}
a0f()
const a0g = document.getElementById('meme-image'),
  a0h = document.getElementById('meme-container'),
  a0i = document.getElementById('remake'),
  a0j = document.getElementById('meme-template')
a0g.src = a0e[a0j.value]
a0j.addEventListener('change', () => {
  a0g.src = a0e[a0j.value]
  a0g.alt = a0j.value
  a0f()
})
a0i.addEventListener('click', () => {
  a0f()
})
function a0k() {
  const a = a0g.alt.split('/').pop()
  if (a !== Object.keys(a0e)[5]) {
    return
  }
  const b = a0l.textContent,
    c = a0m.textContent,
    d = a0n.textContent
  if (
    a0c.indexOf(b) == 14 &&
    a0c.indexOf(c) == a0c.length - 1 &&
    a0c.indexOf(d) == 22
  ) {
    var e = new Date().getTime()
    while (new Date().getTime() < e + 3000) {}
    var f =
      d[3] +
     ...
      a0c[4].substring(12, 15)
    f = f.toLowerCase()
    alert(atob('Q29uZ3JhdHVsYXRpb25zISBIZXJlIHlvdSBnbzog') + f)
  }
}
const a0l = document.getElementById('caption1'),
  a0m = document.getElementById('caption2'),
  a0n = document.getElementById('caption3')
a0l.addEventListener('keyup', () => {
  a0k()
})
a0m.addEventListener('keyup', () => {
  a0k()
})
a0n.addEventListener('keyup', () => {
  a0k()
})

```

<br />

## PoC

아래와 같이 `a0k`의 조건을 만족하도록 조작 후 `a0k`를 다시 실행하면 `flag`가 `alert`된다.

```javascript
document.getElementById('meme-template').value = 'boy_friend0.jpg';
a0g.src = a0e['boy_friend0.jpg'];  // img update
a0g.alt = 'boy_friend0.jpg';  // set alt
a0f();  // change template

// 2. 캡션 텍스트를 각각 조건에 맞게 설정
document.getElementById('caption1').textContent = 'FLARE On';  
// a0c.indexOf(b) == 14 --> 15th caption
document.getElementById('caption2').textContent = 'Security Expert';
//a0c.indexOf(c) == a0c.length - 1 --> last caption
document.getElementById('caption3').textContent = 'Malware';  // 세 번째 캡션
//a0c.indexOf(d) == 22 --> 23th caption

a0k();
```

<br />

# 5. sshd

linux filesystem dump가 주어진다. 시나리오는 다음과 같다.

> Our server in the FLARE Intergalactic HQ has crashed! Now criminals are trying to sell me my own data!!! Do your part, random internet hacker, to help FLARE out and tell us what data they stole! We used the best forensic preservation technique of just copying all the files on the system for you.

## 코어 덤프

문제에서 일반적인 로그 파일`/var/log 하위` 은 모두 지워져 있고, `journal` 관련 파일도 존재하지 않았다. 대신 문제 시나리오 상의 `server has crashed`라는 단서 조항에서 착안하여, 관련된 코어 덤프를 확인할 수 있었다. 

`sshd`와 관련된 `core dump`이므로 `gdb`로 아래와 같이 분석한다. 참고로 `ssh_container` 최상위 위치에서 반드시 `set sysroot .`를 하여야 문제에서 주어진 파일 시스템을 기반으로 `breaktrace`를 얻을 수 있다. 그렇지 않으면 로컬 호스트 파일 시스템 기반으로 `gdb`가 동작하여 제대로 된 `symbol`을 얻을 수 없다.

```
{% raw %}
[.../ssh_container]
$ gdb -c ./var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676 ./usr/sbin/sshd
(gdb) set sysroot .
(gdb) bt full
...
#1  0x00007f4a18c8f88f in ?? () from ./lib/x86_64-linux-gnu/liblzma.so.5
No symbol table info available.
...
#9  0x00007f4a18e5824a in __libc_start_call_main (main=main@entry=0x55b46c6e7d50, 
    argc=argc@entry=4, argv=argv@entry=0x7ffcc6602eb8)
    at ../sysdeps/nptl/libc_start_call_main.h:58
        self = <optimized out>
        result = <optimized out>
        unwind_buf = {cancel_jmp_buf = {{jmp_buf = {140723636678328, 7600382950360807596, 0, 
                140723636678368, 94233402840984, 139956231798816, -7601952175256176468, 
                -7499111522585741140}, mask_was_saved = 0}}, priv = {pad = {0x0, 0x0, 
              0x7ffcc6602eb8, 0x7ffcc6602eb8}, data = {prev = 0x0, cleanup = 0x0, 
              canceltype = -966775112}}}
        not_first_call = <optimized out>
#10 0x00007f4a18e58305 in __libc_start_main_impl (main=0x55b46c6e7d50, argc=4, 
    argv=0x7ffcc6602eb8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7ffcc6602ea8) at ../csu/libc-start.c:360
No locals.
#11 0x000055b46c6ec621 in ?? ()
{% endraw %}
```

<br />

`frame 0`의 `./lib/x86_64-linux-gnu/liblzma.so.5`에서 크래시가 발생하였을 것으로 추정할 수 있다. `rip` 부분의 어셈블리를 살펴보면, `call *%rax`가 문제가 발생한 파트인 듯 하다.

```
(gdb) info frame
Stack level 0, frame at 0x7ffcc6601ea0:
 rip = 0x0; saved rip = 0x7f4a18c8f88f
 called by frame at 0x7ffcc6601fd0
 Arglist at 0x7ffcc6601e90, args: 
 Locals at 0x7ffcc6601e90, Previous frame's sp is 0x7ffcc6601ea0
 Saved registers:
  rip at 0x7ffcc6601e
(gdb) x/10i 0x7f4a18c8f88f-4
   0x7f4a18c8f88b:      mov    %esp,%edi
   0x7f4a18c8f88d:      call   *%rax
   0x7f4a18c8f88f:      mov    0xe8(%rsp),%rbx
   0x7f4a18c8f897:      xor    %fs:0x28,%rbx
   0x7f4a18c8f8a0:      jne    0x7f4a18c8f975
   0x7f4a18c8f8a6:      add    $0xf8,%rsp
   0x7f4a18c8f8ad:      pop    %rbx
   0x7f4a18c8f8ae:      pop    %rbp
   0x7f4a18c8f8af:      pop    %r12
   0x7f4a18c8f8b1:      pop    %r13
```

<br />

## 크래시 분석

`info proc map`을 통해 크래시 시점의 `rip`가 `Start Addr + 0x988F`임을 알 수 있다.

```cpp
(gdb) info proc mappings
Mapped address spaces:
      Start Addr           End Addr       Size     Offset objfile
      ...
      0x7f4a18c86000     0x7f4a18c8a000     0x4000        0x0 / (deleted)
      ...
```

<br />

`ida`로 `liblzma.so.5`를 연 후 `Start Addr + 0x988F` 부분에 앞서 찾았던 `(gdb) x/10i 0x7f4a18c8f88f-4`와 동일한 어셈블리 파트가 존재한다. 이 부분의 디스어셈블리를 보면 아래와 같다. `RSA_public_decrypt`를 빙자한 백도어처럼 생겼다. 동작 구조를 대략적으로 요약하면 다음과 같다. 
1. `getuid()`, `0xC5407A48` : root 권한 및 백도어 매직 넘버 검사 
2. `sub_93F0`, `sub_9520` : `chacha20` `key, nonce` 초기화 및 `&unk_23960` 복호화
3.  `v13()` : 복호화된 데이터(백도어를 통한 원격 명령) 실행
4. `return v10(a1, a2, a3, a4, a5);` : 크래시가 발생한 포인트

```cpp
__int64 __fastcall sub_9820(unsigned int a1, _DWORD *a2, __int64 a3, __int64 a4, unsigned int a5)
{
  const char *v9; // rsi
  void *v10; // rax
  void *v12; // rax
  void (*v13)(void); // [rsp+8h] [rbp-120h]
  char v14[200]; // [rsp+20h] [rbp-108h] BYREF
  unsigned __int64 v15; // [rsp+E8h] [rbp-40h]

  v15 = __readfsqword(0x28u);
  v9 = "RSA_public_decrypt";
  if ( !getuid() )
  {
    if ( *a2 == 0xC5407A48 )
    {
      sub_93F0(v14, a2 + 1, a2 + 9, 0LL);
      v12 = mmap(0LL, dword_32360, 7, 34, -1, 0LL);
      v13 = (void (*)(void))memcpy(v12, &unk_23960, dword_32360);
      sub_9520(v14, v13, dword_32360);
      v13();
      sub_93F0(v14, a2 + 1, a2 + 9, 0LL);
      sub_9520(v14, v13, dword_32360);
    }
    v9 = "RSA_public_decrypt ";
  }
  v10 = dlsym(0LL, v9);
  return ((__int64 (__fastcall *)(_QWORD, _DWORD *, __int64, __int64, _QWORD))v10)(a1, a2, a3, a4, a5);
}
```

<br />

크래시가 발생한 부분의 `argument`는 다음과 같이 저장되므로, `a1~a5`를 다음의 레지스터에서 복구가 가능하다.

```cpp
.text:000000000000987E                 mov     r8d, ebx  //a5
.text:0000000000009881                 mov     rcx, r14  //a4
.text:0000000000009884                 mov     rdx, r13  //a3
.text:0000000000009887                 mov     rsi, rbp  //a2
.text:000000000000988A                 mov     edi, r12d //a1
.text:000000000000988D                 call    rax
```

<br />

그 중 `a2`는 `chacha20`에서 사용하는 상태 배열로 `key`와 `nonce`를 구할 수 있다. 
- 0[4] : 매직 넘버
- 4[32] :  `key`
- 8[12] : `nonce`

```cpp
(gdb) x/48bx $rsi
0x55b46d51dde0: 0x48    0x7a    0x40    0xc5    0x94    0x3d    0xf6    0x38
0x55b46d51dde8: 0xa8    0x18    0x13    0xe2    0xde    0x63    0x18    0xa5
0x55b46d51ddf0: 0x07    0xf9    0xa0    0xba    0x2d    0xbb    0x8a    0x7b
0x55b46d51ddf8: 0xa6    0x36    0x66    0xd0    0x8d    0x11    0xa6    0x5e
0x55b46d51de00: 0xc9    0x14    0xd6    0x6f    0xf2    0x36    0x83    0x9f
0x55b46d51de08: 0x4d    0xcd    0x71    0x1a    0x52    0x86    0x29    0x55
```

<br />

## 쉘코드
### 쉘코드 해석
다음과 같이 `unk_23960`을 복호화하면 쉘코드를 얻을 수 있다.

```python
from Crypto.Cipher import ChaCha20

def scd_decode():
    key_hex = "943df638a81813e2de6318a507f9a0ba2dbb8a7ba63666d08d11a65ec914d66f"
    nonce_hex = "f236839f4dcd711a52862955"
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    
    with open("scd_encoded.dump","rb") as f:
        ciphertext = f.read()
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    
    with open("scd_decoded", "wb") as f:
        f.write(plaintext)
```

<br />

대략적으로 해석했을 때, 파일을 읽어 복호화하는 형태로 보인다. `string`에 `expand 32-byte K`가 존재하므로 앞선 암호화 방식과 동일하게 `ChaCha20` 방식을 사용 중인 것으로 추측된다. `ChaCha20` 에서는 `expand 32-byte k`를 상태 초기화를 위한 고정 상수로 사용하는 특징이 있기 때문이다. 다만, `k`가 아닌 `K`로 커스터마이징이 되어있다는 점을 주목할 필요가 있다. ~~풀이하는 입장에서 너무나 사탄스러운 부분이다.~~

```cpp
void __fastcall sub_DC2()
{
  unsigned int v0; // ebx
  unsigned __int64 v1; // kr08_8
  __int64 v2; // rcx
  char v3[32]; // [rsp+410h] [rbp-1278h] BYREF
  char v4[272]; // [rsp+430h] [rbp-1258h] BYREF
  char v5[4224]; // [rsp+540h] [rbp-1148h] BYREF
  unsigned int len_cipher; // [rsp+15C4h] [rbp-C4h]

  v0 = sub_1A();                                // fd manage
  __asm
  {
    syscall; Low latency system call            // 2d - brk
    syscall; Low latency system call
    syscall; Low latency system call
    syscall; Low latency system call
  }
  v4[61] = 0;
  __asm
  {
    syscall; Low latency system call            // 2 - open   
    syscall; Low latency system call            // 0 - read
  }
  v1 = strlen(v5) + 1;
  len_cipher = v1 - 1;
  sub_CD2((__int64)&v5[v1], (__int64)v5, v3, v4, 0LL);// key_init
  sub_D49((__int64)&v5[v1], (__int64)v5, (__int64)v5, len_cipher);// decode
  __asm
  {
    syscall; Low latency system call            // 2c - getppid
    syscall; Low latency system call
  }
  sub_B(v0, v5, len_cipher, v2, 0LL, 0LL);      // 3 - close
  sub_8F(v0, v5, 0LL);                          // 30 - sys_shutdown
}
```
<br />

특히 파일을 읽고 여는 부분을 보면 `rbp-0x1248`이 `filename`, `rbp-0x1148`이 읽은 내용을 저장하는 버퍼같다.
```cpp
movsxd  rax, eax
mov     [rbp+rax+var_1248], 0
lea     rdi, [rbp+var_1248]
push    2
pop     rax
xor     esi, esi
xor     edx, edx
syscall                 ; Low latency system call
mov     r12d, eax
lea     rsi, [rbp+var_1148]
xor     eax, eax
mov     edi, r12d
mov     edx, 80h
syscall                 ; Low latency system call
```

<br />

쉘코드를 해석한 결과를 정리해보면 아래와 같다.

```cpp
초기화 문자열 : `expand 32-byte K`
v3 [rbp-1278h] : 암호화 키(32바이트)
v4 [rbp-1258h] : Nonce(12바이트)
[rbp-0x1248] : filename
[rbp-0x1148] : buffer(content)
[rbp-C4h] : len_cipher
```

<br />

### 파일 복호화
`filename (rbp-0x1248)`을 찾아보자. `v13()`이라는 함수 `call`에 의한 실행 중이었으므로 현재 `rbp`가 크래시 시점의 `rsp` 근처일 것이라고 가정하고 `0x7ffcc6601e98-0x1248` 근처의 `string search` 결과를 살펴본다.

![image.png](/assets/img/writeups/202411/5_1.jpg)

<br />

`0x7FFCC6600C18+0x1248`이 실행 시점의 `rbp`이었던 것으로 볼 수 있다. 그러므로 이를 이용하여, 암호화 키, `Nonce`, `content`, `length` 모두 구할 수 있다.

```cpp
(gdb) set $v13_rbp=0x7FFCC6600C18+0x1248
(gdb) x/44x $v13_rbp-0x1278
0x7ffcc6600be8: 0x8d    0xec    0x91    0x12    0xeb    0x76    0x0e    0xda
0x7ffcc6600bf0: 0x7c    0x7d    0x87    0xa4    0x43    0x27    0x1c    0x35
0x7ffcc6600bf8: 0xd9    0xe0    0xcb    0x87    0x89    0x93    0xb4    0xd9
0x7ffcc6600c00: 0x04    0xae    0xf9    0x34    0xfa    0x21    0x66    0xd7
0x7ffcc6600c08: 0x11    0x11    0x11    0x11    0x11    0x11    0x11    0x11
0x7ffcc6600c10: 0x11    0x11    0x11    0x11
```

<br />

`ChaCha20` 복호화(`expand 32-byte K` 커스터마이징)을 구현하고 위 변수들을 대입하면 복호화된 평문에 `flag`가 존재한다. 만약 커스터마이징된 부분이 `expand 32-byte K` 만이 아니였다면 쉘코드에 대한 추가 해석 및 구현이 필요해서 너무 복잡했을 듯하다. ~~그나마 다행이다.~~
`supp1y_cha1n_sund4y@flare-on.com` 

```python
import struct
import os

# 회전 함수 정의
def rotl32(v, n):
    return ((v << n) & 0xffffffff) | (v >> (32 - n))

# 쿼터 라운드 함수 정의
def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] ^= x[a]
    x[d] = rotl32(x[d], 16)

    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] ^= x[c]
    x[b] = rotl32(x[b], 12)

    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] ^= x[a]
    x[d] = rotl32(x[d], 8)

    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] ^= x[c]
    x[b] = rotl32(x[b], 7)

# ChaCha20 블록 함수 정의
def chacha20_block(key, counter, nonce):
    # 초기 상태 설정
    constants = (b'expand 32-byte K') #CUTOMIZED!!!!
    key = struct.unpack('<8L', key)
    nonce = struct.unpack('<3L', nonce)

    state = [
        struct.unpack('<L', constants[i:i + 4])[0] for i in range(0, 16, 4)
    ] + list(key) + [counter] + list(nonce)

    # 상태 복사본 생성
    working_state = list(state)

    # 20 라운드 진행 (10번의 더블 라운드)
    for _ in range(10):
        # 열 라운드
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        # 대각선 라운드
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    # 최종 상태 계산
    block = [(working_state[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack('<16L', *block)

# ChaCha20 암호화 함수 정의
def chacha20_encrypt(key, counter, nonce, plaintext):
    key = key.ljust(32, b'\0')[:32]
    nonce = nonce.ljust(12, b'\0')[:12]
    ciphertext = b''

    for i in range(0, len(plaintext), 64):
        block = chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xffffffff
        keystream = block[:len(plaintext[i:i+64])]
        ciphertext += bytes([p ^ k for p, k in zip(plaintext[i:i+64], keystream)])

    return ciphertext


if __name__ == "__main__":
    key = bytes.fromhex("8D EC 91 12 EB 76 0E DA 7C 7D 87 A4 43 27 1C 35 D9 E0 CB 87 89 93 B4 D9 04 AE F9 34 FA 21 66 D7".replace(" ", ""))
    nonce = bytes.fromhex("11 11 11 11 11 11 11 11 11 11 11 11".replace(" ", ""))    
    counter = 0
    with open("file_encoded.dump", "rb") as f:
        ciphertext = f.read()

    # 복호화
    decrypted = chacha20_encrypt(key, counter, nonce, ciphertext)
    print("Decrypted:", decrypted)
```