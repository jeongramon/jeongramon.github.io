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
  - [frog, 1, Reversing, Warming Up]
  - [checksum, 2, Reversing, Golang]
  - [aray, 3, Reversing, Yara Rule]
  - [Meme Maker 3000, 4, Reversing, JavaScript Obfuscation]
  - [sshd, 5, Reversing, CoreDump]
---

2024년 10월 27일부터 6주 간 개최된 `Flare-On 11`에 참여하였다. `Flare-On`은 `Maindiant`에서 매년 주최하는 리버싱 챌린지로, 모든 문제를 해결하면 기념 코인(메달)을 준다고 한다. 올해는 모든 문제를 해결하지 못해 아쉽고, 내년에 다시 참여해서 기념 코인을 챙겨보고 싶다.

{% include problems.html probs=page.probs %}

<br />

# frog

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

# checksum

`Go`로 작성된 것으로 보이는 `exe`가 제공되며, 실행 시 아래와 같이 사용자의 입력을 요구한다.

![image.png](/assets/img/writeups/202411/2_1.png)

<br />

## 코드 분석

메인 코드는 대략 세 부분으로 나눌 수 있다.

1. `Math Problem`
2. `Check Function`
3. `Print Flag`

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

# aray

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

# Meme Maker 3000

`html`이 제공되고, 실행 시 여러 `meme`을 관람할 수 있다.

![image.png](/assets/img/writeups/202411/4.png)

<br />

## 난독화된 JavaScript

개발자 도구로 `html`을 살펴보면 `<script>`태그로 둘러싸인 난독화된 `JavaScript`를 발견할 수 있다. 

https://deobfuscate.relative.im/ 을 이용하여 난독화 해제하면 아래와 같다. 이 중 중요한 함수는 a0k로, 특정 조건을 만족하면 `Congratulations! + f` 를 `alert`하도록 되어 있다.

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

# sshd

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