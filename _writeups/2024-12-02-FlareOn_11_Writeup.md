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