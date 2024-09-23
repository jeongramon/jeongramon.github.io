---
layout: post
title: CyberSpace CTF 2024 Writeup
subtitle: login, sole, snake
thumbnail-img: /assets/img/writeups/202409/4_1snake.png
tags: [Writeup, Reversing]
comments: true
ctf: CyberSpace CTF 2024
color: b2f2e5
ctf_date: 20240830
probs:
  - [snake, 1, Reversing, 메모리 영역 검색 및 패치]
  - [sole, 6, Reversing, Golang]
  - [login, 8, Reversing, Flutter / Dart]
---

2024년 8월 30일부터 9월 1일까지 48시간 간 진행된 `CyberSpace CTF 2024`이다.

{% include problems.html probs=page.probs %}

# snake

실행 시 조작하여 `10`점 씩 점수를 획득할 수 있으며, `flag`를 얻기 위하여 `16525`점을 획득하라는 안내가 출력된다. 

![image.png](/assets/img/writeups/202409/4snake.png)

<br />

## 문제 분석

`Score :`  오른쪽에 현재 `score` 가 출력되므로, 출력 시 `score`를 어느 변수에서 가져오는지 코드로부터 확인한 후 변수를 조작하려 하였다. 그러나 변수 호출 과정이 복잡하여 분석에 한계가 있었다.

때문에 `gdb`를 이용하여 직접 메모리 영역에 점수를 검색하였다.

<br />

## 메모리 분석 (gdb)

### 1. snake 실행

`40`점을 달성한 후 `pause` 기능을 이용하여 잠시 정지한다. `Hi-score`는 `40`점이 되지 않도록 미리 경신한다.

<br />

### 2. 메모리 영역 확인

`snake`의 `pid`를 확인 후 `process map`을 확인한다. 이 중 `score`가 저장될 수 있는 위치는 읽고 쓰기가 모두 가능한 `rw` 영역이다.

```cpp
# ps -ef | grep snake
kali        1705    1619 56 05:08 pts/0    00:00:33 ./snake

# cat /proc/1705/maps 
...
7ffxxxxxxx-7ffyyyyyyyy rw-p 00000000 00:00 0                          [stack]
...
```

<br />

### 3. gdb로 score  영역 검색

`rw`  영역을 순차적으로 검색하며 현재 점수가 저장되어 있는 부분을 검색할 필요가 있다. `stack`을 먼저 검색하였는데 `score` 로 보이는 영역이 존재하여 `40 → 16515`으로 조작하였다.

```cpp
# gdb -p 1705
(gdb) find /w 0x7ffxxxxxxx, 0x7ffyyyyyy, 0x28 #현재 40점이므로 0x28(40)검색
0x7ffeeeeeeee

(gdb) x /10xb 0x7ffeeeeeeee  # 조작 전 score 영역 확인
0x7ffeeeeeeeee: 0x28    0x00    0x00    0x00    0x00    0x00    0x00    0x40
0x7ff...      : 0x3c    0x00

(gdb) set *(int *)0x7ffeeeeeee= 16515  # 10점 추가 획득시 16525점 도달 가능
(gdb) x /10xb 0x7ffeeeeeeee # 조작 후 score 영역 확인
0x7ffec7fdb45c: 0x83    0x40    0x00    0x00    0x00    0x00    0x00    0x40
0x7ffec7fdb464: 0x3c    0x00
(gdb) continue
```

<br />

### 4. snake 재실행

`snake`를 재실행 후 `10점`을 추가 획득하면 조작한 점수 `16515점`에 `10점`이 더해져 `16525점`이 되고, `flag`가 출력된다.

`CSCTF{Y0u_b34T_My_Sl1th3r_G4m3!}`

<br />

# sole
`Enter the flag:`를 출력하며 `flag` 입력을 요구한다. `Golang` 리버싱을 필요로 한다.

## 코드 해석

`main` 함수는 어렵지 않게 찾을 수 있다. 사용자 입력 길이가 `26` 인지 확인 후 입력 각 자리를 `char_{i}`에 저장한다.

```cpp
input_str = core::str::<impl str>::trim(v1, v2);
  if ( core::str::<impl str>::len(input_str, v4) != 26 ) // input_len==26
  {
    ...
  }
  v363 = 0;
  input_str2 = <alloc::string::String as core::ops::deref::Deref>::deref(v359);
  input_str3 = core::str::<impl str>::chars(input_str2, v6);
  core::iter::traits::iterator::Iterator::collect(input_str4, input_str3, v8);// *input_str4에 한자리 당 4바이트씩 저장
  char_0 = *(_DWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(
                        (int)input_str4,
                        0,
                        (int)&off_5555555A9A38,
                        v9,
                        v10,
                        v11,
                        v93,
                        v120,
                        v148,
                        v175,
                        v202,
                        v229,
                        v256,
                        v283);
  char_1 = *(_DWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(
                        (int)input_str4,
                        1,
                        (int)&off_5555555A9A50,
                        v12,
                        v13,
                        v14,
                        v94,
                        v121,
                        v149,
                        v176,
                        v203,
                        v230,
                        v257,
                        v284);
  ...
```

<br />

이후 각 자리(`char{i}`)에 대해서 특정 연산을 수행하고, 결과가 정해진 값과 같은지 `26번` 검증한다.

```cpp
if ( !is_mul_ok(char_19, char_11) )  
    core::panicking::panic();         //overflow 등 예외처리 -> 무시해도 됨
  if ( !is_mul_ok(char_4, mul1) )
    core::panicking::panic();
  if ( char_4 * mul1 != 391020 )     //condition 1
    v363 = 1;
  mul2 = char_13 * char_8;
  ...
  if ( char_22 * mul2 != 567720 )   //condition 2
    v363 = 1;
  mul3 = char_22 * char_0;
  if ( !is_mul_ok(char_22, char_0) )
    core::panicking::panic();
  if ( __OFADD__(char_15, mul3) )
    core::panicking::panic();
  if ( char_15 + mul3 != 4872 )     //condition 3
    v363 = 1;
  
  ...
  
  if ( v363 )
  {
    ... // fail
  }
  ...
```
<br />

## PoC

위 `conditions`를 가독성이 있도록 옮겨 적으면 아래와 같다.

```python
s[19]*s[11]*s[4] ==391020
s[13]*s[8]*s[22] == 567720
s[22]*s[0]+s[15] == 4872
s[0]+s[8]+s[11] == 199
s[13] - (s[22]*s[12]) == -3721
s[9]*s[4] - s[1] == 8037
s[9]*s[16] *s[11] == 272832
s[3]*s[23] +s[15] == 9792
s[9] - s[23] -s[4] == -70
s[5] -s[21] -s[8] ==-63
s[3]*s[24] +s[0] ==5359
s[25]*s[1] +s[17] == 10483
s[7] * s[19] *s[2] == 893646
s[11] -s[4] +s[19] == 93
s[7] + s[6] -s[10] ==136
s[0] +s[25] +s[10] ==287
s[12] + s[5] -s[22] ==104
s[4] *s[7] +s[12] == 8243
s[1] - s[22] +s[4] == 81
s[8] - s[19] * s[11] == -5503
s[8] -s[10] -s[7] == -129
s[20] +s[21] +s[22] ==224
s[23] + s[24]+ s[12] == 232
s[15] -s[9] +s[4] == 2
s[9]*s[15]+s[2] ==5635
s[24] +s[14] +s[16] ==210
s[1] +s[10] -s[12] ==125
s[18] -s[1] -s[5] ==-111
s[12] -s[14] -s[7] ==-163
s[1] + s[5] -s[16] ==158
```

<br />

`26개`의 변수와 `26개`의 방정식이므로 위 조건들로만으로도 각 자리를 구할 수 있지만, `FLAG` 양식에서 아래와 같이 각 자리에 대한 힌트를 더 얻을 수 있다. 

```python
    s[0] = ord('C') #67
    s[1] = ord('S') #83
    s[2] = ord('C') #67
    s[3] = ord('T') #84
    s[4] = ord('F') #70
    s[5] = ord('{') #123
    s[25] = ord('}') #125
```
<br />

방정식을 순차적으로 풀이하면 아래와 같고, `ascii` 코드 변환을 거치면 `flag`를 얻을 수 있다.

```python
# 1차 대입
s[9]*70 - 83 == 8037 #116
84*s[24] +67 ==5359 #63
125*83 +s[17] == 10483 #108
67 +125 +s[10] ==287 #95
83 - s[22] +70 == 81 #72
s[18] -83 -123 ==-111 #95
83 + 123 -s[16] ==158 #48

#2차 대입
72*67+s[15] == 4872 #48
116*48 *s[11] == 272832 #49
116 - s[23] -70 == -70 #116
s[12] + 123 -72 ==104 #53
s[15] -116 +70 == 2
116*s[15]+67 ==5635
63 +s[14] +48 ==210 #99
83 +95 -s[12] ==125

#3차 대입
s[19]*49*70 ==391020 #114
67+s[8]+49 == 199 #83
s[13] - (72*53) == -3721 #95
49 -70 +s[19] == 93
70 *s[7] +53 == 8243 #117
53 -99 -s[7] ==-163

#4차 대입
123 -s[21] -83 ==-63 #103
117 + s[6] -95 ==136 #114

#5차 대입
s[20] +103 +72 ==224 #49
```

`CSCTF{ruSt_15_c00l_r1gHt?}`

<br />

# login

`apk` 파일이 주어지며, 실행 시 로그인을 요구한다. `Flutter` 프레임워크로 작성되었다.

![image.png](/assets/img/writeups/202409/5login.png)

<br />

## 초기 분석

`AndroidManifest.xml`을 보면 `com.example.login.MainActivity`가 시작 `Activity`이며, `Flutter` 엔진을 초기화하는 역할임을 알 수 있다.

```xml
<activity android:theme="@style/LaunchTheme" android:name="com.example.login.MainActivity" ...>
	<meta-data android:name="io.flutter.embedding.android.NormalTheme" android:resource="@style/NormalTheme"/>
	<intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/>
	</intent-filter>
</activity>
```

<br />

실제로 `MainActivity`는 다음과 같은 형태로 어플리케이션의 실제 로직은 `Flutter`의 `Dart` 코드에서 처리될 것으로 예상할 수 있다.

```java
package com.example.login;

import p020io.flutter.embedding.android.C0237f;

public class MainActivity extends C0237f {
}
```

<br />

`Flutter` 프로젝트의 `main.dart`는 보통 `Resource/lib` 에 위치한다. 이 위치를 확인하면, `.so`로 컴파일된 `dart` 코드를  확인할 수 있다. `libapp.so` 가 컴파일된 앱의 `Dart` 코드이고, `libflutter.so`는 `Flutter` 엔진 파일이다.

## libapp.so 분석

https://github.com/worawit/blutter를 이용하여 `liapp assembly`를 추출할 수 있다. 그 중 `login` 폴더에 `main.dart`가 존재하며, 그 중 `login` 관련 함수는 아래와 같다.

```python
_ _login(/* No info */) {
    // ** addr: 0x2a5258, size: 0x19c
    ...
    // 0x2a52c4: r16 = <String>
    //     0x2a52c4: ldr             x16, [PP, #0x788]  ; [pp+0x788] TypeArguments: <String>
    // 0x2a52c8: r30 = Instance_Utf8Codec
    //     0x2a52c8: ldr             lr, [PP, #0x5c0]  ; [pp+0x5c0] Obj!Utf8Codec@465471
    // 0x2a52cc: stp             lr, x16, [SP, #8]
    // 0x2a52d0: r16 = Instance_Base64Codec
    //     0x2a52d0: ldr             x16, [PP, #0x1350]  ; [pp+0x1350] Obj!Base64Codec@465461
    // 0x2a52d4: str             x16, [SP]
    // 0x2a52d8: r4 = const [0x1, 0x2, 0x2, 0x2, null]
    //     0x2a52d8: ldr             x4, [PP, #0x58]  ; [pp+0x58] List(5) [0x1, 0x2, 0x2, 0x2, Null]
    // 0x2a52dc: r0 = fuse()
    //     0x2a52dc: bl              #0x2a95b8  ; [dart:convert] Codec::fuse
    // 0x2a52e0: mov             x1, x0
    // 0x2a52e4: ldur            x0, [fp, #-0x10]
    // 0x2a52e8: stur            x1, [fp, #-8]
    // 0x2a52ec: r2 = LoadClassIdInstr(r0)
    //     0x2a52ec: ldur            x2, [x0, #-1]
    //     0x2a52f0: ubfx            x2, x2, #0xc, #0x14
    **// 0x2a52f4: r16 = "4dm1n"
    //     0x2a52f4: add             x16, PP, #0xa, lsl #12  ; [pp+0xa280] "4dm1n"**
    //     0x2a52f8: ldr             x16, [x16, #0x280]
    // 0x2a52fc: stp             x16, x0, [SP]
    // 0x2a5300: mov             x0, x2
    // 0x2a5304: mov             lr, x0
    // 0x2a5308: ldr             lr, [x21, lr, lsl #3]
    // 0x2a530c: blr             lr
    // 0x2a5310: tbnz            w0, #4, #0x2a53cc
    // 0x2a5314: ldur            x2, [fp, #-0x18]
    // 0x2a5318: LoadField: r0 = r2->field_f
    //     0x2a5318: ldur            w0, [x2, #0xf]
    // 0x2a531c: DecompressPointer r0
    //     0x2a531c: add             x0, x0, HEAP, lsl #32
    // 0x2a5320: stur            x0, [fp, #-0x10]
    // 0x2a5324: ldur            x16, [fp, #-8]
    **// 0x2a5328: r30 = "U3VwM3JTM2NyM3RmMHJNeVMzY3VSM0wwZ2luQXBw"
    //     0x2a5328: add             lr, PP, #0xa, lsl #12  ; [pp+0xa288] "U3VwM3JTM2NyM3RmMHJNeVMzY3VSM0wwZ2luQXBw"
    //     0x2a532c: ldr             lr, [lr, #0x288]**
    // 0x2a5330: stp             lr, x16, [SP]
    // 0x2a5334: r0 = decode()
    //     0x2a5334: bl              #0x2a94c8  ; [dart:convert] Codec::decode
    ...
  }
```

<br />

로그인과 관련이 있어 보이는 `4dm1n`과 `U3VwM3JTM2NyM3RmMHJNeVMzY3VSM0wwZ2luQXBw` 문자열이 보이는데, 각각 `ID`와 `base64.encode(password)` 이다. 올바른 `ID`와 `PW`를 이용하여 로그인하면 `Flag`가 출력된다.

`CSCTF{SuP3r_S3cuRe_l0g1n_1234}`
