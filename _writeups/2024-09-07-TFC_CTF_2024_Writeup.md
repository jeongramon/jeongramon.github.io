---
layout: post
title: TFC CTF 2024 Writeup
subtitle: x8, MCKNIGHT, VIRTUAL-REV
thumbnail-img: /assets/img/writeups/202409/3.png
tags: [Writeup, Reversing]
comments: true
ctf: TFC CTF 2024
color: e0bbf3
ctf_date: 2024-08-02
probs:
  - [VIRTUAL-REV, -, Reversing, 논리 및 사칙연산 등 구현 해석]
  - [MCKNIGHT, -, Reversing, Pyarmor  Deobfuscation]
  - [x8, -, Reversing, Rust / VM]
---

2024년 8월 2일부터 4일까지 48시간 간 진행된 `TFC CTF 2024`이다.

{% include problems.html probs=page.probs %}


# VIRTUAL-REV

## 코드 해석

### 전반적 로직

사용자로부터 입력 값을 받아 `l0,l1,l2,l3,l4,l5,lax` 레지스터에 대하여 연산을 진행한다. `l0~l4` 의 값이 특정 값이 되었을 때 `FLG` 명령을 수행하면 `flag`를 출력할 수 있다.  사용자 입력의 형식은 `[instruction] [register1],[register2]\n`  형태가 된다.

```cpp
src = strtok(luma_code, " \n");
    ...
    step1_1(dest, &check1_1);
    step1_2(dest, &check1_2);
    step1_3(dest, &check1_3);
    if ( check1_1 == -1 && check1_2 == -1 && check1_3 == -1 )// step1 3개 중 하나라도 만족시 통과
    {
      puts("LUMA_ERROR (1): Invalid instruction name!");
      exit(0);
    }
    src = strtok(0LL, ",");                     // [step1] [step2_1],[step2_2]\n
    if ( src )
    {
      strncpy(s, src, 3uLL);
      if ( s[0] == ' ' )                        // 띄어쓰기 방지?
      {
        s_len = strlen(s);
        memmove(s, &s[1], s_len);
      }
      step2(s, &index2_1);                      // [step2_1] : l0 ~l5 lax lip
    }
    src = strtok(0LL, "\n");
    if ( src )
    {
      strncpy(s2, src, 3uLL);
      if ( s2[0] == ' ' )
      {
        v5 = strlen(s2);
        memmove(s2, &s2[1], v5);
      }
      step2(s2, &index2_2);                     // [step2_1] : l0 ~l5 lax lip
    }
```

<br />

`instruction`은 크게 3종류로 입력 형식 또한 3종류이며, `reg1 = instruction(reg1,reg2)` 혹은 `reg1 = instruction(reg1)`를 실행한다. 또한 각 `instruction` 실행 시마다 `count`가 측정되어, 동일 instruction이 10번 이상 호출되면 에러를 출력한다.

```cpp
 if ( check1_2 != -1 && (index2_2 != -1 || index2_1 == -1)// step 1_2 :: 2_1 (X) or 2_2 (O) :: 2_1에 입력
      || check1_1 != -1 && (index2_1 == -1 || index2_2 == -1)// step 1_1은 2_1, 2_2 모두 입력
      || check1_3 != -1 && (index2_1 != -1 || index2_2 != -1) )// step1_3 :: 2_1(O) or 2_2(O) :: 레지스터 미입력
    {
      puts("LUMA_ERROR (3): Invalid registers for this type of instruction!");
      exit(0);
    }
```

<br />

특히 `FLG instruction`은 호출 시 `l0,l1,l2,l3,l4` 값이 각각 `1337,108,117,109,996`인 경우에 `flag`를 출력하므로, 다른 `instruction`을 통하여 레지스터 값을 원하는 값으로 조정하고 `FLG`를 호출할 필요가 있다.

```cpp
int __fastcall get_flag(__int64 *a1)
{
  __int64 v1; // rax
  char v3; // [rsp+17h] [rbp-9h]
  FILE *stream; // [rsp+18h] [rbp-8h]

  v1 = *a1;
  if ( *a1 == 1337 )
  {
    v1 = a1[1];
    if ( v1 == 108 )
    {
      v1 = a1[2];
      if ( v1 == 117 )
      {
        v1 = a1[3];
        if ( v1 == 109 )
        {
          v1 = a1[4];
          if ( v1 == 97 )
          {
            stream = fopen("./flag.txt", "r");
           ...
}
```
<br />

### Instruction 종류

호출하는 `Instruction`은 각각 입력된 `register`에 대하여 사칙, 논리 연산 등을 시행한다. 각 함수 명은 의미  없는 문자 나열이기 때문에 각 `Instruction`의 기능은 직접 파악하여 한다. `Instruction`의 수가 너무많기 때문에 파악 과정은 생략한다. `[name]_[function]` 으로 정리하면 다음과 같다.

```cpp
.data:000055B0F3BD10D0                 dq offset XZD_AandB
.data:000055B0F3BD10D8                 dq offset STF_AshiftleftB
.data:000055B0F3BD10E0                 dq offset QER_AshiftrightB
.data:000055B0F3BD10E8                 dq offset LQE_AandB
.data:000055B0F3BD10F0                 dq offset SQL_AorB
.data:000055B0F3BD10F8                 dq offset RALK_SUM
.data:000055B0F3BD1100                 dq offset MQZL_SUB
.data:000055B0F3BD1108                 dq offset LQDM_divide
.data:000055B0F3BD1110                 dq offset SAMO_mod
.data:000055B0F3BD1118                 dq offset XKA_mul
.data:000055B0F3BD1120                 dq offset MISZ_AisB
.data:000055B0F3BD1128                 align 10h
.data:000055B0F3BD1130                 dq offset NEAZ_not
.data:000055B0F3BD1138                 dq offset MINL_not_plus_1
.data:000055B0F3BD1140                 dq offset OAN_inc
.data:000055B0F3BD1148                 dq offset MAZ_dec
.data:000055B0F3BD1150                 dq offset NO_returnA
.data:000055B0F3BD1158                 dq offset BRAILA_???
```
<br />

## PoC

### Instruction 조합

`Instruction` 종류를 파악했으므로 아래와 같이 연산을 수행하면 목표 `Value`에 도달 및 `Flag`를 출력할 수 있다.

```cpp
l0 = 1337 = 0101 0011 1001
l1 = 108 = 0110 1100
l2 = 117 = 0111 0101
l3 = 109 = 0110 1101
l4 = 97 = 0110 0001
```

<br />

|  | l0 | l1 | l2 | l3 | l4 | l5 | lax |
| --- | --- | --- | --- | --- | --- | --- | --- |
| inc l5 |  |  |  |  |  | 1 |  |
| shl l5,l5 |  |  |  |  |  | 10 |  |
| inc lax |  |  |  |  |  |  | 1 |
| sum lax,l5 |  |  |  |  |  |  | 11 |
| mov l2,lax |  |  | 11 |  |  |  |  |
| inc l2 |  |  | 100 |  |  |  |  |
| mul l2,l5 |  |  | 1000 |  |  |  |  |
| shl lax,lax |  |  |  |  |  |  | 0001 1000 |
| shl lax,l5 |  |  |  |  |  |  | 0110 0000 |
| **l4** |  |  |  |  |  |  |  |
| mov l4,lax |  |  |  |  | 0110 0000 |  |  |
| inc l4 |  |  |  |  | 0110 0001 |  |  |
| **l1** |  |  |  |  |  |  |  |
| mov l1,lax |  | 0110 0000 |  |  |  |  |  |
| shr l1,l5 |  | 0001 1000  |  |  |  |  |  |
| divide l1,l5 |  | 0000 1100 |  |  |  |  |  |
| sum l1,lax |  | 0110 1100 |  |  |  |  |  |
| **l3** |  |  |  |  |  |  |  |
| mov l3, l1 |  |  |  | 0110 1100 |  |  |  |
| inc l3 |  |  |  | 0110 1101 |  |  |  |
| **l2** |  |  |  |  |  |  |  |
| sum l2,l3 |  |  | 0111 0101 |  |  |  |  |
| **l0** |  |  |  |  |  |  |  |
| mov l0,l5 | 10 |  |  |  |  |  |  |
| mul l0,l5 | 100 |  |  |  |  |  |  |
| inc l0 | 101 |  |  |  |  |  |  |
| shl l0,l0 | 1010 0000 |  |  |  |  |  |  |
| shl l0, l5 | 10 1000 0000 |  |  |  |  |  |  |
| mul l0,l5 | 101 0000 0000 |  |  |  |  |  |  |
| mov lax,l2 |  |  |  |  |  |  | 0111 0101 |
| div lax,l5 |  |  |  |  |  |  | 0011 1010 |
| dec lax |  |  |  |  |  |  | 0011 1001 |
| or l0.lax |  |  |  |  |  |  |  |

<br />

### PoC.py

```python
from pwn import *

p = remote('localhost', 1337)

p.recvuntil(b'Insert luma code: \n')

payload = b'''OAN l5
STF l5,l5
OAN lax
RALK lax,l5
MISZ l2,lax
OAN l2
XKA l2,l5
STF lax,lax
STF lax,l5
MISZ l4,lax
OAN l4
MISZ l1,lax
QER l1,l5
LQDM l1,l5
RALK l1,lax
MISZ l3, l1
OAN l3
RALK l2,l3
MISZ l0,l5
XKA l0,l5
OAN l0
STF l0,l0
STF l0,l5
XKA l0,l5
MISZ lax,l2
LQDM lax,l5
MAZ lax
SQL l0,lax
FLG
'''

p.sendline(payload)

response = p.recv()
print(response.decode())

p.close()
```

<br />

# MCKNIGHT
## PyArmor Deobfuscate

문제에는 `PyArmor`로 난독화된 `hasher.py`가 존재한다. 이를 [PyArmor-Unpacker](https://github.com/Svenskithesource/PyArmor-Unpacker) 의 `methods3 - pybass.py`를 활용하여 난독화 해제한다. 문제 파일 중 `init.cpython-310.pyc`, `_pytransform.so` 가 존재하므로 `python3.10` 및 `Linux` 환경에서 구동한다.  구동 결과로 `hasher.pyc` 를 얻을 수 있다.

> [https://github.com/Svenskithesource/PyArmor-Unpacker/blob/main/methods/method 3/bypass.py](https://github.com/Svenskithesource/PyArmor-Unpacker/blob/main/methods/method%203/bypass.py)
> 

`hasher.pyc`로부터 `pycdc`를 활용하여 원본 소스코드를 얻을 수 있다. 평문 `password`를 읽어 자체 알고리즘을 통한 `hash dump (fllag.tfc)`를 생성하는 코드이다.

```python
def generator(cnt):
    coeffs = []
    for i in range(cnt):
        aux = []
        for j in range(cnt):
            aux.append(nums[(i + j) * 1337 % 256])
        coeffs.append(aux)
    return coeffs

coeffs = generator(FLAG_LEN)

def calc_line(k, password):
    rez = 0
    for i in range(len(password)):
        rez += password[i] * coeffs[k][i]
    return rez

def hash(password):
    password = password.encode()
    rez = []
    for i in range(FLAG_LEN):
        rez.append(calc_line(i, password))
    final = []
    for k in range(FLAG_LEN):
        aux = 0
        for i in range(FLAG_LEN):
            aux += coeffs[i][i] * rez[k] ** i
        final.append(aux)
    data = 'X'.join((lambda .0: [ str(i) for i in .0 ])(final))
    data = lzma.compress(data.encode())
    return data

def protect_pytransform():
    pass

protect_pytransform()
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 hasher.py <password>')
        sys.exit(1)
    password = sys.argv[1]
    f = open('flag.tfc', 'wb')
    f.write(hash(password))
    f.close()
    return None
```

<br />

## 패스워드 역산

### flag.tfc to rez

`final[k] == Σcoeffs[i][i] * (rez[k] ** i)` 이므로, `rez[k]진법` 으로 `final[k]` 를 표현하였을 때 각 자리 숫자가 `coeffs[i][i]` 라고 할 수 있다. 근거하여 역산 코드를 작성하면 아래와 같다.

```python
def brute_force(n):
    res = 256
    while True:
        fin = 0
        for i in range(FLAG_LEN-1,-1,-1):
            fin += coeffs[i][i] * res**i
            if fin > n:
                res += 1
                break
        if fin < n:
            res += 1
        elif fin ==n:
            return res
        elif fin > n :
            return 0       # res < 256 인 케이스 (없었음)
            
def fin_to_rez(data):
    final = lzma.decompress(data).decode().split('X')
    rez = []  
    for i in range(FLAG_LEN):
        fin = int(final[i])
        rez.append(brute_force(fin))
    return rez
```

<br />

### rez to password

`rez[k] == Σpassword[i]*coeff[k][i]` 이므로, `password` 각 자리를 변수`(17개)`로 하는 일차 방정식`(17개)`가 주어졌다고 볼 수 있으므로, 아래와 같이 역산 알고리즘을 짤 수 있다. 

```python
def rez_to_password(rez):
    result =''
    rez_vector = np.array(rez)
    coeff_matrix = np.array(coeffs)
    solution_vector = np.linalg.solve(coeff_matrix,rez_vector)
    for sol in solution_vector:
        result +=chr(int(round(sol)))
    return result
```

<br />

### 결과

`password`는 `lum41sv3ryskibid1` 이다.  원본 코드에 이 패스워드를 대입하여 실행하면 문제 파일과 동일한 `flag.tfc`파일이 생성된다. 

<br />

## 부록(PoC.py)

```python
import sys
import lzma
import np
FLAG_LEN = 17
nums = [
    203,
    99,
    1,
    ... # 표기 상 생략
    63,
    179,
    136]

def generator(cnt):
    coeffs = []
    for i in range(cnt):
        aux = []
        for j in range(cnt):
            aux.append(nums[(i + j) * 1337 % 256])
        coeffs.append(aux)
    return coeffs

coeffs = generator(FLAG_LEN)

def brute_force(n):
    res = 256
    
    while True:
        fin = 0
        for i in range(FLAG_LEN-1,-1,-1):
            fin += coeffs[i][i] * res**i
            if fin > n:
                res += 1
                print("ouch")
                break
        if fin < n:
            res += 1
        elif fin ==n:
            return res
        elif fin > n :
            return 0       # res < 256 인 케이스 
            
def fin_to_rez(data):
    final = lzma.decompress(data).decode().split('X')
    rez = []
    for i in range(FLAG_LEN):
        fin = int(final[i])
        rez.append(brute_force(fin))
    return rez

def rez_to_password(rez):
    result =''
    rez_vector = np.array(rez)
    coeff_matrix = np.array(coeffs)
    solution_vector = np.linalg.solve(coeff_matrix,rez_vector)
    for sol in solution_vector:
        result +=chr(int(round(sol)))
    return result

if __name__=='__main__':
    f = open('./dist/flag.tfc', 'rb')
    data = f.read()
    rez = fin_to_rez(data)
    password = rez_to_password(rez)
    print(password)
```

<br />

# x8

`./x8 --file program.bin` 의 형태로 `program.bin`과 함께 실행하며, 이후 사용자 입력값을 요구한다. `Rust`로 작성된 것으로 추정된다.

## 코드 분석

### 메인 로직

메인 로직은 쉽게 찾을 수 있다. `program.bin`으로부터 값을 읽어 `<dyn x8::instruction::Instruction>::parse`를 통해 `opcode`를 생성하고, 그에 따라 `(v3 + 0x28), (v4 + 0x20)` 함수를 실행한다.

그 중 `(v3 + 0x28)` 은 `program.bin`에서 단순 `return 3`  등의 함수만 호출하여, `program.bin`의 `offset` 를 옮기는 일종의 `rip` 역할만 한다. 그러므로 `(v4 + 0x20)` 에 집중할 필요가 있다.

```cpp
__int64 (__fastcall *__fastcall x8::vm::VM::run(_BYTE *s, __int64 v17))(__int64)
{
	...
  while ( 1 )
  {
    v10 = (char **)&s[(unsigned __int8)s[0x409] + 1];// program.bin 앞 파트
    v11 = (__int64)(s + 0x101);                 // program.bin 뒤파트
    pc = &v10;
    v2 = <dyn x8::instruction::Instruction>::parse((__int64)&pc, (__int64)&unk_55555561B2B8);// parse(program.bin[i,i+3?])
    v4 = v3;
    s[0x409] += (*(__int64 (__fastcall **)(__int64))(v3 + 0x28))(v2);// [rdx+28h](v2)
    (*(void (__fastcall **)(__int64, _BYTE *))(v4 + 0x20))(v2, s);// [rdx+20h](v2,s)
    result = *(__int64 (__fastcall **)(__int64))v4;
    if ( *s )
      break;
    if ( result )
      result(v2);
    v6 = *(_QWORD *)(v4 + 8);
    if ( v6 )
      _rust_dealloc(v2, v6, *(_QWORD *)(v4 + 0x10));
  }
	...
}
```

### (v4 + 0x20)

사용자 입력을 요구하므로 올바른 입력 값이 무엇인지 체크하는 부분이 있을 것으로 예상되므로, 아래와 같은 방법으로 `v4+0x20` 이 호출하는 함수들을 순차적으로 파싱하였다.

```python
import idc
import idaapi
import idautils
import ida_dbg

# 결과를 저장할 파일 경로
output_file_path = "./function.txt"

def hook_call_instruction(ea, iterations=10):
    with open(output_file_path, "a") as file:
        count = 0
        while count < iterations:
            ida_dbg.add_bpt(ea)
            idaapi.run_to(ea)
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

            r15_value = idc.get_reg_value("r15")
            call_address = idc.get_qword(r15_value + 0x20) # 호출 함수 주소
            
            result = f"Iteration {count+1}: Address: 0x{ea:X}, r15: 0x{r15_value:X}, call [r15+20h]: 0x{call_address:X}\n"
            print(result)
            file.write(result)

            ida_dbg.del_bpt(ea)
            count += 1

        print(f"Finished {iterations} iterations. Results saved to {output_file_path}")

call_instruction_address = 0x5555555659D7  # 'call qword ptr [r15+20h]' 명령어의 주소
hook_call_instruction(call_instruction_address, iterations=10000)
```
<br />

마지막 `jump_not_equal`함수가 `equal`조건을 만족하도록 하면 `flag`를 얻을 수 있다.

```cpp
r15: 0x55555561B3B0, call [r15+20h]: 0x555555566180
...
r15: 0x55555561B5A8, call [r15+20h]: 0x555555566EC0  //xor_final
r15: 0x55555561B618, call [r15+20h]: 0x555555567080  //cmp_2
r15: 0x55555561B458, call [r15+20h]: 0x555555566400  //jump not equal
r15: 0x55555561B5E0, call [r15+20h]: 0x555555566F90  //write
r15: 0x55555561B5E0, call [r15+20h]: 0x555555566F90
r15: 0x55555561B5E0, call [r15+20h]: 0x555555566F90
r15: 0x55555561B5E0, call [r15+20h]: 0x555555566F90
r15: 0x55555561B5E0, call [r15+20h]: 0x555555566F90
r15: 0x55555561B378, call [r15+20h]: 0x555555566380  //rtn 1
```

### xor_final

사용자 입력 값`([rsi+rax+401h])`과 어떤 값`(cl)`을 `xor`한다. (동적 디버깅으로 파악)

```cpp
.text:0000555555566EC0 xor_final       proc near
.text:0000555555566EC0 ; __unwind { // 555555554000
.text:0000555555566EC0                 push    rax
.text:0000555555566EC1                 mov     rax, rdi
.text:0000555555566EC4                 movzx   edi, byte ptr [rdi+1]
.text:0000555555566EC8                 cmp     rdi, 10h
.text:0000555555566ECC                 jnb     short loc_555555566EE8
.text:0000555555566ECE                 movzx   eax, byte ptr [rax]
.text:0000555555566ED1                 cmp     rax, 10h
.text:0000555555566ED5                 jnb     short loc_555555566EFA
.text:0000555555566ED7                 movzx   ecx, byte ptr [rsi+rdi+401h]
.text:0000555555566EDF                 xor     [rsi+rax+401h], cl
.text:0000555555566EE6                 pop     rax
.text:0000555555566EE7                 retn
```

### cmp_2

`xor_final` 결과 값`(cl)`과 어떤 값`([rsi+rax+401h])`을 비교한다.

```cpp
.text:0000555555567080 cmp_2           proc near               
.text:0000555555567080 ; __unwind { // 555555554000
.text:0000555555567080                 push    rax
.text:0000555555567081                 mov     rax, rdi
.text:0000555555567084                 movzx   edi, byte ptr [rdi]
.text:0000555555567087                 cmp     rdi, 10h
.text:000055555556708B                 jnb     short loc_5555555670BD
.text:000055555556708D                 movzx   eax, byte ptr [rax+1]
.text:0000555555567091                 cmp     rax, 10h
.text:0000555555567095                 jnb     short loc_5555555670CF
.text:0000555555567097                 movzx   ecx, byte ptr [rsi+rdi+401h]
.text:000055555556709F                 cmp     cl, [rsi+rax+401h]
.text:00005555555670A6                 setz    al
.text:00005555555670A9                 movzx   ecx, byte ptr [rsi+411h]
.text:00005555555670B0                 and     cl, 0FEh
.text:00005555555670B3                 or      cl, al
.text:00005555555670B5                 mov     [rsi+411h], cl
.text:00005555555670BB                 pop     rax
.text:00005555555670BC                 retn
```
<br />

## PoC

`(올바른 사용자 입력값) = (cmp_2 어떤 값) xor (cmp_2 어떤 값)`  이 된다. `ida python`을 이용하여 각 값을 추출한 후 `flag`를 연산하였다. 추가적으로 원활한 `flag` 추출을 위하여 `cmp_2`가 한번에 그치지 않도록, `cmp_2` 결과가 항상 참이 되도록 패치하였다.

```python
import idc
import idaapi
import idautils
import ida_dbg

output_file_path = "flag.txt"

def set_cl_to_1(): # mov cl, 1
    cl_value = 1
    rcx_value = idc.get_reg_value("rcx")
    new_rcx_value = (rcx_value & 0xFFFFFFFFFFFFFF00) | cl_value
    idc.set_reg_value(new_rcx_value, "rcx")

def extract_and_xor(xor_ea, cmp_ea, iterations=10):
    flag = ''
    patch_ea = 0x00005555555670B3
    with open(output_file_path, "a") as file:
        count = 0
        ida_dbg.add_bpt(xor_ea)
        ida_dbg.add_bpt(cmp_ea)
        ida_dbg.add_bpt(patch_ea)

        while count < iterations:
            # 1 .text:0000555555566EDF xor [rsi+rax+401h], cl
            idaapi.run_to(xor_ea)
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
            cl_value = idc.get_reg_value("cl")

            # 2 .text:000055555556709F cmp cl, [rsi+rax+401h]
            idaapi.run_to(cmp_ea)
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

            rsi_value = idc.get_reg_value("rsi")
            rax_value = idc.get_reg_value("rax")
            memory_address = rsi_value + rax_value + 0x401
            memory_value_after = idc.get_wide_byte(memory_address)

            ### result
            xor_result = cl_value ^ memory_value_after
            result_char = chr(xor_result)
            
            result = f"Iteration {count+1}: CL: 0x{cl_value:X}, After: 0x{memory_value_after:X}, chr(a^b): {result_char}\n"
            flag +=result_char
            print(result)
            file.write(result)
            file.write(f"flag:{flag}\n")
            
            # 3. cmp2 결과 항상 참으로 패치
            idaapi.run_to(patch_ea)
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
            set_cl_to_1()
            count += 1
        
xor_instruction_address = 0x555555566EDF  # xor_final -> 'xor [rsi+rax+401h], cl' 
cmp_instruction_address = 0x55555556709F  # cmp2 -> 'cmp cl, [rsi+rax+401h]' 
iterations = 100

extract_and_xor(xor_instruction_address, cmp_instruction_address, iterations=iterations)
```

`flag:TFCCTF{3ede51da1709268b2cefddcd93c4cd98}`