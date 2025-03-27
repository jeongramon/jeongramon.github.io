---
layout: post
title: WolvCTF Writeup
subtitle: Passwords
thumbnail-img: /assets/img/writeups/202503/wolv0.png
tags: [Writeup, Reversing, Forensics]
comments: true
ctf: WolvCTF 2025
color: 77A1D9
ctf_date: 2025-03-23
probs:
  - [Passwords, Very Easy, Forensics, KeePass Database Brute-Force]
  - [CrackMeEXE, Very Easy, Reversing, UPX Unpacking]
  - [AngerIssues, Easy, Reversing, ]
  - [Office, Easy, Reversing, ]
---

나른하던 일요일 오후, 선배에게 카톡 한 통을 받았다.

![image.png](/assets/img/writeups/202503/wolv1.jpg)

<br />

12시까지 잠들지 않으면 월요병 증세가 심해지므로... 자체 6시간 타임 리밋 CTF 렛츠고 

![image.png](/assets/img/writeups/202503/wolv2.jpg)

<br />

{% include problems.html probs=page.probs %}

<br />

# Passwords
`kdbx` 파일 1개가 주어진다. `kdbx`는 `KeePass`라는 비밀번호 관리 프로그램의 데이터베이스 파일 형식이다. 내용을 바로 열람 가능할 수도 있지만 보통 데이터베이스 암호화 해제를 위한 마스터 키가 필요하다. 

```bash
└─$ file Database.kdbx 
Database.kdbx: Keepass password database 2.x KDBX
```

<br />

## PoC

`keepass2john`으로 해시를 덤프하고, 이를 brute-force attack 하여 쉽게 마스터 키를 얻을 수 있었다.

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ keepass2john Database.kdbx > hash.txt
                                                                            
┌──(kali㉿kali)-[~/Desktop]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
goblue1          (Database)     
1g 0:00:00:36 DONE (2025-03-23 03:52) 0.02758g/s 2459p/s 2459c/s 2459C/s gobucks1..giana
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                            
┌──(kali㉿kali)-[~/Desktop]
└─$ john --show hash.txt                                     
Database:goblue1

1 password hash cracked, 0 left

```

<br />

아래와 같이 데이터베이스 내 주요 필드를 출력하여 Flag를 찾을 수 있다.

```python
from pykeepass import PyKeePass

kp = PyKeePass('Database.kdbx', password='goblue1')

for entry in kp.entries:
    print(f"[{entry.title}]")
    print(f"  Username: {entry.username}")
    print(f"  Password: {entry.password}")
    print(f"  Notes: {entry.notes}")
    print()
```

```python
[Sample Entry]
  Username: User Name
  Password: Password
  Notes: Notes

...

[flag]
  Username: the flag
  Password: wctf{1_th0ught_1t_w4s_s3cur3?}
  Notes: :3
```

<br />

# CrackMeEXE

exe 1개가 주어진다. 올바른 패스워드 입력을 요구한다.

![image.png](/assets/img/writeups/202503/wolv3.jpg)

## UPX Unpacking

IDA에 문제 파일을 로드하자 IAT 로드 관련 에러가 발생하였다.

![image.png](/assets/img/writeups/202503/wolv4.png)

<br />

때문에 PE 구조를 확인해보니 UPX 패킹이 되어 있었다.

![image.png](/assets/img/writeups/202503/wolv5.png)

<br />

언패킹을 한 뒤 IDA에 다시 올리면 된다.

```bash
$ upx -d chall_unpack.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     12289 <-      8705   70.84%    win64/pe     chall_unpack.exe

Unpacked 1 file.
```

## PoC

디버거 체크 로직 2개 `if ( ((__int64 (*)(void))IsDebuggerPresent)() )`와 `!((unsigned int (__fastcall *)(__int64, int *))CheckRemoteDebuggerPresent)(v15, &v24)`만 잘 우회하면 비밀번호 체크 로직인 `v22 = v16(Buffer);`로 진입할 수 있다. 디버거 체크 로직은 로직 실행 후 `rax`와 `v24(stack)` 값만 적절히 바꾸어 주는 것으로 간단히 우회 가능하다.

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  ...
  if ( ((__int64 (*)(void))IsDebuggerPresent)() )
  {
    puts("Nice try");
    exit(-1);
  }
  v13 = v12();
  v14 = ((__int64 (__fastcall *)(__int64, _QWORD, _QWORD))OpenProcess)(0x1FFFFFLL, 0LL, v13);
  v15 = v14;
  if ( !v14 )
    return -1;
  v16 = (__int64 (__fastcall *)(char *))((__int64 (__fastcall *)(__int64, _QWORD, __int64, __int64, int))VirtualAllocEx)(
                                          v14,
                                          0LL,
                                          139LL,
                                          12288LL,
                                          4);
  if ( !v16 )
    return -2;
  srand(0x3419u);
  v18 = 0;
  v19 = &unk_7FF618405080;
  do
  {
    *v19 ^= rand();
    ++v18;
    ++v19;
  }
  while ( v18 < 0x8B );
  if ( !((unsigned int (__fastcall *)(__int64, __int64 (__fastcall *)(char *), void *, __int64, char *))WriteProcessMemory)(
          v15,
          v16,
          &unk_7FF618405080,
          139LL,
          v25) )
    return -3;
  if ( !((unsigned int (__fastcall *)(__int64, __int64 (__fastcall *)(char *), __int64))VirtualProtectEx)(
          v15,
          v16,
          139LL) )
    return -4;
  puts("What is the password?\n");
  if ( !((unsigned int (__fastcall *)(__int64, int *))CheckRemoteDebuggerPresent)(v15, &v24) )// v24 needs patch : 1->0 , not rax!!
    return -5;
  if ( v24 )
  {
    puts("NO CHEATING");
    exit(-1);
  }
  v27 = 0;
  *(_OWORD *)Buffer = 0LL;
  v20 = _acrt_iob_func(0);
  fgets(Buffer, 19, v20);
  v21 = strcspn(Buffer, "\n");
  if ( v21 >= 0x14 )
    _report_rangecheckfailure();
  Buffer[v21] = 0;
  v22 = v16(Buffer);
  v23 = "\nCORRECT!";
  if ( v22 )
    v23 = "\nWhat? no...";
  puts(v23);
  return 0;
}
```

<br />

`v4`, `v5` 값을 활용한 간단한 XOR 연산으로 비밀번호를 체크한다. 
```cpp
__int64 __fastcall sub_1CEB7450000(__int64 buffer)
{
  __int64 i; // r10
  __int64 v3; // rdi
  _QWORD v4[4]; // [rsp-28h] [rbp-28h] BYREF
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF

  for ( i = 0LL; *(_BYTE *)(buffer + i); ++i )
    ;
  if ( i != 18 )
    return 1LL;
  v5 = 1734437990LL;
  v4[3] = &v5;
  v4[2] = 4441LL;
  v4[1] = 0x1352353903521556LL;
  v4[0] = 0x90F2D1D01150F11LL;
  v3 = 0LL;
  while ( i )
  {
    v3 += *((_BYTE *)v4 + i - 1) != (unsigned __int8)(*((_BYTE *)&v5 + (i - 1) % 4uLL) ^ *(_BYTE *)(buffer + i - 1));
    --i;
  }
  return v3;
}
```

<br />

아래와 같이 역연산 코드를 짤 수 있다.

```python

import struct

# v4 데이터 (총 32바이트)
v4_bytes = (
    struct.pack("<Q", 0x90F2D1D01150F11) +       # v4[0]
    struct.pack("<Q", 0x1352353903521556) +      # v4[1]
    struct.pack("<Q", 4441) +                    # v4[2] (4B 유효)
    struct.pack("<Q", 0x0)                       # dummy for alignment
)

v5 = struct.pack("<I", 0x67616C66) 

password = b""

for i in range(18):
    expected = v4_bytes[i]
    mask = v5[i % 4]
    password += bytes([expected ^ mask])

print("Recovered password:", password.decode('latin1'))  

```

<br />

# AngerIssues

ELF 한 개가 주어지며, 실행 시 적절한 60자 입력을 요구한다.

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  printf("Enter the secret string: ");
  fgets(input, 60, stdin);
  checks((__int64)input);
  puts("Yay! You did it!");
  return 0;
}
```

<br />

입력값 체크 로직 형태를 보면 내면에서 잠시 Anger Issue가 발생한다.

```cpp
__int64 __fastcall checks(__int64 a1)
{
  base(a1);
  func0(a1);
  func1();
  func2(a1);
  func3(a1);
  func4(a1);
  func5(a1);
  func6(a1);
  func7(a1);
  func8(a1);
  func9(a1);
  func10(a1);
  ...
  func232(a1);
  func233(a1);
  func234(a1);
  func235(a1);
  func236(a1);
  func237(a1);
  func238(a1);
  return func239(a1);
}
```

<br />

## Approach

다행히 각 func 형태가 복잡하지 않으므로, 금새 Anger Issue를 가라앉힐 수 있었다. ~~문제 닉값이 약하다고 본다.~~

```cpp
__int64 __fastcall func0(__int64 a1)
{
  __int64 result; // rax

  result = (unsigned int)*(char *)(a1 + 12);
  if ( (_DWORD)result != *(char *)(a1 + 24) + 39 )
    errorFunc();
  return result;
}
```

<br />

대부분의 func는 위와 같이 `array[a1] == array[a2] + a3` 형태이거나 아무 내용도 담고 있지 않다. 분석을 위해 어셈블리를 보면 아래와 같다. 형태가 일정하므로, IDA python 스크립트를 활용하여 각 `func{n}`으로부터 `array[a1] == array[a2] + a3`의 `a1, a2, a3`를 추출하는 쪽으로 문제 풀이 방향을 설정하였다.

![image.png](/assets/img/writeups/202503/wolv6.jpg)

<br />

## PoC

각 func{n} 심볼로부터 함수의 주소 값을 파악하고, `array[a1] == array[a2] + a3`의 `a1, a2, a3`를 추출하는 IDA Python 코드이다. 

```python
from idautils import *
from idc import *

def parse_func_offsets(ea):
    insts = list(FuncItems(ea))
    reg_map = {}      # 레지스터가 기준 주소를 가리키고 있는지 (e.g., a1)
    mem_reads = {}    # 레지스터가 메모리에서 어떤 오프셋을 읽었는지
    result = None

    for i in insts:
        mnem = print_insn_mnem(i)

        if mnem == "mov" and "[rbp+var_8]" in print_operand(i, 1):
            reg = print_operand(i, 0)
            reg_map[reg] = 0

        elif mnem == "add":
            reg = print_operand(i, 0)
            val = get_operand_value(i, 1)
            if reg in reg_map:
                reg_map[reg] += val
            elif reg in mem_reads:
                prev = mem_reads[reg]
                if isinstance(prev, tuple):
                    offset, const = prev
                else:
                    offset, const = prev, 0
                mem_reads[reg] = (offset, const + val)

        elif mnem == "sub":
            reg = print_operand(i, 0)
            val = get_operand_value(i, 1)
            if reg in mem_reads:
                prev = mem_reads[reg]
                if isinstance(prev, tuple):
                    offset, const = prev
                else:
                    offset, const = prev, 0
                mem_reads[reg] = (offset, const - val)

        elif mnem in ["movzx", "movsx"]:
            dst = print_operand(i, 0)
            src = print_operand(i, 1)
            if "byte ptr" in src:
                for reg, offset in reg_map.items():
                    if reg in src:
                        mem_reads[dst] = offset

        elif mnem == "cmp":
            op1 = print_operand(i, 0)
            op2 = print_operand(i, 1)

            def resolve(op):
                if op in mem_reads:
                    val = mem_reads[op]
                    if isinstance(val, tuple):
                        return val
                    else:
                        return (val, 0)
                return None

            val1 = resolve(op1)
            val2 = resolve(op2)

            if val1 and val2:
                offset1, const1 = val1
                offset2, const2 = val2
                result = (offset1, offset2, const2 - const1)
                break

    return result


def parse_all_funcs():
    results = []
    for i in range(240):
        name = f"func{i}"
        ea = get_name_ea_simple(name)
        if ea == BADADDR:
            print(f"[!] {name} not found.")
            continue

        res = parse_func_offsets(ea)
        if res:
            print(f"[+] {name}: {res}")
            results.append((name, *res))
        else:
            print(f"[-] {name}: no match")
    return results

parse_all_funcs()

```

<br /> 

추출 결과를 `conditions.txt`에 저장한 다음, `z3`을 이용하여 조건을 만족하는 입력값을 알아내었다.  

```python
from z3 import *

def parse_conditions_from_file(filename):
    conditions = []
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith("[+]"):
                try:
                    parts = line.split(":")
                    values = parts[1].strip().strip("()").split(",")
                    a1, a2, a3 = map(int, values)
                    conditions.append((a1, a2, a3))
                except:
                    continue
    print(f"[+] Parsed {len(conditions)} conditions")
    return conditions

def solve_with_z3(conditions):
    max_index = max(max(a1, a2) for a1, a2, _ in conditions)
    max_index = max(max_index, 42) + 1

    array = [Int(f'array_{i}') for i in range(max_index)]
    s = Solver()

    # 바이트 범위 제한
    for b in array:
        s.add(b >= 0, b <= 255)

    # 조건들 추가
    for a1, a2, a3 in conditions:
        s.add(array[a1] == array[a2] + a3)

    # 초기 조건 (wctf, 마지막 문자 == 'w')
    s.add(array[0] == 119)  # 'w'
    s.add(array[1] == 99)   # 'c'
    s.add(array[2] == 116)  # 't'
    s.add(array[3] == 102)  # 'f'
    s.add(array[42] == array[0])  # array[42] == 'w'

    if s.check() == sat:
        model = s.model()
        flag_bytes = [
            model.evaluate(byte, model_completion=True).as_long()
            for byte in array
        ]

        print("[+] Flag bytes:")
        print(flag_bytes)

        print("[+] As characters:")
        flag_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in flag_bytes)
        print(flag_str)

        return flag_str
    else:
        print("[-] No solution found.")
        return None

if __name__ == "__main__":
    conditions = parse_conditions_from_file("conditions.txt")
    solve_with_z3(conditions)

```

<br />

# Office

ELF 1개가 주어진다. 실행 시 가상 Office에 출근하여 일당을 받거나, 일당 인상을 요구하거나, 사직할 수 있다.

![image.png](/assets/img/writeups/202503/wolv7.jpg)

<br />

## Approach

실행 하였을 때 파악한 로직과 동일하게, 사용자에게 3가지 옵션이 주어진다.

```cpp
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  char s[3]; // [rsp+1h] [rbp-Fh] BYREF
  unsigned int v4; // [rsp+4h] [rbp-Ch]
  FILE *stream; // [rsp+8h] [rbp-8h]

  sub_40149A(a1, a2, a3);
  stream = fopen("/dev/urandom", "r");
  if ( !stream )
  {
    puts("Cannot open /dev/urandom");
    exit(1);
  }
  fread(&initial_balance, 1uLL, 1uLL, stream);
  fclose(stream);
  temp_balance = initial_balance;
  while ( 1 )
  {
    do
    {
      print_selections();
      fgets(s, 3, stdin);
      *__errno_location() = 0;
      v4 = strtol(s, 0LL, 10);
    }
    while ( *__errno_location() );
    if ( v4 == 3 )
      print_flag();
    if ( v4 > 3 )
      break;
    if ( v4 == 1 )
    {
      clock_in();
    }
    else
    {
      if ( v4 != 2 )
        break;
      raise();
    }
LABEL_14:
    if ( balance <= 0 )
    {
      puts("You can't even spend money and yet you lost it all. You're fired.");
      exit(0);
    }
  }
  printf("choice: %d\n", v4);
  goto LABEL_14;
}
```

<br />

`1. clock_in` 시 발생하는 이벤트가 완전 랜덤이 아닌, 잔고와 관련하여 연산된 값에 의존하여 발생한다. 참고로 `byte_40408n` 값들은 모두 특정 값이 정해져 있다.

```cpp
__int64 clock_in()
{
  __int64 result; // rax

  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_404088) != 0 )
    puts("You forget to put the cover sheet on your TPS report");
  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_404089) != 0 )
    puts("You have a meeting with a consultant");
  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_40408A) != 0 )
    puts("The printer jams");
  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_40408B) != 0 )
    puts("Your boss tells you that you have to come in on Saturday");
  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_40408C) != 0 )
    puts("The fire alarm goes off");
  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_40408D) != 0 )
    puts("Your cowworker asks if you have seen his stapler");
  if ( ((unsigned __int8)temp_balance & (unsigned __int8)byte_40408E) != 0 )
    puts("You think about quitting");
  printf("Time to clock out. You made $%d today\n", (unsigned int)clock);
  balance += clock;
  result = balance ^ (unsigned int)(unsigned __int8)temp_balance;
  temp_balance ^= balance;
  return result;
}
```

`3. quit job` 선택 시 현재 잔고가 초기 잔고의 257배일 경우 플래그를 출력하는 히든 이벤트(?)가 있다. 그러므로 option 1과 2를 적절히 활용하여 balance를 initial_balance의 257배로 조정 후 option 3를 선택하면 되겠다. 유일한 문제는 initial_balance가 random하게 결정된다는 점이다.

```cpp
void __noreturn print_flag()
{
  char ptr[56]; // [rsp+0h] [rbp-40h] BYREF
  FILE *stream; // [rsp+38h] [rbp-8h]

  if ( 257 * (unsigned __int8)initial_balance == balance )
  {
    stream = fopen("./flag.txt", "r");
    if ( !stream )
    {
      printf("Cannot open ./flag.txt");
      exit(1);
    }
    fread(ptr, 0x20uLL, 1uLL, stream);
    ptr[32] = 0;
    puts("You were actually nice to have around");
    puts("Here, take this parting gift:");
    puts(ptr);
    exit(0);
  }
  puts("Good riddance");
  exit(0);
}
```

## PoC

Option 1에서 `temp_balance`와 XOR 연산한 결과에 따라 이벤트를 출력하므로, option 1을 선택할 때마다 현재 `temp_balance`의 조건을 알 수 있다. 반복적으로 option 1을 선택하면서, 이외 기타 연산을 적절히 처리하면 initial_balance를 알 수 있다. 이후엔 `initial_balnce`의 257배까지 남은 금액을 clock_in으로 요청하면 된다.

```python
from pwn import *

def check_candidates(candidates,out):
    bitmask_table = {
        "cover sheet":     ("You forget to put the cover sheet", 0x0A),
        "consultant":      ("You have a meeting with a consultant", 0x16),
        "printer":         ("The printer jams", 0x18),
        "saturday":        ("Your boss tells you that you have to come in on Saturday", 0x28),
        "fire alarm":      ("The fire alarm goes off", 0xA8),
        "stapler":         ("Your cowworker asks if you have seen his stapler", 0x60),
        "quitting":        ("You think about quitting", 0x01),
    }
    
    for label, (msg, bit) in bitmask_table.items():
        if msg in out:
            candidates = [i for i in candidates if (i & bit) != 0]
        else:
            candidates = [i for i in candidates if (i & bit) == 0]
    
    return candidates

def xor_update(candidates,balance):
    candidates = [i^balance for i in candidates]
    return candidates

def calculate_goal(candidates, balance):
    candidate = candidates[0]
    while True:
        candidate ^=balance
        balance -=10
        if balance ==1337:
            break
    
    goal = 257 * candidate
    return goal

if __name__=='__main__':
    p = remote("office.kctf-453514-codelab.kctf.cloud", 1337)
    balance = 1337
    candidates = [i for i in range(256)]
    
    out = p.recvuntil(b"> ")
    print(out.decode(errors='ignore'))

    while True:
        print("-------------")
        print(candidates)
        if len(candidates)==1:
            break
        p.send(b"1\n")
        out = p.recvuntil(b"> ")
        print(out.decode(errors='ignore'))
        candidates = check_candidates(candidates,out.decode(errors='ignore'))
        balance += 10
        candidates = xor_update(candidates,balance)
        
    
    goal = calculate_goal(candidates,balance)
    print(balance)
    left = goal-balance
    
    print("[send 2]-----------------------")
    p.send(b"2\n")
    out = p.recvuntil(b"> ")
    print(out.decode(errors='ignore'))
    
    print(f"[send left {left}]-----------------------")
    p.sendline(bytes(str(left), "utf-8"))
    out = p.recvuntil(b"> ")
    print(out.decode(errors='ignore'))
    
    print("[send 1 again]-----------------------")
    p.send(b"1\n")
    out = p.recvuntil(b"> ")
    print(out.decode(errors='ignore'))
    
    print("[send 3]-----------------------")
    p.send(b"3\n")
    out = p.recvall(timeout=2)
    print(out.decode(errors='ignore'))
```