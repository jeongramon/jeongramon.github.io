---
layout: post
title: Whitehat Conference QUALS 2024 Writeup
subtitle: Stop Happy Act, Dump
thumbnail-img: /assets/img/writeups/202410/0whitehat.jpg
tags: [Writeup, Reversing, Forensics]
comments: true
ctf: Whitehat Conference QUALS 2024
color: f0f0f0
ctf_date: 2024-10-19
probs:
  - [Dump, Very Easy, Forensics, Non-Resident File Recovery]
  - [Stop Happy Act, Easy, Reversing, AES]
---

2024년 10월 19일 개최된 `Whitehat 2024` 예선 국방트랙에 `싸축 C` 팀으로 참여, 5위로 ~~아마도~~ 예선 통과하였다.  

{% include problems.html probs=page.probs %}

<br />

# Dump

`E01` 이미지가 제공되었으며, 삭제된 기밀 파일의 무결성이 훼손되었다며 복구를 요구한다.

<br />

## 복구 대상 파일 찾기

`autopsy`를 이용하여 이미지를 분석하였다. 휴지통에서 `pdf` 1개가 삭제되었고, 휴지통에서조차 삭제된 것을 확인할 수 있다.

![image.png](/assets/img/writeups/202410/2recycle.jpg)

<br />

`$I` 파일에서 확인한 원본 파일의 경로를 따라가면 `MFT` 메타 데이터만 남아있다. 메타 데이터의 `$DATA` 속성이 남아 있어, `Starting address: 3491442`에서 이 파일이 `Non-Resident` 파일이고, 클러스터 3491442에 실 데이터가 저장되었었음을 알 수 있다.

![image.png](/assets/img/writeups/202410/3metadata.jpg)

<br />

## pdf 복구

`FTK Imager`는 `Go to Sector / Cluster` 기능을 지원한다. 클러스터 3491442로 이동하여 시그니처 `%PDF-`로 시작, `%%EOF`로 끝나는 `Raw Data`를 카빙하면 원본 `PDF`를 얻을 수 있다.

![image.png](/assets/img/writeups/202410/1pdf.jpg)

<br />

# Stop Happy Act
`C&C` 서버로부터 암호화된 명령을 받아 복호화 후 해당하는 명령을 실행한다. 문제 조건에 따라 `STOP` 명령을 실행하는 `string`을 찾으면 된다.
대회 후 후기를 보니 `AES` 암호화라는 사실만 알면 직접 복호화 코드를 짤 필요 없이 쉽게 풀 수 있다고 한다. 나는 몰랐다. ~~모르면 얼마나 고생하는지 보여주겠다.~~

<br />

## 메인 코드 분석
`172.24.9.190:8080` 서버와 통신을 요구한다. 나는 `ip`를 `127.0.0.1`로 패치한 다음, 로컬 가상 서버를 구축하여 동적 디버깅을 용이하게 하였다.
`read_fd()`에서 서버에서의 송신 값을 처리하고, `respond_data()`에서 그 값을 처리한다.

~~~cpp
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  const char *v4; // rax
  uint16_t port; // ax
  const char *ip; // rax
  int fd; // [rsp+20h] [rbp-40h]
  __int64 buf; // [rsp+30h] [rbp-30h] BYREF
  char v9[8]; // [rsp+38h] [rbp-28h] BYREF
  struct sockaddr addr; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v11; // [rsp+58h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  fd = socket(2, 1, 0);
  if ( fd >= 0 )
  {
    addr.sa_family = 2;
    v4 = (const char *)base64_decode("ODA4MA==", 8LL, v9);
    port = atoi(v4);                            // 8080
    *(_WORD *)addr.sa_data = htons(port);
    ip = (const char *)base64_decode("MTI3LjAuMC4x", 16LL, v9);// 172.24.9.190 -> 127.0.0.1 patched
    if ( inet_pton(2, ip, &addr.sa_data[2]) > 0 )
    {
      if ( connect(fd, &addr, 0x10u) < 0 )
      {
        puts("connect error");
        sleep(0xAu);
      }
      while ( check_value )
      {
        read_fd((unsigned int)fd, &buf);
        respond_opcode((unsigned int)fd, buf);
        sleep(1u);
      }
      return 1LL;
    }
    else
    {
      puts("inet_pton error");
      return 0xFFFFFFFFLL;
    }
  }
  else
  {
    puts("socket creation error");
    return 0xFFFFFFFFLL;
  }
}
~~~

<br />

`translate_opcode(buf,"STOP",2)`를 만족하도록 알맞는 `buf`(서버에서의 송신 값)을 구해주면 된다.

~~~cpp
__int64 __fastcall respond_opcode(unsigned int fd, const char *buf)
{
  if ( translate_opcode(buf, "STOP", 2) )
  {
    check_value = 0;
    return 1LL;
  }
  ...
~~~

<br />

## 암호화 로직 분석
`key`는 코드 내 정해진 값으로 생성되므로 `make_key_final()` 함수 실행 후 `dump`하여 추출하면 된다. 주요 암호화 로직은 `check_main()`에서 이루어진다. 암호화 결과 값을 `off_55555555A080[num - 1]`와 비교하여 같은지 체크한다.

~~~cpp
_BOOL8 __fastcall translate_opcode(const char *buf, const char *opcode, int num)
{
  ...
  v12[0] = 0xDA8DA1B609F565A0LL;
  v12[1] = 0x50A0D191961D0F92LL;
  dest = malloc(size);
  memcpy(dest, buf, size);
  make_key((__int64)key);
  len_opcode = strlen(opcode);
  plus_STOP((__int64)key, (__int64)opcode, len_opcode);
  sub_5555555561C8((__int64)key, (__int64)real_key);
  make_key_final(realrealkey, real_key, v12);
  check_main(realrealkey, dest, size);
  s1 = (char *)encode_base64(dest, size, &v6);
  s1[v6] = 0;
  return strcmp(s1, off_55555555A080[num - 1]) == 0;
}
~~~

<br />

`ida`에서 왜 잘못 해석했는지는 모르겠지만 `buf+=0x10`이다. 16바이트씩 나누어 암호화를 진행한다. 최종 결과 값을 `off_55555555A080[num - 1]`과 비교하여야 하므로 입력 값이 48바이트일 것을 예측할 수 있다.

~~~cpp
__int64 __fastcall check_main(__int64 key, __int64 *buf, unsigned __int64 size)
{
  ...
  v8 = (__int64 *)(key + 0xF0);
  for ( i = 0LL; i < size; i += 16LL )
  {
    xor_key((__int64)buf, (__int64)v8);
    phase_2(buf, key);
    v8 = buf;
    buf += 2;                                   // 0x10
  }
  ...
}
~~~

<br />

암호화 코드 중 `phase2`는 아래와 같이 생겼는데, 여기서 14라운드짜리 대칭키 암호화 로직이라는 걸 판단을 할 수 있어야 한다. 난 못했으니까 이어서 풀이를 작성하겠다.

~~~cpp
__int64 __fastcall phase_2(_BYTE *buf, __int64 key)
{
  unsigned __int8 i; // [rsp+1Fh] [rbp-1h]

  xor_2(0, (__int64)buf, key);
  for ( i = 1; ; ++i )
  {
    phase2_1((__int64)buf);
    sbox(buf);
    if ( i == 14 )
      break;
    phase2_2((__int64)buf);
    xor_2(i, (__int64)buf, key);
  }
  return xor_2(14u, (__int64)buf, key);
}
~~~

<br />

## PoC
### 복호화 개요
`string length`가 48바이트라는 것을 알고 있으므로 전체 복호화는 아래와 같이 요약할 수 있다. 전체 PoC는 부록을 참조바라며, 추가 설명이 필요한 부분만 작성하겠다.

~~~python
def decode(buf,key):
    inverse_phase_2(buf,key,0x20)
    xor_key(buf,0x20)
    inverse_phase_2(buf,key,0x10)
    xor_key(buf,0x10)
    inverse_phase_2(buf,key,0x00)
    xor_with_key(buf,key)
    return buf
~~~

<br />

### phase2_1_0

복호화 로직을 직접 짜기 복잡해 보인다.
~~~cpp
__int64 __fastcall phase2_1_0(unsigned __int8 a1)
{
  unsigned __int8 v1; // al
  unsigned __int8 v3; // [rsp+1Eh] [rbp-2h]

  v1 = sub_555555556532(a1);
  v3 = (2 * ((2 * ((2 * v1) | (v1 >> 7))) | ((unsigned __int8)((2 * v1) | (v1 >> 7)) >> 7))) | ((unsigned __int8)((2 * ((2 * v1) | (v1 >> 7))) | ((unsigned __int8)((2 * v1) | (v1 >> 7)) >> 7)) >> 7);
  return ((v3 >> 7) | (2 * v3)) ^ (unsigned __int8)(v3 ^ ((2 * ((2 * v1) | (v1 >> 7))) | ((unsigned __int8)((2 * v1) | (v1 >> 7)) >> 7)) ^ ((2 * v1) | (v1 >> 7)) ^ v1) ^ 0x63u;
}
~~~

<br />

그러나 입력 파라미터와 `return` 파라미터가 `int8` 범위 내 (0~255)로 한정되므로, `bp`를 설치하여 이 함수의 입력`(edi)` 및 반환`(al)` 값을 관찰하였다. (아래 코드 참조)
이를 통해 `{key:value}` 값을 수집하고, 이를 역연산 코드 내에 하드 코딩했다. 수집이 안된 값은 직접 `edi`를 패치하여서 함수를 실행해보고 `al`을 얻으면 된다.

~~~python
import idaapi
import idc
import idautils

# Dictionary to store the values in {edi: al} format
value_map = {}

# Event handler class for breakpoints
class MyBreakpointHandler(idaapi.DBG_Hooks):
    def __init__(self):
        super().__init__()
    
    # Callback for when a breakpoint is hit
    def dbg_bpt(self, tid, ea):
        if ea == 0x0000555555556569:
            # Get the value of the edi register at the first breakpoint
            edi_value = idc.get_reg_value("edi")
            value_map['current_edi'] = edi_value
            print(f"Breakpoint 1 hit at {hex(ea)}: edi = {edi_value}")
        elif ea == 0x00005555555565FB:
            # Get the value of the al register at the second breakpoint
            al_value = idc.get_reg_value("al")
            edi_value = value_map.get('current_edi')
            if edi_value is not None:
                # Store the edi:al pair in the value_map
                value_map[edi_value] = al_value
                print(f"Recorded {len(value_map)}")
                print(f"{value_map}")
        return 0

# Install breakpoints
first_bp_addr = 0x0000555555556569
second_bp_addr = 0x00005555555565FB

# Set breakpoints at the specified addresses
idc.add_bpt(first_bp_addr)
idc.add_bpt(second_bp_addr)

# Create and hook the breakpoint handler
bpt_handler = MyBreakpointHandler()
bpt_handler.hook()

print("Breakpoints set. The script will now record {edi: al} values.")
~~~

<br />

### phase2_2

이 경우도 직관적으로 복호화를 할 방법이 떠오르지 않았다.

~~~cpp
void __fastcall phase2_2(__int64 buf)
{
  unsigned __int8 i; // [rsp+14h] [rbp-4h]
  char v0; // [rsp+15h] [rbp-3h]
  char v0123; // [rsp+16h] [rbp-2h]

  for ( i = 0; i <= 3u; ++i )
  {
    v0 = *(_BYTE *)(buf + 4LL * i);
    v0123 = *(_BYTE *)(buf + 4LL * i + 2) ^ *(_BYTE *)(buf + 4LL * i + 1) ^ v0 ^ *(_BYTE *)(buf + 4LL * i + 3);
    *(_BYTE *)(buf + 4LL * i) = v0123 ^ phase2_2_0((unsigned __int8)(v0 ^ *(_BYTE *)(buf + 4LL * i + 1))) ^ v0;
    *(_BYTE *)(buf + 4LL * i + 1) ^= v0123 ^ (unsigned __int8)phase2_2_0((unsigned __int8)(*(_BYTE *)(buf + 4LL * i + 1) ^ *(_BYTE *)(buf + 4LL * i + 2)));
    *(_BYTE *)(buf + 4LL * i + 2) ^= v0123 ^ (unsigned __int8)phase2_2_0((unsigned __int8)(*(_BYTE *)(buf + 4LL * i + 2) ^ *(_BYTE *)(buf + 4LL * i + 3)));
    *(_BYTE *)(buf + 4LL * i + 3) ^= v0123 ^ (unsigned __int8)phase2_2_0((unsigned __int8)(v0 ^ *(_BYTE *)(buf + 4LL * i + 3)));
  }
}
~~~

<br />

2개 변수에 대하여 전수 조사를 함으로써 해결하였다. 때문에 여기서 연산 시간이 많이 소모됐다. 

~~~python
def phase2_2(buf,off):
    for i in range(3,-1,-1):
        v0 = buf[off+4*i]
        v1 = buf[off+4*i+1]
        v2 = buf[off+4*i+2]
        v3 = buf[off+4*i+3]
        for v0123 in range(256):
            for v3_bef in range(256):
                v0_bef = phase2_2_0(v3 ^ v0123 ^ v3_bef) ^ v3_bef
                v1_bef = phase2_2_0(v0 ^ v0123 ^ v0_bef) ^ v0_bef
                v2_bef = phase2_2_0(v1 ^ v0123 ^ v1_bef) ^ v1_bef
                v3_check = phase2_2_0(v2 ^ v0123 ^ v2_bef) ^ v2_bef
                if (v3_check==v3_bef and (v0_bef ^ v1_bef ^ v2_bef ^ v3_bef ==v0123)):
                    buf[off+4*i] = v0_bef
                    buf[off+4*i+1] = v1_bef
                    buf[off+4*i+2] = v2_bef
                    buf[off+4*i+3] = v3_bef
~~~

<br />

## 부록
### PoC.py
~~~python
import base64
import struct

def xor_2(num,buf,key,off):
    for i in range(3,-1,-1):
        for j in range(3,-1,-1):
            buf[off+4*i+j] ^= key[4*(4*num+i)+j]

def phase2_2_0(num):
    key = {0: 0, 1: 2, 2: 4, 3: 6, 4: 8, 5: 10, 6: 12, 7: 14, 8: 16, 9: 18, 10: 20, 11: 22, 12: 24, 13: 26, 14: 28, 15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 40, 21: 42, 22: 44, 23: 46, 24: 48, 25: 50, 26: 52, 27: 54, 28: 56, 29: 58, 30: 60, 31: 62, 32: 64, 33: 66, 34: 68, 35: 70, 36: 72, 37: 74, 38: 76, 39: 78, 40: 80, 41: 82, 42: 84, 43: 86, 44: 88, 45: 90, 46: 92, 47: 94, 48: 96, 49: 98, 50: 100, 51: 102, 52: 104, 53: 106, 54: 108, 55: 110, 56: 112, 57: 114, 58: 116, 59: 118, 60: 120, 61: 122, 62: 124, 63: 126, 64: 128, 65: 130, 66: 132, 67: 134, 68: 136, 69: 138, 70: 140, 71: 142, 72: 144, 73: 146, 74: 148, 75: 150, 76: 152, 77: 154, 78: 156, 79: 158, 80: 160, 81: 162, 82: 164, 83: 166, 84: 168, 85: 170, 86: 172, 87: 174, 88: 176, 89: 178, 90: 180, 91: 182, 92: 184, 93: 186, 94: 188, 95: 190, 96: 192, 97: 194, 98: 196, 99: 198, 100: 200, 101: 202, 102: 204, 103: 206, 104: 208, 105: 210, 106: 212, 107: 214, 108: 216, 109: 218, 110: 220, 111: 222, 112: 224, 113: 226, 114: 228, 115: 230, 116: 232, 117: 234, 118: 236, 119: 238, 120: 240, 121: 242, 122: 244, 123: 246, 124: 248, 125: 250, 126: 252, 127: 254, 128: 27, 129: 25, 130: 31, 131: 29, 132: 19, 133: 17, 134: 23, 135: 21, 136: 11, 137: 9, 138: 15, 139: 13, 140: 3, 141: 1, 142: 7, 143: 5, 144: 59, 145: 57, 146: 63, 147: 61, 148: 51, 149: 49, 150: 55, 151: 53, 152: 43, 153: 41, 154: 47, 155: 45, 156: 35, 157: 33, 158: 39, 159: 37, 160: 91, 161: 89, 162: 95, 163: 93, 164: 83, 165: 81, 166: 87, 167: 85, 168: 75, 169: 73, 170: 79, 171: 77, 172: 67, 173: 65, 174: 71, 175: 69, 176: 123, 177: 121, 178: 127, 179: 125, 180: 115, 181: 113, 182: 119, 183: 117, 184: 107, 185: 105, 186: 111, 187: 109, 188: 99, 189: 97, 190: 103, 191: 101, 192: 155, 193: 153, 194: 159, 195: 157, 196: 147, 197: 145, 198: 151, 199: 149, 200: 139, 201: 137, 202: 143, 203: 141, 204: 131, 205: 129, 206: 135, 207: 133, 208: 187, 209: 185, 210: 191, 211: 189, 212: 179, 213: 177, 214: 183, 215: 181, 216: 171, 217: 169, 218: 175, 219: 173, 220: 163, 221: 161, 222: 167, 223: 165, 224: 219, 225: 217, 226: 223, 227: 221, 228: 211, 229: 209, 230: 215, 231: 213, 232: 203, 233: 201, 234: 207, 235: 205, 236: 195, 237: 193, 238: 199, 239: 197, 240: 251, 241: 249, 242: 255, 243: 253, 244: 243, 245: 241, 246: 247, 247: 245, 248: 235, 249: 233, 250: 239, 251: 237, 252: 227, 253: 225, 254: 231, 255: 229}
    matching_keys = [k for k, v in key.items() if v == num]
    if len(matching_keys)!=1:
        print("error")
    else:
        return matching_keys[0]
    
    
def phase2_2(buf,off):
    for i in range(3,-1,-1):
        v0 = buf[off+4*i]
        v1 = buf[off+4*i+1]
        v2 = buf[off+4*i+2]
        v3 = buf[off+4*i+3]
        for v0123 in range(256):
            for v3_bef in range(256):
                v0_bef = phase2_2_0(v3 ^ v0123 ^ v3_bef) ^ v3_bef
                v1_bef = phase2_2_0(v0 ^ v0123 ^ v0_bef) ^ v0_bef
                v2_bef = phase2_2_0(v1 ^ v0123 ^ v1_bef) ^ v1_bef
                v3_check = phase2_2_0(v2 ^ v0123 ^ v2_bef) ^ v2_bef
                if (v3_check==v3_bef and (v0_bef ^ v1_bef ^ v2_bef ^ v3_bef ==v0123)):
                    buf[off+4*i] = v0_bef
                    buf[off+4*i+1] = v1_bef
                    buf[off+4*i+2] = v2_bef
                    buf[off+4*i+3] = v3_bef
    

def sbox(buf,off):    
    v5 = buf[off + 7]
    buf[off + 7] = buf[off + 11]
    buf[off + 11] = buf[off + 15]
    buf[off + 15] = buf[off + 3]
    buf[off + 3] = v5

    v4 = buf[off + 14]
    buf[off + 14] = buf[off + 6]
    buf[off + 6] = v4

    v3 = buf[off + 10]
    buf[off + 10] = buf[off + 2]
    buf[off + 2] = v3

    v2 = buf[off + 13]
    buf[off + 13] = buf[off + 9]
    buf[off + 9] = buf[off + 5]
    buf[off + 5] = buf[off + 1]
    buf[off + 1] = v2

    return 0

def phase2_1_0(num):
    key = {135: 23, 151: 136, 38: 247, 172: 145, 45: 216, 150: 144, 18: 201, 199: 198, 108: 80, 142: 25, 188: 101, 104: 69, 23: 240, 217: 53, 192: 186, 216: 97, 241: 161, 15: 118, 147: 220, 177: 200, 100: 67, 14: 171, 66: 44, 3: 123, 21: 89, 170: 172, 148: 34, 232: 155, 234: 135, 212: 72, 35: 38, 17: 130, 207: 138, 164: 73, 43: 241, 183: 169, 94: 88, 91: 57, 54: 5, 52: 24, 185: 86, 193: 120, 47: 21, 112: 81, 160: 224, 159: 219, 115: 143, 211: 102, 218: 87, 81: 209, 113: 163, 63: 117, 153: 238, 67: 26, 72: 82, 176: 231, 144: 96, 247: 104, 227: 17, 184: 108, 209: 62, 204: 75, 252: 176, 125: 255, 69: 110, 102: 51, 130: 19, 98: 170, 88: 106, 105: 249, 222: 29, 4: 242, 169: 211, 95: 207, 120: 188, 202: 116, 240: 140, 158: 11, 97: 239, 30: 114, 255: 22, 78: 47, 50: 35, 165: 6, 106: 2, 90: 190, 27: 175, 31: 192, 131: 236, 111: 168, 116: 146, 221: 193, 253: 84, 89: 203, 107: 127, 237: 85, 57: 18, 33: 253, 205: 189, 210: 181, 44: 113, 231: 148, 189: 122, 239: 223, 179: 109, 109: 60, 136: 196, 228: 105, 76: 41, 101: 77, 196: 28, 245: 230, 127: 210, 37: 63, 201: 221, 233: 30, 175: 121, 248: 65, 12: 254, 190: 174, 254: 187, 161: 50, 75: 179, 64: 9, 118: 56, 58: 128, 219: 185, 80: 83, 26: 162, 152: 70, 244: 191, 110: 159, 230: 142, 92: 74, 51: 195, 48: 4, 235: 233, 121: 182, 77: 227, 99: 251, 145: 129, 119: 245, 149: 42, 82: 0, 61: 39, 84: 32, 163: 10, 49: 199, 36: 54, 22: 71, 137: 167, 13: 215, 178: 55, 182: 78, 223: 158, 225: 248, 56: 7, 29: 164, 83: 237, 124: 16, 28: 156, 220: 134, 123: 33, 65: 131, 249: 153, 133: 151, 86: 177, 214: 246, 1: 124, 132: 95, 6: 111, 162: 58, 7: 197, 117: 157, 103: 133, 157: 94, 200: 232, 93: 76, 19: 125, 213: 3, 62: 178, 143: 115, 156: 222, 236: 206, 146: 79, 134: 68, 24: 173, 208: 112, 0: 99, 242: 137, 5: 107, 128: 205, 122: 218, 39: 204, 229: 217, 32: 183, 198: 180, 238: 40, 46: 49, 16: 202, 206: 139, 203: 31, 114: 64, 173: 149, 141: 93, 42: 229, 224: 225, 126: 243, 70: 90, 85: 252, 34: 147, 129: 12, 55: 154, 60: 235, 194: 37, 2: 119, 155: 20, 171: 98, 250: 45, 187: 234, 41: 165, 8: 48, 166: 36, 20: 250, 53: 150, 195: 46, 226: 152, 140: 100, 40: 52, 74: 214, 180: 141, 197: 166, 174: 228, 71: 160, 68: 27, 138: 126, 243: 13, 167: 92, 59: 226, 25: 212, 186: 244, 87: 91, 79: 132, 9: 1, 139: 61, 246: 66, 181: 213, 168: 194, 73: 59, 191: 8, 251: 15, 11: 43, 96: 208, 154: 184}
# 0부터 255까지의 값 집합
    key[10] = 0x67
    key[215] = 0x0e
    matching_keys = [k for k, v in key.items() if v == num]
    if len(matching_keys)!=1:
        print("error")
    else:
        return matching_keys[0]
    
def phase2_1(buf,off):
    for i in range(3,-1,-1):
        for j in range(3,-1,-1):
            buf[off+i+4*j] = phase2_1_0(buf[off+i+4*j])

def inverse_phase_2(buf,key,off):
    xor_2(14,buf,key,off)
    sbox(buf,off)
    phase2_1(buf,off)
    for i in range(13,0,-1):
        xor_2(i,buf,key,off)
        phase2_2(buf,off)
        sbox(buf,off)
        phase2_1(buf,off)
    xor_2(0,buf,key,off)
    return 0

def xor_key(buf,off):
    for i in range(0xF,-1,-1):
        buf[off+i] ^= buf[off-0x10+i]

def xor_with_key(buf,key): #checked
    for i in range(0xF,-1,-1):
        buf[i] ^= key[0xF0+i]
       
def decode(buf,key):
    inverse_phase_2(buf,key,0x20)
    xor_key(buf,0x20)
    inverse_phase_2(buf,key,0x10)
    xor_key(buf,0x10)
    inverse_phase_2(buf,key,0x00)
    xor_with_key(buf,key)
    return buf

if __name__=='__main__':
    result = 'RIOqhp1lPsns8toXWMJBEiyQCOFSLtepe5uXJUzHyBoVXXD6rdC18n4ZB7IssO48'
    decoded_bytes = base64.b64decode(result)
    decoded_bytearray = bytearray(decoded_bytes)
    with open("key.dump","rb") as f:
        key = f.read()
    
    buf = decode(decoded_bytearray,key)
    with open("answer.txt","wb") as d:
        d.write(buf)
~~~