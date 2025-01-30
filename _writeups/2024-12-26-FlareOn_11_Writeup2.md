---
layout: post
title: Flare-On 11 Writeup (6-10)
subtitle: bloke2
thumbnail-img: /assets/img/writeups/202412/6_1.png
tags: [Writeup, Reversing]
comments: true
ctf: Flare-on 11
color: FFB6B6
ctf_date: 2024-10-27
probs:
  - [bloke2, 6, Reversing, Verilog]
---

[Flare-On 11 Writeup (1-5)](https://blog.jeongramon.dev/2024-12-02-FlareOn_11_Writeup/)에서 이어지는 글이다. 

{% include problems.html probs=page.probs %}

<br />

# bloke2
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

 일반 컴파일 파일을 실행 시에는 특이사항이 없다. 대신 `tests`로 빌드한 경우 다음과 같이 특별한 출력 값을 가진다. 

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

# fullspeed

.NET exe 파일과 pcap 파일이 주어진다. pcap 파일 내에는 192.168.56.103:31337과 패킷 몇 개를 주고받은 기록이 있다.

## 초기 접근

### AOT 

닷넷이므로 전용 디컴파일러를 활용하여 간편히 분석하려 하였으나, 오류가 발생하였다. 

![image.png](/assets/img/writeups/202412/7_0.png)

<br />

`PEview`로 실행파일의 구조를 확인하니, `.managed`와 `.hydrated` 섹션을 확인하였다. 이 두 섹션은 `.NET` 파일이 `AOT` 컴파일되었을 떄 존재한다.

![image.png](/assets/img/writeups/202412/7_1.png)

<br />

우리가 평소 마주하는 `.NET`은 `JIT` 컴파일 방식으로, 초기 실행 시에 바이트코드를 컴파일하는 과정을 거치는 특징이 있어 `ILspy`와 같은 전용 디컴파일러로 쉽게 해석이 가능하다. 그러나 `AOT` 방식의 경우 이러한 실행 시점의 컴파일이 없어, 앞서 언급한 닷넷 전용 디컴파일러로는 디컴파일이 어렵다.

또한 `IDA`에 `.NET AOT` 관련 시그니처가 없는 듯하다... 그래서 `IDA`로 문제 파일을 열면 아래와 같이 시그니처 하나 없는 척박한 바이너리를 마주하게 된다.
![image.png](/assets/img/writeups/202412/7_2.png)

<br />

### BouncyCastle(AOT) FLIRT Signature 생성 / 로드

String Search를 통하여 `exe` 내 [BouncyCastle](https://github.com/bcgit/bc-csharp.git)의 `commit 83ebf4a805... version`을 사용하였음을 알 수 있다. 

![image.png](/assets/img/writeups/202412/7_3.png)

<br />

`IDA`에는 바이너리를 분석하여 직접 시그니처를 생성하고, 이를 내가 분석 중인 파일에 로드하는 기능을 제공한다. 이를 `FLIRT Signature`라 부르는데 상세한 방법은 링크를 참조 바란다. 

직접 `BouncyCastle`을 `AOT Compile`하고, `FLIRT Signature`를 추출한 다음 문제 파일에 로드하면 어느 정도의 시그니처를 얻을 수 있다.

![image.png](/assets/img/writeups/202412/7_7.png)

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

`pcap` 내용을 봤을 때 예상할 수 있듯, `192.168.56.103:31337`과 패킷을 주고받는 기능을 수행함을 알 수 있다. `decrypt_string`의 결과는 동적 분석을 통해 얻어내었으며, `v4 = sub_7FF6649C4000(IP_PORT, (int)v3, 0, 0x7FFFFFFF, 0);`에서 `rcx->offset` 부분에서 `127.0.0.1`로 패치한 다음 로컬에 서버를 구축하면 원활하게 이후 동적 분석을 시행할 수 있다.

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

메인 로직 중 이 부분이 찾기 가장 어렵다. 메인 로직의 뒷부분을 보면 패킷을 송수신하는 역할을 상대적으로 쉽게 발견할 수 있다. 그런데 선행되어야 할 암호화 관련 시드나 키 설정 등이 전혀 보이지 않아서 뒤지다 보니까 발견할 수 있었다.

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

찾기 어려운 이유는 반복문을 돌며 런타임 환경에서, `((void (*)(void))v3)();`으로 여러 함수를 동적 호출하는 과정에 `main_logic_1_0()`이 실행되기 떄문이다. ~~악랄하다~~

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
       **   ((void (*)(void))v3)();**
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

아래 코드는 `ECDH` 디피헬만 상에서 타원 곡선을 정의하는 함수로 볼 수 있다. 

```cpp
__int64 mainlogic_1_0()
{
	...

  q = RhpNewFast(&unk_7FF664A6B268);
  v1 = decrypt_string(&off_7FF664A4FC68);       // c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd
  sub_7FF66497B680(q, v1, 16LL);
  a = RhpNewFast(&unk_7FF664A6B268);
  v3 = decrypt_string(&off_7FF664A4FA90);       // a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
  sub_7FF66497B680(a, v3, 16LL);
  b = RhpNewFast(&unk_7FF664A6B268);
  v5 = decrypt_string(&off_7FF664A4EEC8);       // 9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380
  sub_7FF66497B680(b, v5, 16LL);
  v6 = RhpNewFast(&unk_7FF664A6B268);
  G_x = decrypt_string(&off_7FF664A4EC18);      // 087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
  sub_7FF66497B680(v6, G_x, 16LL);
  v8 = RhpNewFast(&unk_7FF664A6B268);
  G_y = decrypt_string(&off_7FF664A4E860);      // 127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182
  sub_7FF66497B680(v8, G_y, 16LL);
  v10 = RhpNewFast(&unk_7FF664A6B618);
  sub_7FF664985810(v10, q, a, b, 0LL, 0LL, 0);
  if ( qword_7FF664A68FC0[-1] )
    mainlogic_1();
  v11 = qword_7FF664B48A68;
  RhpAssignRefAVLocation(qword_7FF664B48A68 + 8, v10);
  v12 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(**(_QWORD **)(v11 + 8) + 88LL))(
          *(_QWORD *)(v11 + 8),
          v6,
          v8);
  RhpAssignRefAVLocation(v11 + 16, v12);
  random = RhpNewFast(&unk_7FF664A6B188);
  Prng = CreatePrng(&off_7FF664A59B98, 1LL);
  sub_7FF6649D0380(random, 0LL);
  RhpAssignRefAVLocation(random + 16, Prng);
  return RhpAssignRefAVLocation(v11 + 24, random);
}
```

### main_logic_2

