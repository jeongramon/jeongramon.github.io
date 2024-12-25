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
permalink: /2024-12-27-FlareOn_11_Writeup2/
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

작성중...


