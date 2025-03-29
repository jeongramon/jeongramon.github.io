---
layout: post
title: Kalmar CTF 2025 Writeup
subtitle: Shafus, FlagSecurityEngine, Snake I
thumbnail-img: /assets/img/writeups/202503/kalmar0.png
tags: [Writeup, Reversing]
comments: true
ctf: KalmarCTF 2025
color: d5f5e3
ctf_date: 2025-03-07
probs:
  - [Snake I, Very Easy, Reversing, Super Nintendo Entertainment System (SNES)]
  - [FlagSecurityEngine, Very Easy, Reversing, ]
  - [Shafus, Very Easy, Reversing, ]
---

`Kalmar CTF 2025`에 `Team jejupork`로 참여하였다. 문제가 전반적으로 좀 어려웠다...

<br />

{% include problems.html probs=page.probs %}

# Snake I

`.sfc` 파일이 1개 주어진다. Super Nintendo Entertainment System (SNES) 게임의 롬(Rom) 파일 확장자라고 한다. ~~말로만 듣던 패미컴 시절 ㄷㄷ~~ 

에뮬레이터를 이용하여 실행 시 애벌레를 조작하여 사과를 먹는 게임이 실행되며, 사과를 먹을 때 마다 특정 문자가 게임 우상단에 출력된다.

![image.png](/assets/img/writeups/202503/kalmar1.png)

# 