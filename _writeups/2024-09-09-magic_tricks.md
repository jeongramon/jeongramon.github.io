---
layout: post
title: Magic Tricks
subtitle: CSAW QUALS 2024
thumbnail-img: /assets/img/writeups/202409/2gopher.jpg
tags: [writeups,Reversing,CSAW QUALS 2024]
comments: true

ctf: CSAW QUALS 2024
level: 1              
date: 2024-09-07      
category: Reversing
note: Golang              
---

# 문제 소개
어떤 입력값을 주어야 문제에 주어진 `output.txt`을 만들 수 있는지 찾는 문제이다. Golang 리버싱을 요구한다.
![gopher](/assets/img/writeups/202409/2gopher.jpg)

* TOC
{:toc}

# 코드 분석
`main` 함수가 존재하지 않고 `start` 또한 메인 로직과 크게 관련이 없다. 이외에도 기타 함수의 수와 종류를 보았을 때 `Golang`으로 작성한 파일로 추정된다. 
`Enter any data...`를 `String Search`하면 `sub_48BA80`이 메인 로직임을 알 수 있다. ~~라고 생각했는데 `ida` 최신 버전을 사용하니까 main.main으로 바로 매칭도 해주고 서브루틴 분석도 구 버전과 차이가 많이 난다.~~
사용자 입력 값에 대하여 각각 연산을 한 후 ``output.txt``를 작성하는 로직임을 확인할 수 있다.
~~~cpp
// main.main
void __fastcall main_main()
{
  ...
  fmt_Fprint(
    (unsigned int)off_4CA118,
    qword_541A90,
    (unsigned int)v81,
    1,
    1,
    (unsigned int)&off_4C9C28,                  // "Enter data: "
    v20,
    v21,
    v22,
    v70,
    v71);
  len_str = bufio__ptr_Reader_ReadString(v88, 10LL);
  str = runtime_stringtoslicerune((unsigned int)&v76, len_str, 9, 1, 1, v24, v25, v26, v27, v70, v71, (__int64)v72.ptr);
  for ( i = 0LL; len_str > i; ++i )
  {
    str_char = *(_DWORD *)(str + 4 * i);        // 입력 글자 한글자 당 4바이트 단위로 저장
    n0 = str_char;
    n1 = (2LL * (str_char - 1)) ^ (str_char + 23LL);
    n2 = (n1 + ((unsigned __int64)(n1 >> 63) >> 62)) & 0xFFFFFFFFFFFFFFFCLL;
    n3 = n1 % 4 + 2 * n0 - 32;
    *(_DWORD *)(str + 4 * i) = n3;
  }
  
  ...
  v64 = os_WriteFile((int)"output.txt", 10, v58, v53, v59, 420, v61, v62, v63, v70, v71, v72, v73);
  ...
}
~~~

# PoC
~~~python
def decode(data):
    dictionary = []
    for i in range(0,255):
        n0 = i
        n1 = (2 * (i - 1)) ^ (i + 23);
        #n2 = (n1 + ((n1 >> 63) >> 62)) & 0xFFFFFFFFFFFFFFF;
        n3 = n1 % 4 + 2 * n0 - 32
        dictionary.append(n3)  
    result  = ''
    for ch in data:
        print(ch)
        for i in range(0,255):
            if ord(ch)==dictionary[i]:
                result += (chr(i))
    return result
if __name__=='__main__':
    with open('output.txt','r',encoding='utf-8') as f:
        data = f.read()
    flag = decode(data)
    print(flag)
~~~

