---
title: calc
published: 2024-12-11
description: calc
tags: [Pwnable.tw]
category: WarGame
draft: false
---

# 문제 설명 #
Have you ever use Microsoft calculator?

nc chall.pwnable.tw 10100

# 코드 분석

IDA를 이용해 디컴파일 해보면 main 함수는 다음과 같이 calc라는 함수를 호출한다.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ssignal(14, timeout);
  alarm(60);
  puts("=== Welcome to SECPROG calculator ===");
  fflush(stdout);
  calc();
  return puts("Merry Christmas!");
}
```

calc() 함수의 코드는 다음과 같다. 아래 코드를 보면 bzero 함수를 이용해 operators 버퍼를 0x400 바이트 만큼 초기화한다.
초기화가 끝난 후에는 get_expr함수에서 operators 버퍼에 대해서 연산자가 포함되어 있는지에 대해서 검사한다.
그리고 init_pool함수를 이용해 numbers 버퍼를 초기화 하고, parse_expr함수에서는 operators, numbers에 대한 expression에 대해서 parsing한다.
마지막으로 printf함수를 이용해 계산한 값을 출력한다.

### calc 함수 ###
```
unsigned int calc()
{
  _DWORD numbers[101]; // [esp+18h] [ebp-5A0h] BYREF
  _BYTE operators[1024]; // [esp+1ACh] [ebp-40Ch] BYREF
  unsigned int canary; // [esp+5ACh] [ebp-Ch]

  canary = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(operators, 0x400u);
    if ( !get_expr((int)operators, 1024) )
      break;
    init_pool(numbers);
    if ( parse_expr(operators, numbers) )
    {
      printf("%d\n", numbers[numbers[0]]);
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ canary;
}
```

### get_expr 함수 ###
```
int __cdecl get_expr(int buf, int len)
{
  int v2; // eax
  char operator; // [esp+1Bh] [ebp-Dh] BYREF
  int v5; // [esp+1Ch] [ebp-Ch]

  v5 = 0;
  while ( v5 < len && read(0, (int)&operator, 1) != -1 && operator != '\n' )
  {
    if ( operator == '+'
      || operator == '-'
      || operator == '*'
      || operator == '/'
      || operator == '%'
      || operator > '/' && operator <= '9' )
    {
      v2 = v5++;
      *(_BYTE *)(buf + v2) = operator;
    }
  }
  *(_BYTE *)(v5 + buf) = 0;
  return v5;
}
```

### parse_expr 함수

```
int __cdecl parse_expr(int operators, _DWORD *numbers)
{
  int idx1; // eax
  int _operators; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int idx2; // [esp+28h] [ebp-80h]
  int size; // [esp+2Ch] [ebp-7Ch]
  char *number; // [esp+30h] [ebp-78h]
  int _number; // [esp+34h] [ebp-74h]
  _BYTE operator[100]; // [esp+38h] [ebp-70h] BYREF
  unsigned int canary; // [esp+9Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  _operators = operators;
  idx2 = 0;
  bzero(operator, 0x64u);
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)(*(char *)(i + operators) - 48) > 9 )
    {
      size = i + operators - _operators;
      number = (char *)malloc(size + 1);
      memcpy(number, _operators, size);
      number[size] = 0;
      if ( !strcmp(number, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      _number = atoi(number);
      if ( _number > 0 )
      {
        idx1 = (*numbers)++;
        numbers[idx1 + 1] = _number;
      }
      if ( *(_BYTE *)(i + operators) && *(char *)(i + 1 + operators) - (unsigned int)'0' > 9 )
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      _operators = i + 1 + operators;
      if ( operator[idx2] )
      {
        switch ( *(_BYTE *)(i + operators) )
        {
          case '%':
          case '*':
          case '/':
            if ( operator[idx2] != 43 && operator[idx2] != 45 )
              goto LABEL_14;
            operator[++idx2] = *(_BYTE *)(i + operators);
            break;
          case '+':
          case '-':
LABEL_14:
            eval(numbers, operator[idx2]);
            operator[idx2] = *(_BYTE *)(i + operators);
            break;
          default:
            eval(numbers, operator[idx2--]);
            break;
        }
      }
      else
      {
        operator[idx2] = *(_BYTE *)(i + operators);
      }
      if ( !*(_BYTE *)(i + operators) )
        break;
    }
  }
  while ( idx2 >= 0 )
    eval(numbers, operator[idx2--]);
  return 1;
}
```

