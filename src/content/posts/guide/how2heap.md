---
title: Introduction Heap Exploitation
published: 2024-12-11
description: Platypwn CTF 2024 Write-Up
tags: [CTF]
category: Hacking
draft: false
---

# 목차
1. [first_fit](#first_fit)
2. [fastbin_dup](#fastbin_dup)

# first_fit
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
	fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
	fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
	fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

	fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	fprintf(stderr, "1st malloc(0x512): %p\n", a);
	fprintf(stderr, "2nd malloc(0x256): %p\n", b);
	fprintf(stderr, "we could continue mallocing here...\n");
	fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
	strcpy(a, "this is A!");
	fprintf(stderr, "first allocation %p points to %s\n", a, a);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at %p\n", a);

	fprintf(stderr, "So, let's allocate 0x500 bytes\n");
	c = malloc(0x500);
	fprintf(stderr, "3rd malloc(0x500): %p\n", c);
	fprintf(stderr, "And put a different string here, \"this is C!\"\n");
	strcpy(c, "this is C!");
	fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
	fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.\n");
}
```

## First Fit  ##
First Fit 알고리즘이란 Heap에서 메모리를 해제 이후, 가장 첫번째 공간에 할당하는 알고리즘을 뜻합니다. 

## Code Analysis ##
0x512, 0x256 바이트 크기의 Heap 메모리 공간을 각각 a, b에 할당 시키고, c라는 포인터 변수를 선언했습니다.
```
char* a = malloc(0x512);
char* b = malloc(0x256);
char* c;
```

각 a, b에 대한 메모리 주소를 출력하면 아래와 같습니다.
```
1st malloc(0x512): 0x55d31b3632a0
2nd malloc(0x256): 0x55d31b3637c0
```

이와 같이 두개의 동적 메모리를 할당했습니다. 그리고 a라는 동적 메모리 공간에 "this is A!"라는 문자열을 복사 한 후, 내용을 출력했습니다. 결과는 아래와 같습니다.

```
now let's put a string at a that we can read later "this is A!"
```

그리고 free함수를 통해 a라는 동적 메모리를 해제 한 후 메모리 주소를 출력해보면 결과는 아래와 같습니다.
```
We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at 0x55d31b3632a0
```

a라는 동적 메모리 공간을 해제 한 후, c라는 동적 메모리 공간을 0x500바이트 할당했습니다. 결과를 보면 a의 주소와 c의 주소는 같다는 것을 알 수 있습니다. 

```
3rd malloc(0x500): 0x55d31b3632a0
```

이러한 방법을 이용한 공격 방법을 Use-After-Free 라고 합니다. 이는 말 그대로 메모리를 사용한 후 해제 했을 떄 발생하는 취약점을 뜻합니다.

# fastbin_dup #
```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple double-free attack with fastbins.\n");

	printf("Fill up tcache first.\n");
	void *ptrs[8];
	for (int i=0; i<8; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	printf("Allocating 3 buffers.\n");
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

	printf("1st calloc(1, 8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	printf("Freeing the first one...\n");
	free(a);

	printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	printf("So, instead, we'll free %p.\n", b);
	free(b);

	printf("Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = calloc(1, 8);
	b = calloc(1, 8);
	c = calloc(1, 8);
	printf("1st calloc(1, 8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	assert(a == c);
}
```
(작성중)