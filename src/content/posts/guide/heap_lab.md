---
title: Heap Exploitation LAB
published: 2024-12-11
description: Platypwn CTF 2024 Write-Up
tags: [CTF]
category: Hacking
draft: false
---

# Code #
다양한 힙 공격을 해보기 위해 만든 코드입니다.

```
#include <stdio.h>
#include <stdlib.h>

void menu()
{
    printf("\n");
    printf("--------------------------------------------------\n");
    printf("|            The Heap Exploitation Lab           |\n");
    printf("--------------------------------------------------\n");
    printf("\n");
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Edit\n");
    printf("4. Print\n");
    printf("> ");
}

int main()
{
    int select;
    int ptr_length;
    int size;
    int idx;

    printf("--------------------------------------------------\n");
    printf("|            The Heap Exploitation Lab           |\n");
    printf("--------------------------------------------------\n");

    printf("Array Size: ");
    scanf("%d", &ptr_length);

    void* ptr[ptr_length];

    while (1)
    {
        menu();
        scanf("%d", &select);
        switch (select)
        {
            case 1:
               printf("Allocation Size: ");
               scanf("%d", &size);
               printf("Index: ");
               scanf("%d", &idx);
               ptr[idx] = malloc(size);
               break;
            case 2:
               printf("Free Index: ");
               scanf("%d", &idx);
               free(ptr[idx]);
               break;
            case 3:
               printf("Read Size: ");
               scanf("%d", &size);
               printf("Index: ");
               scanf("%d", &idx);
               read(0, ptr[idx], size);
               break;
            case 4:
               printf("Write Index: ");
               scanf("%d", &idx);
               printf(ptr[idx]);
               break;
        }
    }
}
```