---
title: QBAP (QEMU  Binary Analysis Platform)
published: 2025-09-17
description: Binary Analysis Platform
tags: [Side Project]
category: Security
draft: false
---

# 설명 #
The Powerful Binary Analysis Platform

# 만들려는 기능 #
- [ ] Assembly-to-C conversion function
- [ ] Function analysis while loaded into memory
- [ ] Tracing function for complex function structures
- [ ] Function description function using LLM
- [ ] Notification of potential vulnerabilities
- [ ] Fuzzing function using ASAN and AFL
- [ ] Programs to be analyzed are executed on QEMU (difference from other BAPs)
- [ ] Code chat function using LLM
- [ ] Memory structure visualization
- [ ] Network analysis function (when loaded into memory, check what packet information is exchanged)
- [ ] Split view function (view both C and assembly language to check the location of the program)
- [ ] Shellcode recommendation function
- [ ] Provides a Python API for extensions
- [ ] Function Name Suggestion Feature
- [ ] Structure Auto-Completion Feature

# 구조 #
```
QBAP
├── analyzers/
│   ├── func/
│   └── vuln/
├── core/
│   ├── decompile/
│   ├── fuzzer/
│   ├── network/
│   ├── qemu/
│   └── shellcode/
├── docs/
├── ext/
│   └── gdb/
├── gui/
├── llm_modules/
│   └── gpt/
│   └── claude/
│   └── grok/
│   └── deepseek/
│   └── ...
├── tests/
├── utils/
└── readme.md
```


