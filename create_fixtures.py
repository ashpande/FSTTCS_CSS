#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
create_fixtures.py — writes stdin fixtures for all tasks.v2 slugs into ./fixtures
Each slug gets at least:
  - in1: a 'happy path' input
  - in2: an edge or malformed input (where applicable)
Some also get in3 for a size/bounds stress.

Re-run any time; files are overwritten.
"""

from pathlib import Path

fixtures = {
# 1
"sum-ints": [
"""3
10 20 30
""",
"""5
2147483647 -2147483648 1 0 -1
"""],
"csv-stats": [
"""1,2,3,4,5
""",
"""  1 , -2 , 999999999999999999999999 , x
"""],
"strfind": [
"""abracadabra
cad
""",
"""hello
zzz
"""],
"uniq-lines": [
"""a
b
a
c
b
""",
""  # empty input (edge)
],
"hex-parse": [
"""7fffFFFFffffffff
""",
"""xyz  # invalid
"""
],
"json-int-array-sum": [
"""[1,2,3]
""",
"""[1,   2,  9223372036854775807]
"""
],
"rle-encode": [
"""aaabbcaaaa
""",
""  # empty
],
"paren-balance": [
"""([{}])()
""",
"""([)]
"""
],
"topk": [
"""3
10 9 8 7 6 5
""",
"""0
1 2 3
"""
],
"trim-and-join": [
"""   hello
world    
""",
"""
   \t \n
\t
"""
],
"safe-copy": [
"""this is a short line
""",
("A"*5000) + "\n",
],
"wordfreq": [
"""To be, or not to be: that is the question.
""",
"""            \n"""
],
"matrix-mul": [
"""2 3
1 2 3
4 5 6
3 2
7 8
9 10
11 12
""",
"""1 1
2
1 1
3
"""
],
"b64-decode": [
"""SGVsbG8sIHdvcmxkIQ==
""",
"""!!!!  ### invalid
"""
],
"url-decode": [
"""hello%20world%21
""",
"""bad%GZcode
"""
],
"rot13": [
"""Hello Uryyb!
""",
""""
"""
],
"itoa-safe": [
"""-9223372036854775808
"""
, """9223372036854775807
"""
],
"lines-sort": [
"""c
b
a
c
""",
("\n".join(str(i) for i in range(10000,0,-1000)))+"\n"
],
"dedup-sorted-ints": [
"""1 1 2 2 2 3 4 4 5
""",
""""
"""
],
"histo-bytes": [
"""hello
""",
("\x00\xff\x7f").encode("latin1").decode("latin1")
],
"checksum": [
"""abc
""",
""  # empty
],
"safe-sprintf": [
"""Alice
42
""",
"""Bob
-1
"""
],
"str-reverse": [
"""Hello, 世界
""",
""],
"stack-queue": [
"""push 1
push 2
pop
enqueue 7
dequeue
""",
"""pop
dequeue
"""
],
"infix-eval": [
"""(2+3)*4-5/5
""",
"""1/0
"""
],
"dedup-hash": [
"""10
1 2 3 2 1 4 5 6 6 7
""",
"""0
"""
],
"grep-substr": [
"""foo
a
foo
b
bar
""",
"""zzz
alpha
beta
"""
],
"csv-split-fields": [
"""a,"b,b",c
""",
"""a,"unterminated,c
"""
],
"args-parse": [
# These programs likely parse argv; for stdin-driven main we simulate typical lines:
"""-n 3
-o /tmp/x
""",
"""-n notanint
-o
"""
],
"rand-sample": [
"""3
a
b
c
d
e
""",
"""0
a
"""
],
"moving-average": [
"""3
1
2
3
4
5
""",
"""-1
1
"""
],
"edit-distance": [
"""kitten
sitting
""",
"""abc
"""
],
"safe-split": [
"""a   bb   c
""",
("x ")*1000 + "\n"
],
"bitmap-popcount": [
"""ffff
""",
"""g123   # invalid hex
"""
],
"safe-strtol": [
"""  -42
""",
"""999999999999999999999999999
"""
],
"unique-ints": [
"""8
5 5 4 4 3 2 1 1
""",
"""-1
"""
],
"interval-merge": [
"""3
1 3
2 6
8 10
""",
"""2
5 4
7 8
"""
],
"lzw-encode": [
"""ABABABA
""",
""],
"ini-parse": [
"""# comment
x=1
y=hello
""",
"""bad line
"""
],
"crc32": [
"""hello
""",
""],
"minstack": [
"""push 3
push 1
min
pop
min
""",
"""min
"""
],
"queue-ring": [
"""push 1
push 2
pop
push 3
pop
pop
""",
"""pop
"""
],
"atoi-bounds": [
"""2147483647
""",
"""-2147483649
"""
],
"parse-ipv4": [
"""192.168.0.1
""",
"""256.0.0.1
"""
],
"fmt-printf": [
"""12
34
""",
"""a
b
"""
],
"fib-iter": [
"""10
""",
"""94
"""
],
"binary-search": [
"""5
1 3 5 7 9
3
""",
"""3
1 2 3
10
"""
],
"median-of-ints": [
"""1
2
3
4
5
""",
("\n".join(str(i) for i in range(1000000)))+"\n"
],
"safe-memcpy": [
"""4
abcd
wxyz
""",
"""-1
a
b
"""
],
"kmp-substr": [
"""abracadabra
cad
""",
"""abc
zzz
"""
],
"sieve": [
"""30
""",
"""10000001
"""
],
"transpose": [
"""2 3
1 2 3
4 5 6
""",
"""46341 46341
"""
],
"uniq-sort": [
"""b
a
b
c
""",
("\n".join("x"+str(i) for i in range(100000)))+"\n"
],
"json-kv": [
"""{"a":1,"b":2,"c":3}
""",
"""{"a":1,"b":"x"}
"""
],
"base10-to-baseN": [
"""255
16
""",
"""-9223372036854775808
2
"""
],
"longest-line": [
"""short
the-longest-line-here
tiny
""",
("X"*1048577) + "\n"
],
"hamming-distance": [
"""ffff
0f0f
""",
"""abc   # odd length/invalid
"""
],
"safe-realloc": [
"""10
some data
""",
"""1000000000
x
"""
],
}

def main():
    out = Path("fixtures")
    out.mkdir(exist_ok=True)
    count = 0
    for slug, cases in fixtures.items():
        for i, data in enumerate(cases, 1):
            p = out / f"{slug}.in{i}"
            with open(p, "wb") as f:
                # allow raw bytes for some cases
                if isinstance(data, bytes):
                    f.write(data)
                else:
                    f.write(data.encode("utf-8", errors="replace"))
            count += 1
    print(f"Wrote {count} fixture files into {out.resolve()}.")

if __name__ == "__main__":
    main()

