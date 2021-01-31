## Command Injection
[CWE-78](https://cwe.mitre.org/data/definitions/78.html): Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

> *"The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component."*

Want to see real-world examples of CWE-78? Check out [Command Injection on awesome-bugs](https://github.com/HackOvert/awesome-bugs#command-injection).

## What are these Scripts?
| Script | Tool & Version Tested | Description |
| --- | --- | --- |
| `SystemCallAuditorBinja.py` | Binary Ninja v2.2.2487 | Checks system calls for potentially vulnerable command injections |
| `SystemCallAuditorGhidra.py` | Ghidra v9.2.1 | Checks system calls for potentially vulnerable command injections |

## What's this binary?
The binary in this folder `tdpServer` comes from the TP-Link Archer A7 (AC1750) router, hardware version 5, MIPS Architecture, firmware version 190726. It contains a command injection via a system call. For more details check out this [ZDI blog post](https://www.thezdi.com/blog/2020/4/6/exploiting-the-tp-link-archer-c7-at-pwn2own-tokyo). Each of the scripts in this directory will find this vulnerable system call.

## Can I see an example of these scripts running?
Wow, how conveinient of you to ask! I just happen to have two videos that highlight each of these scripts in action. Check out the [Binary Ninja version](https://www.youtube.com/watch?v=F3uh8DuS0tE) and the [Ghidra version](https://www.youtube.com/watch?v=UVNeg7Vqytc).
