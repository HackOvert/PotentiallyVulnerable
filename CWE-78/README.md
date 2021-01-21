## Command Injection
[CWE-78](https://cwe.mitre.org/data/definitions/78.html): Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

> *"The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component."*

Want to see real-world examples of CWE-78 from amazing security researchers? Check out [Command Injection on awesome-bugs](https://github.com/HackOvert/awesome-bugs#command-injection).

## What are these Scripts?
| Script | Tool & Version | Description |
| --- | --- | --- |
| `SystemCallAuditorGhidra.py` | Ghidra v9.2.1 | Checks system calls for potentially vulnerable command injections |
| `SystemCallAuditorBinja.py` | Binary Ninja v2.2.2487 | Checks system calls for potentially vulnerable command injections |
