# astack

This is a swiss army knife of easily getting thread dumps
from JVMs and analyzing them from the command line.

Guiding principles:

 - No complicated network setup (e.g. JMX)
 - Designed for linux (sorry OS X)
 - Single file script for ease of copying


Dependencies:

 - gdb


## Ubuntu 10.04 and up

Need to run this:

```bash
$ echo 0 > /proc/sys/kernel/yama/ptrace_scope
```
