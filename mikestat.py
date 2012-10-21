#!/usr/bin/env python
from optparse import OptionParser
from subprocess import Popen, PIPE
import functools
import resource
import tempfile
import time
import sys
import os
import re

DEVNULL = open(os.devnull, 'w')

old_fd_re = re.compile(r'\$2 = (\d+)')
heap_info_re = re.compile(r'object space (?:\w+), (?:\d+)% used \[0x\w+,0x\w+,0x\w+')

MOVED_BACK = True
START, END = 1, 2
OLD_FD = None


def main():
    global MOVED_BACK
    pid = parse_args()
    print get_stack_trace(pid)

def get_stack_trace(pid):
    stdout = os.readlink('/proc/{pid}/fd/1'.format(pid=pid))
    with tempfile.NamedTemporaryFile() as stackfile:
        try:
            MOVED_BACK = False
            move_stdout(pid, stackfile.name)
            os.kill(pid, 3)
            return read_stack_trace(stackfile)
        finally:
            if not MOVED_BACK:
                move_stdout(pid, stdout, edge=END)


def read_stack_trace(stackfile):
    stackfile.seek(0)
    lines = []
    started_heap = False
    started_stack = False
    while True:
        where = stackfile.tell()
        line = stackfile.readline()
        if not line:
            time.sleep(0.1)
            stackfile.seek(where)
        else:
            if line.startswith('Full thread dump'):
                started_stack = True
            if started_stack:
                lines.append(line)
            if line.rstrip() == 'Heap':
                started_heap = True
            elif not started_heap and heap_info_re.search(line):
                started_heap = True
            elif started_heap and line == '\n':
                return ''.join(lines)


def move_stdout(pid, stdout, edge=START):
    global OLD_FD
    exe = os.readlink('/proc/{pid}/exe'.format(pid=pid))
    format = GDB_BATCH_FORMAT_START if edge == START else GDB_BATCH_FORMAT_END
    newfd = find_fd(pid)

    gdb_batch = format.format(
        exe=exe,
        pid=pid,
        oldfd=OLD_FD,
        flags=os.O_RDWR | os.O_APPEND,
        stdout=stdout)

    with tempfile.NamedTemporaryFile() as f:
        f.write(gdb_batch)
        f.flush()
        output = Popen('gdb -batch -x {file}'.format(file=f.name), stdout=PIPE, stdin=DEVNULL, shell=True).communicate()[0]
        OLD_FD = old_fd_re.search(output).group(1)


def memoize(func):
    cache = {}
    @functools.wraps(func)
    def _wrapped(*args, **kwargs):
        key = args + tuple(sorted(kwargs.items()))
        if key in cache:
            return cache[key]
        value = func(*args, **kwargs)
        cache[key] = value
        return value
    return _wrapped



@memoize
def find_fd(pid):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    hard -= 1
    while os.path.exists('/proc/{pid}/fd/{fd}'.format(pid=pid, fd=hard)) and hard > 2:
        hard -= 1
    if hard <= 2:
        raise Exception("Cannot find open fd to map stdout to!?")
    return hard


def parse_args():
    parser = OptionParser()
    parser.add_option("-p", "--pid", dest="pid", default=None,
                      help="process pid", metavar="PID")
    parser.add_option("-n", "--process-name", dest="name", default=None,
                      help="match name of process", metavar="NAME")
    options, args = parser.parse_args()
    if not (bool(options.pid) ^ bool(options.name)):
        parser.error("please specify pid or name, not both")
    if options.pid:
        return int(options.pid)
    lines = Popen("ps aux",
                  shell=True,
                  stdout=PIPE).communicate()[0].splitlines()
    potential = [line for line in lines
                 if options.name in line and
                 line.split()[1] != str(os.getpid())]

    if len(potential) != 1:
        parser.error("didn't get one process matched: {0}".format(
            len(potential)))
    return int(potential[0].split()[1])


GDB_BATCH_FORMAT_START = """
file {exe}
attach {pid}
call open("{stdout}", {flags})
call dup(1)
call dup2($1, 1)
call close($1)
detach
"""

GDB_BATCH_FORMAT_END = """
file {exe}
attach {pid}
call dup2({oldfd}, 1)
call close({oldfd})
detach
"""


if __name__ == '__main__':
    main()
