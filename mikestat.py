#!/usr/bin/env python
from optparse import OptionParser
from subprocess import Popen, PIPE
import tempfile
import time
import sys
import os

DEVNULL = open(os.devnull, 'w')

TCGETS = "0x5401"
TCSETS = "0x5402"
SIZEOF_STRUCT_TERMIOS = 60

GDB_BATCH_FORMAT = """
file {exe}
attach {pid}
call malloc({sizeof_termios})
call ioctl(1, {tcgets}, $1)
call close(1)
call open("{stdout}", {flags})
call ioctl(1, {tcsets}, $1)
call free($1)
detach
"""

MOVED_BACK = True

def main():
    global MOVED_BACK
    pid = parse_args()
    print get_stack_trace(pid)

def get_stack_trace(pid):
    stdout = os.readlink('/proc/{pid}/fd/1'.format(pid=pid))
    if stdout.startswith('/dev/pts'):
        raise Exception("Cannot deal with pts tty yet. Try reptyr to redirect to a file first! (or run redirecting stdout to a file)")
    with tempfile.NamedTemporaryFile() as stackfile:
        try:
            MOVED_BACK = False
            move_stdout(pid, stackfile.name)
            os.kill(pid, 3)
            return read_stack_trace(stackfile)
        finally:
            if not MOVED_BACK:
                move_stdout(pid, stdout)

def read_stack_trace(stackfile):
    stackfile.seek(0)
    lines = []
    started_heap = False
    while True:
        where = stackfile.tell()
        line = stackfile.readline()
        if not line:
            time.sleep(0.1)
            stackfile.seek(where)
        else:
            lines.append(line)
            if line.rstrip() == 'Heap':
                started_heap = True
            elif started_heap and line == '\n':
                return ''.join(lines)

def move_stdout(pid, stdout):
    exe = os.readlink('/proc/{pid}/exe'.format(pid=pid))
    gdb_batch = GDB_BATCH_FORMAT.format(
        exe=exe,
        pid=pid,
        sizeof_termios=SIZEOF_STRUCT_TERMIOS,
        tcgets=TCGETS,
        tcsets=TCSETS,
        flags=os.O_RDWR | os.O_APPEND,
        stdout=stdout)

    with tempfile.NamedTemporaryFile() as f:
        f.write(gdb_batch)
        f.flush()
        Popen('gdb -batch -x {file}'.format(file=f.name), stdout=DEVNULL, stdin=DEVNULL, shell=True).communicate()





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


if __name__ == '__main__':
    main()
