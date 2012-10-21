#!/usr/bin/env python
from optparse import OptionParser
from subprocess import Popen, PIPE
import tempfile
import sys
import os

TCGETS = "0x5401"
TCSETS = "0x5402"
SIZEOF_STRUCT_TERMIOS = 60

GDB_BATCH_FORMAT = """
file {exe}
attach {pid}
call malloc({sizeof_termios})
call ioctl(2, {tcgets}, $1)
call close(2)
call open("{stderr}", {flags})
call ioctl(2, {tcsets}, $1)
call free($1)
detach
"""

def main():
    pid = parse_args()
    stderr = os.readlink('/proc/{pid}/fd/2'.format(pid=pid))
    try:
        get_stack_trace(pid)
    finally:
        move_stderr(pid, stderr)


def move_stderr(pid, stderr):
    exe = os.readlink('/proc/{pid}/exe'.format(pid=pid))
    gdb_batch = GDB_BATCH_FORMAT.format(
        exe=exe,
        pid=pid,
        sizeof_termios=SIZEOF_STRUCT_TERMIOS,
        tcgets=TCGETS,
        tcsets=TCSETS,
        flags=os.O_RDWR,
        stderr=stderr)

    with tempfile.NamedTemporaryFile() as f:
        f.write(gdb_batch)
        f.flush()




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
        return options.pid
    lines = Popen("ps aux",
                  shell=True,
                  stdout=PIPE).communicate()[0].splitlines()
    potential = [line for line in lines
                 if options.name in line and
                 line.split()[1] != str(os.getpid())]

    if len(potential) != 1:
        parser.error("didn't get one process matched: {0}".format(
            len(potential) - 1))
    return potential[0].split()[1]


if __name__ == '__main__':
    main()
