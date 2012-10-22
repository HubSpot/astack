#!/usr/bin/env python
from optparse import OptionParser
from subprocess import Popen, PIPE
import cookielib
import functools
import resource
import tempfile
import getpass
import urllib2
import urllib
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
    options = parse_args()
    if options.upgrade:
        autoupgrade()
    elif options.raw:
        print get_stack_trace(options.pid)
    else:
        print "OTHER"

def get_stack_trace(pid):
    with tempfile.NamedTemporaryFile() as stackfile:
        try:
            MOVED_BACK = False
            move_stdout(pid, stackfile.name)
            os.kill(pid, 3)
            return read_stack_trace(stackfile)
        finally:
            if not MOVED_BACK:
                move_stdout(pid, edge=END)


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


def move_stdout(pid, new_file=None, edge=START):
    global OLD_FD
    exe = os.readlink('/proc/{pid}/exe'.format(pid=pid))
    format = GDB_BATCH_FORMAT[edge]

    gdb_batch = format.format(
        exe=exe,
        pid=pid,
        oldfd=OLD_FD,
        flags=os.O_RDWR | os.O_APPEND,
        stdout=new_file)

    with tempfile.NamedTemporaryFile() as f:
        f.write(gdb_batch)
        f.flush()
        output = Popen('gdb -batch -x {file}'.format(file=f.name), stdout=PIPE, stdin=DEVNULL, shell=True).communicate()[0]
        OLD_FD = old_fd_re.search(output).group(1)


def parse_args():
    parser = OptionParser()
    parser.add_option("-p", "--pid", dest="pid", default=None,
                      help="process pid", metavar="PID")
    parser.add_option("-n", "--process-name", dest="name", default=None,
                      help="match name of process", metavar="NAME")
    parser.add_option("-r", "--raw", action="store_true",
                      dest="raw", default=False, help="print the raw stacktrace and exit")
    parser.add_option("-u", "--upgrade", action="store_true",
                      dest="upgrade", default=False, help="automatically upgrade")
    options, args = parser.parse_args()
    if bool(options.pid) and bool(options.name):
        parser.error("please specify pid or name, not both")
    if options.pid:
        options.pid = int(options.pid)
    elif options.name:
        lines = Popen("ps aux",
                      shell=True,
                      stdout=PIPE).communicate()[0].splitlines()
        potential = [line for line in lines
                     if options.name in line and
                     line.split()[1] != str(os.getpid())]

        if len(potential) != 1:
            parser.error("didn't get one process matched: {0}".format(
                    len(potential)))
        options.pid = int(potential[0].split()[1])

    return options


GDB_BATCH_FORMAT = {
    START: """
file {exe}
attach {pid}
call open("{stdout}", {flags})
call dup(1)
call dup2($1, 1)
call close($1)
detach
""",
    END: """
file {exe}
attach {pid}
call dup2({oldfd}, 1)
call close({oldfd})
detach
"""
}


def autoupgrade():
    print "About to update from git.hubteam.com..."
    _token_re = re.compile(r'authenticity_token.*?value="([^"]+)')
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    content = opener.open('https://git.hubteam.com/auth/ldap').read()
    token = _token_re.search(content).group(1)
    username = raw_input('enter ldap username [{username}]: '.format(username=getpass.getuser())).strip()
    if not username:
        username = getpass.getuser()
    password = getpass.getpass('enter ldap password: ')
    opener.open('https://git.hubteam.com/auth/ldap', data=urllib.urlencode({
                'username': username,
                'password': password,
                'authenticity_token': token,
                'commit': "Sign in"}))
    r = opener.open('https://git.hubteam.com/maxiak/superjstackstat/raw/master/mikestat.py')
    contents = r.read()
    os.rename(__file__, __file__ + '.bak')
    print "Renamed {0} to {1}".format(__file__, __file__ + '.bak')
    print "Saved new {0}".format(__file__)
    with open(__file__, 'w+') as f:
        f.write(contents)


if __name__ == '__main__':
    main()
