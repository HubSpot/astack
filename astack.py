#!/usr/bin/env python
from optparse import OptionParser
from subprocess import Popen, PIPE
import datetime
import tempfile
import urllib
import time
import sys
import os
import re

__all__ = ('main',)

DEVNULL = open(os.devnull, 'w')

old_fd_re = re.compile(r'\$2 = (\d+)')
heap_info_re = re.compile(r'space (?:\w+), (?:\d+)% used \[0x\w+,0x\w+,0x\w+')

MOVED_BACK = True
START, END = 1, 2
OLD_FD = None
USE_COLOR = False


def main():
    global MOVED_BACK, USE_COLOR
    options = parse_args()
    if options.upgrade:
        return autoupgrade()
    if options.pretty:
        USE_COLOR = True

    if options.raw:
        print colorize_stacktrace(add_os_thread_info(options.pid, get_stack_trace(options)))
    elif options.agg:
        print aggregate(add_os_thread_info(options.pid, get_stack_trace(options)), int(options.agg))
    elif options.grep:
        print grep(add_os_thread_info(options.pid, get_stack_trace(options)), options.grep)
    elif options.sample:
        print sample(options.pid, 4, 10, int(float(options.sample) / float(10)))
    else:
        sys.argv = [sys.argv[0], '--help']
        print "No action specified"
        return parse_args()


def get_stack_trace(options):
    if options.pid:
        return get_stack_trace_from_pid(options.pid)
    elif options.input:
        return get_stack_trace_from_file(options.input)
    else:
        print "Can't get stacktrace"
        parse_args()
        raise Exception()


def get_stack_trace_from_file(filename):
    if filename.strip() == '-':
        return sys.stdin.read()
    else:
        with open(filename) as f:
            return f.read()


def get_stack_trace_from_pid(pid):
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


def add_os_thread_info(pid, stacktrace):
    _thread_re = re.compile(r'^\S.*\snid=0x([0-9a-f]+)\s', re.I)
    lines = []
    thread_info = get_os_thread_info(pid)
    for line in stacktrace.splitlines():
        m = _thread_re.search(line)
        if m:
            nid = int(m.group(1), 16)
        else:
            lines.append(line)
            continue
        if nid in thread_info:
            cpu, start_time = thread_info[nid]
            line += ' cpu={cpu} start={start_time}'.format(cpu=cpu, start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"))
        lines.append(line)
    return '\n'.join(lines)


def aggregate(stacktrace, nlines):
    threads = split_threads(stacktrace)
    counter = {}
    example = {}
    cpu_totals = {}
    for thread in threads:
        if not thread.strip():
            continue
        thread_info = get_thread_info(thread)
        stack = get_stack(thread)
        top = ''.join(stack[:nlines])
        counter[top] = counter.get(top, 0) + 1
        cpu_totals[top] = cpu_totals.get(top, 0) + (thread_info.get('cpu') or 0)
        example[top] = thread
    items = sorted(counter.items(), key=lambda x: x[1])

    return '\n\n'.join("{0} times ({1}% total cpu)\n{2}".format(count, cpu_totals.get(key), colorize_thread(example.get(key)))
                       for key, count in items)


def grep(stacktrace, text):
    threads = []
    text_re = re.compile(r"({0})".format(re.escape(text)))
    for thread in split_threads(stacktrace):
        if text.lower() not in thread.lower():
            continue
        if USE_COLOR:
            thread = text_re.sub(colored(r'\1', 'red', attrs=['bold']), thread)
        threads.append(thread)
    return '\n\n'.join(colorize_thread(thread) for thread in threads)


def sample(pid, nlines, samples, wait_time):
    sys.stdout.write("Sampling.")
    sys.stdout.flush()
    thread_runnable_counts = {}
    thread_stacks = {}
    for _ in range(samples):
        sys.stdout.write(".")
        sys.stdout.flush()
        threads = split_threads(add_os_thread_info(pid, get_stack_trace_from_pid(pid)))
        for thread in threads:
            thread_info = get_thread_info(thread)
            if thread_info.get('status', '').lower().strip() != 'runnable':
                continue
            thread_id = thread_info.get('thread_id')

            thread_runnable_counts[thread_id] = thread_runnable_counts.get(thread_id, 0) + 1
            thread_stacks.setdefault(thread_id, []).append(thread)
        time.sleep(wait_time)

    items = sorted(thread_runnable_counts.items(), key=lambda x: x[1])

    threads = []

    for tid, count in items:
        stack = thread_stacks[tid][-1]
        stack = stack.replace('runnable', '{0:0.1f}% runnable'.format(float(count) / samples * 100), 1)
        threads.append(stack)

    print

    return aggregate('\n\n'.join(threads), nlines)


def split_threads(stacktrace, get_ends=False):
    begin, end = [], []
    threads = []
    current_thread = []
    _thread_line_re = re.compile(r'^\S.*\sprio=.*\stid=')
    for line in stacktrace.splitlines():
        if _thread_line_re.search(line):
            current_thread.append(line)
        elif not line.strip():
            threads.append('\n'.join(current_thread).strip())
            current_thread = []
            end = []
        elif current_thread:
            current_thread.append(line)
        elif not threads:
            begin.append(line)
        elif not current_thread:
            end.append(line)

    if current_thread:
        threads.append('\n'.join(current_thread).strip())
    if get_ends:
        return '\n'.join(begin), threads, '\n'.join(end)
    else:
        return threads


def get_thread_info(thread):
    _unwanted_hex_re = re.compile(r'\[0x[0-9a-f]+\]\s')
    thread_re = re.compile(r'^"([^"]+)" (daemon)?\s*prio=(\d+) tid=0x([0-9a-f]+) nid=0x([0-9a-f]+) (.+?)\s*(?:cpu=([.\d]+) start=(.+))?$')
    text = _unwanted_hex_re.sub('', thread.split('\n', 1)[0])
    m = thread_re.search(text)
    if not m:
        return {}
    return {
        'name': m.group(1),
        'daemon': bool(m.group(2)),
        'priority': int(m.group(3)),
        'thread_id': int(m.group(4), 16),
        'native_id': int(m.group(5), 16),
        'status': m.group(6).strip(),
        'cpu': float(m.group(7)) if m.group(7) else None,
        'start_time': m.group(8).strip() if m.group(8) else None,
    }


def colorize_thread(thread, line=0):
    if not USE_COLOR:
        return thread
    head = thread.strip().split("\n", 1)
    if len(head) == 1:
        head, tail = head[0].strip(), ''
    else:
        head, tail = head
    thread_info = get_thread_info(head)
    if not thread_info:
        if line < 2:
            return head + colorize_thread(tail, line + 1)
        else:
            return thread

    return '"{name}" {daemon}prio={priority} tid=0x{thread_id:0x} nid=0x{native_id:0x} {status} {cpu}{start_time}\n{tail}'.format(
        name=colored(thread_info.get('name', ''), 'blue'),
        daemon=colored('daemon ' if thread_info.get('daemon') else '', 'yellow'),
        priority=thread_info.get('priority', 0),
        thread_id=thread_info.get('thread_id', 0),
        native_id=thread_info.get("native_id", 0),
        status=colored(thread_info.get('status'), ['white','green']['runnable' in thread_info.get('status','').lower()]),
        cpu="cpu={0:.1f}% ".format(thread_info.get('cpu')) if thread_info.get('cpu') else '',
        start_time="start={0}".format(thread_info.get('start_time')) if thread_info.get('start_time') else '',
        tail=colorize_tail(tail)
    )


def colorize_tail(thread_tail):
    blocked = re.compile(r'(\b)BLOCKED(\b)')
    return blocked.sub(r'\1' + colored('BLOCKED', 'red', attrs=['bold', 'underline']) + r'\2', thread_tail)


def colorize_stacktrace(stacktrace):
    if not USE_COLOR:
        return stacktrace
    begin, threads, end = split_threads(stacktrace, True)
    return begin.strip() + '\n\n' + '\n\n'.join(colorize_thread(thread) for thread in threads).strip() + '\n\n' + end.strip()


def get_stack(thread):
    _at_re = re.compile(r'^\s+at ')
    stack = []
    for line in thread.splitlines()[3:]:
        if _at_re.search(line):
            stack.append(line.strip())
    return stack


def indent_text(text, indent=4):
    indent = ' ' * indent
    return '\n'.join(indent + line for line in text.splitlines())


def get_os_thread_info(pid):
    pid = str(pid)
    result = {}
    output = Popen("ps -e -T -o pid,spid,pcpu,etime", stdout=PIPE, shell=True).communicate()[0]
    for line in output.splitlines()[1:]:
        row = line.split()
        if row[0] != pid:
            continue
        spid = int(row[1])
        cpu = float(row[2])
        try:
            start = parse_etime(row[3])
        except Exception, e:
            raise Exception("Couldn't parse etime: {0}".format(row[3]))
        result[spid] = (cpu, start)
    return result


def parse_etime(etime):
    info = etime.split('-', 1)
    days = hours = minutes = seconds = 0
    if len(info) == 2:
        days = int(info[0].lstrip('0') or 0)
    info = info[-1].split(':')
    seconds = int(info[-1].lstrip('0') or 0)
    if len(info) > 1:
        minutes = int(info[-2].lstrip('0') or 0)
    if len(info) > 2:
        hours = int(info[-3].lstrip('0') or 0)
    return datetime.datetime.now() - datetime.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


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
    parser.add_option("-a", "--aggregate", default=None, dest="agg",
                      help="Aggregate stacktraces (specify the number of lines to aggregate)")
    parser.add_option("-s", "--sample", default=None, dest="sample",
                      help="Sample stacktraces to the most active ones (specify the number of seconds)")
    parser.add_option("-i", "--input", default=None, dest="input", metavar="INPUT",
                      help="read stacktrace from file (or - with stdin)")
    parser.add_option("--pretty", "--pretty", action="store_true",
                      dest="pretty", default=False, help="Force colors")
    parser.add_option("-g", "--grep", dest="grep", default=None,
                      help="Show only threads that match text", metavar="MATCH")
    options, args = parser.parse_args()

    if os.isatty(sys.stdout.fileno()):
        options.pretty = True

    if bool(options.pid) and bool(options.name):
        parser.error("please specify pid or name, not both")
    if options.pid:
        options.pid = int(options.pid)
    elif options.name:
        lines = Popen("ps aux",
                      shell=True,
                      stdout=PIPE).communicate()[0].splitlines()
        potential = [line for line in lines
                     if options.name.lower() in line.lower() and
                     line.split()[1] != str(os.getpid())]

        if len(potential) != 1:
            parser.error("didn't get one process matched: {0}".format(len(potential)))
        options.pid = int(potential[0].split()[1])

    return options


def autoupgrade():
    print "About to update from git.hubteam.com..."
    contents = urllib.urlopen('https://github.com/HubSpot/astack/raw/master/astack.py').read()
    with open(__file__, 'r') as f:
        if f.read() == contents:
            print "Nothing has changed... exiting"
            return
    os.rename(__file__, __file__ + '.bak')
    print "Renamed {0} to {1}".format(__file__, __file__ + '.bak')
    print "Saved new {0}".format(__file__)
    with open(__file__, 'w+') as f:
        f.write(contents)
        os.chmod(__file__, 0755)


ATTRIBUTES = dict(
        list(zip([
            'bold',
            'dark',
            '',
            'underline',
            'blink',
            '',
            'reverse',
            'concealed'
            ],
            list(range(1, 9))
            ))
        )
del ATTRIBUTES['']


HIGHLIGHTS = dict(
        list(zip([
            'on_grey',
            'on_red',
            'on_green',
            'on_yellow',
            'on_blue',
            'on_magenta',
            'on_cyan',
            'on_white'
            ],
            list(range(40, 48))
            ))
        )


COLORS = dict(
        list(zip([
            'grey',
            'red',
            'green',
            'yellow',
            'blue',
            'magenta',
            'cyan',
            'white',
            ],
            list(range(30, 38))
            ))
        )


RESET = '\033[0m'


def colored(text, color=None, on_color=None, attrs=None):
    if os.getenv('ANSI_COLORS_DISABLED') is None:
        fmt_str = '\033[%dm%s'
        if color is not None:
            text = fmt_str % (COLORS[color], text)

        if on_color is not None:
            text = fmt_str % (HIGHLIGHTS[on_color], text)

        if attrs is not None:
            for attr in attrs:
                text = fmt_str % (ATTRIBUTES[attr], text)

        text += RESET
    return text


if __name__ == '__main__':
    main()
