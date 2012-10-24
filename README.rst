******
astack
******

You've heard of jstack and pstack, well this is a new tool
called astack.

astack is a swiss army knife of easily getting thread dumps
from JVMs and analyzing them from the command line.

Guiding principles:

- No complicated network setup (e.g. JMX)
- Designed for linux (sorry OS X)
- Single file script for ease of copying


Dependencies:

- gdb

========
Synopsis
========


There are two steps to invoking ``astack``: (1) select which process to inspect and
(2) specify what action to take. There are two ways to select which process:

1) ``-p PID`` - Select based on PID
2) ``-n NAME`` - Match based on case insensitive search of command line

Note that name searching does not work if more than one process match.

Once you have a process, there are a few options you can take to get different
output:

1) ``-r`` - Just get the raw stacktrace as if you sent a SIGQUIT to the java process and captured the stdout with some extra info.
2) ``-a NLINES`` - Group and count the threads by ``NLINES`` of stack and display them in order of occurrence with one representative thread.
3) ``-s NSAMPLES`` - Sample the threaddump a few times and display which ones are most active (most oftenly in RUNNABLE state).

Usage description from the process itself:

.. code-block:: bash
    Usage: astack [options]

    Options:
      -h, --help            show this help message and exit
      -p PID, --pid=PID     process pid
      -n NAME, --process-name=NAME
                            match name of process
      -r, --raw             print the raw stacktrace and exit
      -u, --upgrade         automatically upgrade
      -a AGG, --aggregate=AGG
                            Aggregate stacktraces (specify the number of lines to
                            aggregate)
      -s SAMPLE, --sample=SAMPLE
                            Sample stacktraces to the most active ones (specify
                            the number of seconds)

===================
Theory of Operation
===================

Rather than hooking into the JVM and asking it for a stack trace via instrumentation,
this script takes the approach of sending a ``SIGQUIT`` signal and extracting the stacktrace
from the JVM while it's running. The way it does this is by using ``gdb`` to temporary
redirect stdout while the JVM is spouting out the thread dump, and switching it back when
it's done. This does mean that it can occasionally get some artifacts if your JVM is
rapidly sending output to stdout. In most typical scenarios (e.g. log lines) you wouldn't
see any interference.

The advantage of using this technique is that even when a JVM is under heavy load and cannot
fulfill a instrumentaiton approach, the low level response to a ``SIGQUIT`` signal is still
functional. In most cases, thread dumps are most useful when the JVM is at its limit, so
this technique can get interesting results very easily.

=======
Install
=======

.. code-block:: bash
    $ sudo pip install astack


---------------------------
Ubuntu 10.04 and up support
---------------------------

On Ubuntu 10.04 and up you'll need to run this (as root):

.. code-block:: bash
    # echo 0 > /proc/sys/kernel/yama/ptrace_scope

=============
Bugs & Issues
=============

Feel free to file any issues with github's `issues`_ page.


=======
License
=======

MIT License, copyright HubSpot 2012. See the bundled `LICENSE`_ file for details.


.. _issues: https://github.com/HubSpot/astack/issues/
.. _LICENSE: https://github.com/HubSpot/astack/blob/master/LICENSE
