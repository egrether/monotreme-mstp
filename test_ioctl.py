# This script tests multiple simultaneous rznet connections ON SAME RZNET.

import fcntl, struct, time, socket, tty, os, select, sys, array, math
from termios import *

RZNET_IOCGNODES = 0x54E10011
		
def _get_nodes_list():
	str_nodes = 1024 * '\0'
	str_nodes = fcntl.ioctl(fd_ttyS5, RZNET_IOCGNODES, str_nodes)
	nodes_tuple = struct.unpack(256 * 'I', str_nodes)
	print 'Read node list from rznet ldisc ioctl:'
	for node in nodes_tuple:
		if node == 0:
			break
		print '%d' % node

# Start main program:
f_ttyS5 = open('/dev/ttyS5', 'w+b', 0)
os.system('rs485init')
print 'test_ioctl: file open'

# Get file descriptors:
fd_stdin = sys.stdin.fileno()
fd_ttyS5 = f_ttyS5.fileno()

# Get original ldisc:
s_ldisc_ttyS5_org = struct.pack('i', 9)
fcntl.ioctl(fd_ttyS5, TIOCGETD, s_ldisc_ttyS5_org)

# Get current port flags:
flags5 = fcntl.fcntl(fd_ttyS5, fcntl.F_GETFL)

# Set port to nonblocking (for more efficient poll ops):
fcntl.fcntl(fd_ttyS5, fcntl.F_SETFL, flags5 | os.O_NONBLOCK)

# Set ldisc to "rznet":
s = struct.pack('i', 9)
p5 = fcntl.ioctl(fd_ttyS5, TIOCSETD, s)
print 'test_ioctl: ldisc installed'

try:
	attr5 = tcgetattr(fd_ttyS5)
except:
	print 'I/O error'
	sys.exit(0)
attr5[0] = IGNPAR
attr5[1] = 0
attr5[2] = CS8 | CREAD | HUPCL | CLOCAL
attr5[3] = 0
attr5[4] = B9600
attr5[5] = B9600
attr5[6][VMIN] = 1
attr5[6][VTIME] = 0
tcsetattr(fd_ttyS5, TCSANOW, attr5)

# Wait until user signals that they have seen non-trivial node list in procfs:
poll_obj = select.poll()
poll_obj.register(fd_stdin, select.POLLIN)

poll_obj.poll()

# Attempt to read and print node list from ldisc:
_get_nodes_list()

# Reset ldisc to originals (ie before we replaced them with rznet). Apparently,
# neither kernel nor driver does this:
fcntl.ioctl(fd_ttyS5, TIOCSETD, s_ldisc_ttyS5_org)

f_ttyS5.close()

print 'test_ioctl: file closed'
