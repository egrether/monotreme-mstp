import fcntl, struct, time, socket, tty, os, select, sys, array, math
from termios import *

def print_array_as_hex(array_in, line_len = 14):
	len_array = len(array_in)
	lines = math.floor(len_array / line_len) # whole lines only
	offset = 0
	for line in range(lines):
		for byte in range(offset, offset + line_len):
			print '%02x' % array_in[byte],
		print
		offset = byte + 1
		
	# Deal with partial line at end:
	for byte in range(offset, offset + (len_array % line_len)):
		print '%02x' % array_in[byte],
	print

# Start main program:
f = open('/dev/ttyS5', 'w+b', 0)
os.system('rs485init')
print 'test_open: file open'

fd_stdin = sys.stdin.fileno()
fd_mstp = f.fileno()

try:
	attr = tcgetattr(f.fileno())
except:
	print 'I/O error'
	sys.exit(0)
	
print str(attr)
attr[0] = IGNPAR
attr[1] = 0
attr[2] = CS8 | CREAD | HUPCL | CLOCAL
attr[3] = 0
attr[4] = B38400
attr[5] = B38400
attr[6][VMIN] = 1
attr[6][VTIME] = 0
tcsetattr(fd_mstp, TCSANOW, attr)
print str(attr)

# Get current port flags:
flags = fcntl.fcntl(fd_mstp, fcntl.F_GETFL)

# Set port to nonblocking (for more efficient poll ops):
fcntl.fcntl(fd_mstp, fcntl.F_SETFL, flags | os.O_NONBLOCK)

# Set ldisc to "mstp":
s = struct.pack('i', 9)
p = fcntl.ioctl(fd_mstp, TIOCSETD, s)
print 'test_open: ldisc installed'

# Prep a WHO_IS NPDU to broadcast on to MSTP RS485 net:
ar_npdu_out = array.array('B', [0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])

# Send WHO_IS NPDU to mstp ldisc:
ar_npdu_out.tofile(f)

# Allow user to wait arbitrary time before closing mstp file:
print 'fd_stdin = %d. fd_mstp = %d' % (fd_stdin, fd_mstp)
poll_obj = select.poll()
poll_obj.register(fd_stdin, select.POLLIN) # watch for user input from stdin
poll_obj.register(fd_mstp, select.POLLIN) # watch for incoming bytes from mstp
go = 1
while go:
	evt_prs = poll_obj.poll()
	print 'evt_prs = %s' % evt_prs
	
	if len(evt_prs) == 0:
		continue
		
	for evt in evt_prs:
		print 'evt = %s' % str(evt)
		if evt[0] == fd_stdin:
			go = 0
			break
		else:
			ar_npdu_in = array.array('B')
			try: 
				ar_npdu_in.fromfile(f, 1024)
			except Exception, e: 
				print str(e)
			print 'Recvd: ',
			print_array_as_hex(ar_npdu_in, 20)

poll_obj.unregister(fd_stdin)
poll_obj.unregister(fd_mstp)

# Set ldisc back to "n_tty":
s = struct.pack('i', 0)
p = fcntl.ioctl(fd_mstp, TIOCSETD, s)
print 'test_open: n_tty installed'

os.system('rs485init')
print 'test_open: rs485init recalled to passivate line'

f.close()

print 'test_open: file closed'
