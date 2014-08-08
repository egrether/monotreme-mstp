// iocs.h: Definitions of ioctl cmd numbers for mstp ldisc.

#ifndef __MSTP_IOCS_H__
#define __MSTP_IOCS_H__

#define MSTP_IOC_MAGIC    0x54  // 'T', as for all ldiscs
// Start ordinals at 0xE0 to avoid conflict.

// FIXME: Need to figure out how to import numbers below, defined by macros,
// into Python files:

// Read/write mstp LAN address for a given RS485 port (distinguished by ldisc_data
// member of tty struct passed into ioctl():
#define MSTP_IOCGADDRS    0x54E00010    // get own and next addrs (8 bytes total)
#define MSTP_IOCSADDR     0x54E00011    // set own addr (4 bytes total)

// Read list of nodes on main mstp for a given RS485 port:
#define MSTP_IOCGNODES    0x54E10012

// Send Test Request, and return Test Response status:
#define MSTP_IOCTESTREQ   0x54E10013

// Read all available log entries from MSTP ldisc (from all configured ports):
#define MSTP_IOCRDLOG     0x54E10014

// Get/Set custom baud rate. (Must be done by mstp.c, rather than ldisc, since
// info is not available in any way inside kernel code):
#define MSTP_IOCGBAUD     0x54E10015
#define MSTP_IOCSBAUD     0x54E10016


#endif                          // __MSTP_IOCS_H__
