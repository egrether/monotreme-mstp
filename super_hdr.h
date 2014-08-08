#ifndef __SUPER_HDR_H__
#define __SUPER_HDR_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/string.h>       /* used in new tty drivers */
#include <linux/signal.h>       /* used in new tty drivers */
#include <linux/ioctl.h>
#include <linux/time.h>         // for struct timeval and do_gettimeofday()
#include <linux/list.h>         // for tx_pkts and rx_pkts circular buffers (lists)
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <asm/uaccess.h>
#include <asm/termios.h>


//******************************************************************************
// Trace Macro Definitions:
//******************************************************************************


// Macro useful mainly for printk() calls:
#define NAME() ( pInfo->pPortCfg->szPortName )
#define NUMI() ( pInfo->pPortCfg->szPortName[3] - 0x30 )
#define NUMP() ( pPortCfg->szPortName[3] - 0x30 )

//#define DEBUG_QUEUE

/* Log packet formation and transmission operations: */
//#define DEBUG_PKT

/* Log packet formation and transmission errors: */
//#define DEBUG_PKT_E

/* Log successful handshake and protocol operations  */
//#define DEBUG_PROTO_S

/* Log handshake and protocol errors: */
#define DEBUG_PROTO_E

/* Log Linediscipline operations (open, close, read, write...): */
//#define DEBUG_LDISC
//#define DEBUG_LDISC_HV // high-volume (eg receive_buf)

/* Log module and memory operations (init, cleanup; kmalloc, kfree): */
#define DEBUG_MODUL

/* Macro helpers for debug output: */
#define TRACE(format, args...) printk(format "\n" , ## args)

#ifdef DEBUG_PKT
#define TRACE_K(str) printk( (str) )
#define TRACE_K1(format, args...) printk(format, ## args)
#else
#define TRACE_K(str)            //
#define TRACE_K1(fmt, arg...) /**/
#endif
#ifdef DEBUG_PKT_E
#define TRACE_KE(format, args...) printk("mstp: " format "\n" , ## args)
#else
#define TRACE_KE(fmt, arg...) /**/
#endif
#ifdef DEBUG_MODUL
#define TRACE_M(format, args...) printk("mstp: " format "\n" , ## args)
#else
#define TRACE_M(fmt, arg...) /**/
#endif
#ifdef DEBUG_PROTO_S
#define TRACE_PS(format, ...) append_log_entry(0, format , ## __VA_ARGS__)
#define TRACE_PSI(format, ...) \
	append_log_entry( NUMI() , format , ## __VA_ARGS__)
#define TRACE_PSP(format, ...) \
	append_log_entry( NUMP() , format , ## __VA_ARGS__)
#else
#define TRACE_PS(fmt, arg...) /**/
#define TRACE_PSI(fmt, arg...) /**/
#define TRACE_PSP(fmt, arg...) /**/
#endif
#ifdef DEBUG_PROTO_E
#define TRACE_PE(format, ...) append_log_entry(0, format , ## __VA_ARGS__)
#define TRACE_PEI(format, ...) \
	append_log_entry( NUMI() , format , ## __VA_ARGS__)
#define TRACE_PEP(format, ...) \
	append_log_entry( NUMP() , format , ## __VA_ARGS__)
#else                           // DEBUG_PROTO_E
#define TRACE_PE(fmt, arg...) /**/
#define TRACE_PEI(fmt, arg...) /**/
#define TRACE_PEP(fmt, arg...) /**/
#endif                          // DEBUG_PROTO_E
#ifdef DEBUG_LDISC
#define TRACE_L(format, ...) append_log_entry(0, format , ## __VA_ARGS__)
#define TRACE_LI(format, ...) \
	append_log_entry( NUMI() , format , ## __VA_ARGS__)
#define TRACE_LP(format, ...) \
	append_log_entry( NUMP() , format , ## __VA_ARGS__)
#else                           // DEBUG_LDISC
#define TRACE_L(fmt, arg...) /**/
#define TRACE_LI(fmt, arg...) /**/
#define TRACE_LP(fmt, arg...) /**/
#endif                          // DEBUG_LDISC
#ifdef DEBUG_LDISC_HV
#define TRACE_L_HV(format, args...) printk("mstp: " format "\n" , ## args)
#define TRACE_LI(format, ...) \
	append_log_entry( NUMI() , format , ## __VA_ARGS__)
#define TRACE_LP(format, ...) \
	append_log_entry(pPortCfg->szPortName[3] , format , ## __VA_ARGS__)
#else
#define TRACE_L_HV(fmt, arg...) /**/
#define TRACE_LI_HV(fmt, arg...) /**/
#define TRACE_LP_HV(fmt, arg...) /**/
#endif
#ifdef DEBUG_QUEUE
#define TRACE_Q(format, args...) printk("mstp: " format "\n" , ## args)
#else
#define TRACE_Q(fmt, arg...) /**/
#endif
#endif                          // __SUPER_HDR_H__
