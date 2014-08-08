/* mstp linediscipline for Linux kernel 2.6 on Megatron platform.
	*
	* -----------------------------------------------------------
	* Copyright by
	* Cisco
	* San Jose, CA, USA
	* http://www.cisco.com
	* -----------------------------------------------------------
	*
	* PHY for mstp is a shared-media RS485 line. This ldisc implements the Link
	* and MAC layers. The Network layer (including routing and BVLC) is
	* implemented in the framework's C code. The Transport and higher layers
	* are implemented in the framework's Python code.
	*
	* The MSTP LL/MAC layer is based on token-passing. Collisions are detected
	* as failure of "responsible" party (eg token-holder, pkt recipient, etc.)
	* to detect arrival of an expected frame before a timeout occurs.
	* Immediately after a target device receives a frame to which it must reply
	* (eg DATA_NEED_REPLY, PFM, TOKEN), the target responds appropriately; the
	* target does NOT wait to obtain the token before responding (unlike RZnet).
	* The MSTP LL/MAC layers are implemented in this ldisc (as a kernel module)
	* due to tight timing requirements for token passing: No more than 5 msec
	* delay allowed for token passing. Thus, the Network and higher layers
	* (operating in user, rather than kernel, space) should never have to deal
	* with low-level frames, or worry about their timing.
	*
	* As soon as an RS485 MSTP port is opened by the App Layer, this ldisc:
	*   (1) Joins a token ring and maintains its membership therein.
	*   (2) Searches for and inducts new masters in the downstream address space
	*        (higher numbers).
	*   (3) Detects missing controllers in the downstream address space.
	*   (4) Maintains a table of "nodes" (MSTP ports) currently recognized and
	*        passing the token. Table and ldisc statistics are accessible via
	*        proc filesystem.
	*   (5) Buffers and retransmits responses when expected replies are not
	*        received within timeout period
	*   (6) Accepts outgoing frames from the Network and higher layers, and
	*        forwards those frames on to the MSTP bus.
	*   (7) Receives and recognizes frames from the MSTP bus intended for the
	*       Network and higher layers, and forwards those frames accordingly.
	*   (8) Allows some configuration of ldisc via ioctl() calls.
	*
	* Author:
	* S. H. Penner, NeoMachines Computer Programming
	*
	*/

#ifndef __LINUX_N_MSTP_H__
#define __LINUX_N_MSTP_H__

#include <linux/kdev_t.h>

// "FSA" = "Finite State Automata" = "State Machine"

// Bit time base (usec at 2400 baud) for standard baud rates allowed for MSTP.
// Obtain bit times for faster baud rates by shifting this number by difference
// between speed_t for 2400 ("B2400") and target rate (eg "B38400)). 1 byte time
// is assumed to be 10 bit times:
#define B2400_BIT_usec          416

// RecvFrame FSA (RFFSA) States: NOT all states from spec are represented here:
enum {
    MSTP_RFST_IDLE = 0,
    MSTP_RFST_PREAMBLE,
    MSTP_RFST_HEADER,
    MSTP_RFST_DATA
};

// MasterNode FSA (MNFSA) States: States represented herein may differ from
// spec, for efficiency of coding and/or operation. Number and variety of states
// has been increased to allow faster operation:
#define MSTP_MNST_XMT_DLY_1ST   100
#define MSTP_MNST_XMT_DLY_N_MAX  99
#define MSTP_MNST_LO_1ST      200
#define MSTP_MNST_LO_N_MAX     99
enum {
    MSTP_MNST_IDLE = 0,
    MSTP_MNST_WAIT_REPLY,
    MSTP_MNST_PASS_TOKEN,
    MSTP_MNST_PFM,
    MSTP_MNST_NO_TOKEN,
    MSTP_MNST_XMT_DLY_TKN = MSTP_MNST_XMT_DLY_1ST,
    MSTP_MNST_XMT_DLY_PFM_REPLY,
    MSTP_MNST_XMT_DLY_REPLY_POST,
    MSTP_MNST_XMT_DLY_TEST_RESP,
    MSTP_MNST_XMT_DLY_LAST =
        MSTP_MNST_XMT_DLY_1ST + MSTP_MNST_XMT_DLY_N_MAX,
    MSTP_MNST_LO_TKN = MSTP_MNST_LO_1ST,
    MSTP_MNST_LO_DATA,
    MSTP_MNST_LO_NEED_REPLY,
    MSTP_MNST_LO_PFM,
    MSTP_MNST_LO_PFM_REPLY,
    MSTP_MNST_LO_REPLY_POST,
    MSTP_MNST_LO_TEST_RESP,
    MSTP_MNST_LO_LAST = MSTP_MNST_LO_1ST + MSTP_MNST_LO_N_MAX
};

#define MSTP_EVT_TIMEOUT (1 << 24)

#define MSTP_RTN_RESET_LDISC	1000    // rtn value: ldisc was reset
#define MSTP_RTN_SENT_FRAME		1001    // rtn value: frame was sent
#define MSTP_RTN_WAIT_FOR_DATA	1002    // rtn value: need to wait for DATA
#define MSTP_RTN_NOT_HANDLED	1003    // rtn value: no errors, but not handled

#define MSTP_RTN_INVAL_PORT_CFG	2000    // rtn value: invalid mstp_port_cfg
#define MSTP_RTN_INVAL_INFO		2001    // rtn value: invalid mstp_info
#define MSTP_RTN_MOD_BAD_GET	2002    // rtn value: failed to incr module refcnt
#define MSTP_RTN_BAD_USER_BUF	2003    // rtn value: corrupt user buffer
#define MSTP_RTN_BAD_MPX_TYPE	2004    // rtn value: unknown MPX_TYPE
#define MSTP_RTN_MOD_EXITED 	2005    // rtn value: module exited already


// mstp hdr size and indices (relative to FrameType index - as per spec, do not
// incl Preamble1 or Preamble2 in recvd pkt buf):
#define MSTP_PKT_HDR_SIZE         8 // incl 2 preamble bytes that precede FrameType
#define MSTP_PKT_FRAME_TYPE_IDX   0 // do NOT incl 2 preamble bytes
#define MSTP_PKT_DST_IDX          1 // ..
#define MSTP_PKT_SRC_IDX          2 // ..
#define MSTP_PKT_DATA_LEN1_IDX    3 // ..
#define MSTP_PKT_DATA_LEN0_IDX    4 // ..
#define MSTP_PKT_HDR_CRC_IDX      5 // ..

// MSTP_MAX_FRM_SIZE incls hdr (8), data (501), data crc (2), and optional pad
// byte (1, must be 0xFF if present):
#define MSTP_MAX_FRM_SIZE       512
#define MSTP_MAX_DATA_SIZE      501 //  from BN Spec

#define MSTP_PREAMBLE1   0x55
#define MSTP_PREAMBLE2   0xFF

// mstp Counting Params:

// MSTP_N_MAX_INFO_FRAMES_DEF: Arbitrary DEFAULT max # client frames sent, before
// this node must pass the token. Note that value actually used in code is
// writable via procfs and ioctl():
#define   MSTP_N_MAX_INFO_FRAMES_DEF 100

#define   MSTP_N_MAX_MASTER          127    // max allowed master node address

#define   MSTP_N_PFM_TKN_TRG          50    // must PFM after this many tokens seen

#define   MSTP_N_RETRY_TOKEN           1    // max retries after failed tkn pass

// MSTP_N_MIN_OCTETS_ACTIVE: Min # bytes seen on MSTP bus before thsi node
// considers bus "active":
#define   MSTP_N_MIN_OCTETS_ACTIVE     4

// MSTP Timing Params. (jiffy-based, though min allowed Linux "buzzrate" (HZ) is
// 1000). Values defined in main.c:

// MSEC_PER_JIFFY: Used for dyn calc of jiffies from msecs.
extern const int MSEC_PER_JIFFY;

// MSTP_TJ_MAX_FRAME_ABORT: Max jiffies without byte recvd or error evt before
// discarding current incoming frame.
extern const int MSTP_TJ_MAX_FRAME_ABORT;

// MSTP_NBT_MAX_FRAME_GAP: Max # bit times allowed between successive bytes in an
// outgoing frame
#define MSTP_NBT_MAX_FRAME_GAP          20

// MSTP_TJ_MAX_NO_TOKEN: Max jiffies without byte recvd or error evt before
// declaring lost token:
extern const int MSTP_TJ_MAX_NO_TOKEN;

// MSTP_TJ_MAX_REPLY_DELAY Max jiffies after rcvg "reply-reqd" frame before
// starting reply xmssn:
extern const int MSTP_TJ_MAX_REPLY_DELAY;

// MSTP_TJ_MIN_REPLY_TIMEOUT: Min jiffies without byte recvd or error evt before
// declaring "no reply" when awaiting reply after sending "reply-reqd":
extern const int MSTP_TJ_MIN_REPLY_TIMEOUT;

// MSTP_TJ_SLOT: Jiffies during which a given node may "generate a token". Each
// node has a time slot this big, allocated by address, after "no token"
// perceived, in which to send token. Eg node with address 0x23 would initiate
// a PFM cycle by sending a PFM to TS+1 (0x24) after
// (MSTP_TJ_MAX_NO_TOKEN + 0x23 *  MSTP_TJ_SLOT) jiffies of silence:
extern const int MSTP_TJ_SLOT;

// MSTP_NBT_MIN_TURNAROUND: Min # bit times after rcvg last bit of last byte of
// incoming frame before this node may activate its transmitter. Note that this
// value serves mainly as a lower limit and default for an
// ioctl/procfs-configurable value:
#define MSTP_NBT_MIN_TURNAROUND          40

// MSTP_TJ_MAX_USAGE_DELAY: Max jiffies after rcvg token or PFM frame before
// this node must send at least one byte:
extern const int MSTP_TJ_MAX_USAGE_DELAY;

// MSTP_TJ_MIN_USAGE_TIMEOUT: Min jiffies this node must wait after sending token or
// PFM, for rcvg node to send 1st byte of reply or other frame:
extern const int MSTP_TJ_MIN_USAGE_TIMEOUT;

// MSTP_TJ_MIN_ECHO_TIMEOUT: Min jiffies this node must wait after sending any
// frame before timing out due to not seeing 1st byte of echoed frame.
// Because mstp_receive_buf() is called from a workqueue owned by the tty
// driver, we have seen up to 3 msec delay every 10 sec or so. So, set it to
// 5 msec as a starting point. Heavy CPU loads could push this value out...:
extern const int MSTP_TJ_MIN_ECHO_TIMEOUT;

// MSTP_MASTER_WRAP(): Convenience macro to limit master address math to
// acceptable address space:
#define   MSTP_MASTER_WRAP(x) ((x) % (MSTP_N_MAX_MASTER + 1))

#define __PACKED_ATTR __attribute__ ((__packed__))

// struct mstp_frame: Contains and formats bytes sent to and rcvd from port.
// Use as a cookie-cutter on generic byte buffers contained in mstp_frame_wrap
// objects. MUST BE PACKED ON 1-BYTE BOUNDARIES TO WORK AS COOKIE_CUTTER:
struct mstp_frame {
    //unsigned char      ucPre1 __PACKED_ATTR;
    //unsigned char      ucPre2 __PACKED_ATTR;
    unsigned char ucFrameType;
    unsigned char ucDstAddr;
    unsigned char ucSrcAddr;
    unsigned char ucDataLen1;
    unsigned char ucDataLen0;
    unsigned char ucHdrCrc;
    unsigned char pucData[1];
};

struct mstp_frame_entry {       // pucFrame: Actual frame bytes (from preamble to DataCRC):
    unsigned char pucFrame[MSTP_MAX_FRM_SIZE];
    unsigned int nLen;
    unsigned int nFlags;        // see PKTFL_ defines above
    struct timeval time_at_port;    // time recvd from port, or sent to port
    unsigned int nRetries;      // used for tx only
};

// mstp FrameTypes:
#define MSTP_FT_TOKEN           0x00
#define MSTP_FT_PFM             0x01
#define MSTP_FT_PFM_REPLY       0x02
#define MSTP_FT_TEST_REQ        0x03
#define MSTP_FT_TEST_RESP       0x04
#define MSTP_FT_DATA_REPLY      0x05
#define MSTP_FT_DATA_NO_REPLY   0x06
#define MSTP_FT_REPLY_POSTPONED 0x07

// MSTP_MAX_SEG_NODES: Size of sorted array that holds addrs of detected nodes
#define MSTP_MAX_SEG_NODES    256

#define MSTP_BCAST_ADDR       0xFF  // 255

#define MSTP_NEED_REPLY_MASK  0x04

// struct port_cfg: Describes port configuration for a given NBM hardware
// platform. Global instances are defined in mpx_cfg.c. Includes members for
// use during normal ldisc ops (ie mstp_info*, mutex, spinlock_t):
struct port_cfg {
    dev_t port_dev;             // major/minor numbers of port; hardcoded
    unsigned int nIRQ;          // IRQ number used by port device; hardcoded
    char *szPortName;           // name of port, eg "com1"; hardcoded
    spinlock_t spin;            // protects access to pInfo's evt ring buf
    // Runtime variables:
    struct mutex mtx;
    struct work_struct wq_struct;   // workqueue struct
    unsigned long ulFlags;      // to store IRQ flags during locks
    int iLogEnabled;            // 0: append_log_entry ignores, Else: adds
    // Event Processing: Allocated in mstp_open, destroyed in mstp_close.
    unsigned int *pnRawEvts;    // access cntld by port_cfg spin
    unsigned int *pnRawEvtsOut; // access cntld by port_cfg spin OR mtx
#define MSTP_SZ_UINT sizeof(unsigned int)
#define MSTP_SZ_RAW_EVTS ( PAGE_SIZE / MSTP_SZ_UINT )
    int iRawEvtsWr;             // access cntld by port_cfg spin
    int iRawEvtsRd;             // access cntld by port_cfg spin
    // mstp_info: Allocated/initd/used only in mstp_open. Shut down and
    // destroyed in mstp_close.
    struct mstp_info *pInfo;
};

// struct mpx_cfg: Describes a type of NBM hardware platform, and associates
// that type with a given port config. Currently, only 1 defined (for kernel
// 2.6) = megatron:
struct mpx_cfg {
    unsigned int nMpxType;      // type of MPX unit (megatron = "0")
    char *szMpxType;            // name of type of MPX (eg "megatron")
    struct port_cfg *port_cfgs; // pointer to array of port_cfgs
    unsigned int nNumPortCfgs;  // num elems in port_cfgs array
    unsigned int nLoopback;     // 0: Does NOT do RS485 echo. Else: DOES.
};

struct mstp_node_desc {
    unsigned char ucAddr;
    struct timeval tmStartTokenHold __PACKED_ATTR;  // time rcvd tkn
    struct timeval tmEndTokenHold __PACKED_ATTR;    // time passed tkn to next
};

// struct mstp_node_entry: Elem of list of nodes detected on a given mstp bus:
struct mstp_node_entry {
    struct list_head list;
    struct mstp_node_desc node_desc;
};

struct procfs_file_spec {
    const char *szName;
    const struct file_operations *fops;
};

// struct mstp_procfs: Contains procfs-only variables, for human-readable
// display via procfs. Each instance of struct mstp_info owns exactly one
// instance of struct mstp_procfs:
struct mstp_procfs {            // procfs directory entry declarations:
    char szDirName[50];         // name of root subdir in procfs
    // root_dir: Root subdir _under_ /proc/mstp/. Eg, /proc/mstp/com1.
    struct proc_dir_entry *root_dir;
    struct proc_dir_entry *files[6];    // procfs files under root_dir

    // Snapshot array of node_entry structs, fast-copied from mstp_info's list.
    // Double-buffer for procfs read-only access:
    struct mstp_node_desc node_array[MSTP_MAX_SEG_NODES];

    // Timing:
    struct timeval tmStatsStart;    // indicates time of last clear_stats()

    // RecvFrame Statistics:
    unsigned int nTotalBytesRcvd;
    unsigned int nTotalFramesFromPort;
    unsigned int nNoDataFramesFromPort;
    unsigned int nDataFramesFromPort;
    unsigned int nInvalidEchoes;

    // SendFrame Statistics:
    unsigned int nTotalFramesToPort;
    unsigned int nNoDataFramesToPort;
    unsigned int nDataFramesToPort;
    unsigned int nMaxTxQUsed;

    // RecvFrame IDLE Errors:
    unsigned int nEatAnOctet;
    unsigned int nEatAnError;

    // RecvFrame PREAMBLE Errors:
    unsigned int nRptdPre1;
    unsigned int nNotPre2Byte;
    unsigned int nPreambTimeout;
    unsigned int nPreambCommErr;

    // RecvFrame HEADER Errors:
    unsigned int nHdrTimeout;
    unsigned int nHdrCommErr;

    // RecvFrame HEADER_CRC Errors:
    unsigned int nFrameTooLong;
    unsigned int nBadHdrCrc;

    // RecvFrame DATA Errors:
    unsigned int nDataTimeout;
    unsigned int nDataCommErr;

    // RecvFrame DATA_CRC Errors:
    unsigned int nBadDataCrc;

    // Overall Frame Error:
    unsigned int nInvalidFrame;

    // MasterNode Stats:
    unsigned int nTotalFramesFromClient;
    unsigned int nTotalFramesToClient;
    unsigned int nTotalFramesMissedFromClient;
    unsigned int nTotalFramesMissedToClient;
    unsigned int nTotalTokensSeen;
    unsigned int nTotalTokensRecvd;
    unsigned int nTotalTokensPassed;
    unsigned int nTotalPfmsSeen;
    unsigned int nTotalPfmsRecvd;
    unsigned int nTotalPfmsSent;
    unsigned int nTotalPfmsReplied;
    unsigned int nTotalReplyPostponedOut;
    unsigned int nTotalTestRespOut;

    // MasterNode IDLE Errors:
    unsigned int nIdleInvalidFrame;
    unsigned int nLostToken;

    // MasterNode WAIT_REPLY Errors:
    unsigned int nWaitReplyUnexpectedFrame;
    unsigned int nWaitReplyTimeout;
    unsigned int nWaitReplyInvalidFrame;

    // MasterNode PASS_TOKEN Errors:
    unsigned int nRetrySendToken;
    unsigned int nFindNewSuccessor;

    // MasterNode POLL_FOR_MASTER Errors:
    unsigned int nDeclareSoleMaster;
    unsigned int nPfmUnexpectedFrame;

    // MasterNode DLY_XXX Errors:
    unsigned int nDelayUnwantedEvts;

    // MasterNode ECHO_XXX Errors:
    unsigned int nEchoTimeout;

    // General Counters:
    unsigned int nTestRespsRecvd;   // num MSTP_FT_TEST_RESP frames recvd

    // mstp ldisc Version:
    unsigned int nVersion[2];   // a.b

    // TEST VALUES:
    unsigned long ulStartWrite;
    unsigned long ulEchoDelay;
};

struct mstp_npdu {
    unsigned char ucSrcAddr;
    unsigned char pucBuf[MSTP_MAX_FRM_SIZE];
    unsigned int nLen __PACKED_ATTR;
};

#define MSTP_TEST_REQ_DATA_LEN   10

#define MSTP_RXQ_LEN  32
#define MSTP_TXQ_LEN  32

struct mstp_info {
    atomic_t atomInitDone;
    // tty: connection to port assocd with this mstp_info; VALID ONLY WHILE
    // PORT IS OPEN!:
    struct tty_struct *tty;
    // MSTP State Vars (used by RecvFrame and MasterNode FSAs):
    unsigned int nLoopback;     // 0: No. !0: Yes (echo sent bytes).
    int iMnState;
    int iRfState;
    unsigned int nEventCount;   // # bytes recvd PLUS error evts
    unsigned int nXmtFrameCount;    // total num data/req frames sent during a token hold
    unsigned int nXmtFrameCountMax; // max num data/req frames allowed during a token hold
    unsigned int nIndex;        // index into pucInputBuf
    unsigned char pucInputBuf[MSTP_MAX_FRM_SIZE];   // buf for incoming bytes
    unsigned char ucHdrCrc;     // accumulator for incoming hdr byte CRC
    unsigned short usDataLen;   // num data bytes expected
    unsigned short usDataCrc;   // accumulator for incoming data byte CRC
    unsigned char ucTS;         // MAC addr of "This Station"
    unsigned char ucNS;         // MAC addr of "Next Station"
    unsigned char ucPS;         // MAC addr of next "Poll Station" (PFM)
    unsigned char ucReqdTS;     // next reqd TS
    unsigned int nRetryCount;   // for token passes and PFM queries
    unsigned int nPfmTokenCount;    // total # tokens sent since last PFM seq
    unsigned int nSoleMaster;   // 1: no other masters detected on bus
    unsigned int nBitTime;      // time (usec) for 1 bit on the wire
    unsigned int nByteTime;     // time (usec) for 1 byte (10 bits) on the wire
    unsigned long ulMnPeriodJiffs;  // next timeout period, set by MNFSA

    // Echo-checking (loopback verification of transmitted bytes):
    // send_frame: holds next ldisc-generated frame to send:
    struct mstp_frame_entry send_frame;
    // pLastSentFrame: Points to last frame sent (in txq or at send_frame):
    struct mstp_frame_entry *pSendFrame;

    // Support for implementing configurable turnaround time:
    unsigned long ulReplyDelay; // jiffies

    // MSTP_FT_TEST_REQ Support:
    unsigned int nTestReqLen;

    // DEBUG: Local event count: Incremented by mn_recv_event(), zeroed by
    // _send_frame():
    unsigned int nLocalEvtCnt;

    // Capture PID of thread waiting in mstp_read() for incoming frames:
    pid_t reader_pid;

    // Frames recvd from serial port and awaiting transmission to client.
    struct mstp_npdu rxq[MSTP_RXQ_LEN];
    atomic_t rxq_not_empty;     // reqd: cf of indices can be a non-atomic
    unsigned int nRxqWrIdx;     // next pos in array to be written by ldisc
    unsigned int nRxqRdIdx;     // next pos in array to be read for client

    // Frames recvd from client and awaiting transmission to serial port.
    struct mstp_frame_entry txq[MSTP_TXQ_LEN];
    atomic_t txq_not_full;      // reqd: cf of indices can be a non-atomic
    unsigned int nTxqWrIdx;     // next pos in array to be written by ldisc
    unsigned int nTxqRdIdx;     // next pos in array to be read for client

    // iBarrier: For debug only: detect compiler/linker/kernel mismatches:
    int iBarrier;

    // Tools for allowing blocking reads by client:
    wait_queue_head_t read_wait;

    // Node List:
    struct list_head node_list;

    // IRQ/Port Info for attached serial port:
    struct port_cfg *pPortCfg;

    // Overall Timer Enable:
    int timer_restart;          // 0: do NOT restart SilenceTimer

    // DEBUG:
    int iDbg;

    // SilenceTimer: ONLY timer in ldisc. ALWAYS running, to prevent ldisc
    // from getting caught in "cul-de-sac" state and becoming unresponsive:
    struct timer_list SilenceTimer;

    // procfs data:
    struct mstp_procfs procfs;
};

// reset_info(): Called by mstp_open() in main.c, and by error-detection code
// in fsa_rf.c and fsa_mn.c:
int reset_info(struct mstp_info *pInfo);

// validate_info(): (iTty != 0) => test pInfo->tty. Else, don't test that cond.
struct mstp_info *validate_info(struct mstp_info *pInfo, int iTty);
// validate_info(): (iTty != 0) => test pInfo->tty. Else, don't test that cond.
int validate_and_lock_port(struct port_cfg *pPortCfg, int iTty);
void unlock_port(struct port_cfg *pPortCfg);

// Log Ring Buf: Used to offload from printk to userspace, hopefully reducing
// delays imposed by calling printk at kernel priority. Downside: not all msgs
// passed to Log Ring Buf will be printed in userspace in the event of a
// kernel oops.
extern int iGenlLogEnabled;
unsigned int mstp_index_wrap(int iIdx, unsigned int nSz);
void append_log_entry(unsigned char ucPortNum, char *pcFmt, ...);
int get_avail_log_entries(unsigned char *user_buf);

// Global var to take module param:
extern char *MPX_TYPE;

#endif                          // __LINUX_N_MSTP_H__
