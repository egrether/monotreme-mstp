/* mstp linediscipline for Linux kernel 2.6 on Megatron platform.
	*
	* -----------------------------------------------------------
	* Copyright by
	* Cisco
	* San Jose, CA, USA
	* http://www.cisco.com
	* -----------------------------------------------------------
	*
	* Author:
	* S. H. Penner
	*
	*/

#include "super_hdr.h"
#include "mpx_cfg.h"
#include "n_mstp.h"
#include "procfs.h"
#include "util.h"
#include "fsa_rf.h"
#include "iocs.h"

// Log Ring Buf:
#define MSTP_N_MSG_LEN_MAX 123
struct mstp_log_entry           // 128 bytes long
{
    unsigned char ucPortNum;  // com port number
    unsigned long ulJiffies __PACKED_ATTR;  // time when logged
    char pcMsg[MSTP_N_MSG_LEN_MAX];   // msg
};
const int szLogEntry = sizeof(struct mstp_log_entry);

#define MSTP_SZ_LOG 256
struct mstp_log_entry Log[MSTP_SZ_LOG];
int iLogWr = 0;
int iLogRd = 0;

unsigned long ulFlagsLog = 0;
//spinlock_t spinLog = SPIN_LOCK_UNLOCKED;
static DEFINE_SPINLOCK(spinLog);

// C-lang modulo (%) misbehaves with neg nums, so invert manually. nSz MUST
// be power of 2:
unsigned int mstp_index_wrap(int iIdx, unsigned int nSz)
{
    if (iIdx < 0)
        iIdx = (nSz + iIdx);
    return (iIdx & (nSz - 1));
}

#define MSTP_SZ_PYTHON_IOCTL_BUF 1023
const int MSTP_N_RTND_LOG_ENTRIES_MAX = MSTP_SZ_PYTHON_IOCTL_BUF
    / sizeof(struct mstp_log_entry);
const unsigned char MSTP_MORE_LOG_ENTRIES = 0xAD;
const unsigned int MSTP_IDX_LAST_USER_BUF_BYTE = MSTP_SZ_PYTHON_IOCTL_BUF
    - sizeof(int) - 1;

int iGenlLogEnabled = 0;

void append_log_entry(unsigned char ucPortNum, char *pcFmt, ...)
{                               // Changes only Wr idx:
    struct mstp_log_entry *pCurLogEntry = 0;
    unsigned int nNewWr = 0;
    va_list ap;                 // holds variadically-specified (...) formal params
    struct port_cfg *pPortCfg = NULL;

    if (ucPortNum == 0) {
        if (!iGenlLogEnabled)
            return;
    } else {
        pPortCfg = (this_mpx_cfg->port_cfgs + ucPortNum - 1);
        // Bail out if ucPortNum indicates port with disabled logging:
        if (ucPortNum > this_mpx_cfg->nNumPortCfgs)
            return;             // invalid port num
        if (!pPortCfg->iLogEnabled)
            return;             // logging disabled for port
    }
    spin_lock_irqsave(&spinLog, ulFlagsLog);
    nNewWr = mstp_index_wrap(iLogWr + 1, MSTP_SZ_LOG);
    if (nNewWr == (unsigned int) iLogRd)    // prevent overwrite of Rd idx:
    {
        printk("LF\n");
        goto log_full;          // ring buf is full, so drop given msg
    }
    pCurLogEntry = &(Log[iLogWr]);
    pCurLogEntry->ucPortNum = ucPortNum;
    va_start(ap, pcFmt);
    vsnprintf(pCurLogEntry->pcMsg, MSTP_N_MSG_LEN_MAX, pcFmt, ap);
    va_end(ap);
    pCurLogEntry->ulJiffies = jiffies;
    iLogWr = (int) nNewWr;
  log_full:
    spin_unlock_irqrestore(&spinLog, ulFlagsLog);
    return;
}

int get_avail_log_entries(unsigned char *user_buf)
{                               // Changes only Rd idx. user_buf actually starts after initial 4 bytes for
    // number of entries returned:
    int iRtn = 0, iToEnd = 0, iLocalRd = 0, iLocalWr = 0;
    unsigned int nAvail = 0;
    // Grab current read and write indices, protected by spinlock:
    spin_lock_irqsave(&spinLog, ulFlagsLog);
    iLocalRd = iLogRd;
    iLocalWr = iLogWr;
    spin_unlock_irqrestore(&spinLog, ulFlagsLog);
    // Copy from Log to user buf. Can sleep, so read index can be corrupted by
    // intervening calls to append_log_entry(). However, this approach is faster
    // than capturing Log to intermediate buffer before calling copy_to_user()
    // (which can sleep, and should not be entered holding a spinlock):
    nAvail = mstp_index_wrap(iLocalWr - iLocalRd, MSTP_SZ_LOG);
    if (!nAvail)
        return 0;               // nothing to get
    if (nAvail > MSTP_N_RTND_LOG_ENTRIES_MAX) { // Too many entries to rtn at once:
        iLocalWr =
            mstp_index_wrap(iLocalRd + MSTP_N_RTND_LOG_ENTRIES_MAX,
                            MSTP_SZ_LOG);
        // Show "more entries available":
        iRtn = put_user(MSTP_MORE_LOG_ENTRIES,
                        user_buf + MSTP_IDX_LAST_USER_BUF_BYTE);
        if (iRtn) {
            printk("get_avail_log_entries: Could not put_user!\n");
            return -MSTP_RTN_BAD_USER_BUF;
        }
        nAvail = MSTP_N_RTND_LOG_ENTRIES_MAX;
    }
    if (iLocalRd < iLocalWr) {
        iRtn = copy_to_user(user_buf, (unsigned char *) &Log[iLocalRd], nAvail * szLogEntry);   // can sleep
    } else {
        iToEnd = MSTP_SZ_LOG - iLocalRd;
        iRtn = copy_to_user(user_buf, (unsigned char *) &Log[iLocalRd], iToEnd * szLogEntry);   // can sleep
        iRtn += copy_to_user(user_buf + (iToEnd * szLogEntry), (unsigned char *) Log, (nAvail - iToEnd) * szLogEntry);  //can sleep
    }
    if (iRtn) {
        printk
            ("get_avail_log_entries: Could not copy_to_user! Rd %i, Wr %i, "
             "Av %u\n", iLocalRd, iLocalWr, nAvail);
        return -MSTP_RTN_BAD_USER_BUF;
    }
    spin_lock_irqsave(&spinLog, ulFlagsLog);
    iLogRd = iLocalWr;          // show that we read all msgs avail at call time
    spin_unlock_irqrestore(&spinLog, ulFlagsLog);
    return nAvail;
}

// See "n_mstp.h" for descriptions of these constants that are calculated at
// compile time:
const int MSEC_PER_JIFFY = 1000 / HZ;
const int MSTP_TJ_MAX_FRAME_ABORT = (100 * HZ) / 1000;
const int MSTP_TJ_MAX_NO_TOKEN = (500 * HZ) / 1000;
const int MSTP_TJ_MAX_REPLY_DELAY = (250 * HZ) / 1000;
const int MSTP_TJ_MIN_REPLY_TIMEOUT = (300 * HZ) / 1000;
const int MSTP_TJ_SLOT = (10 * HZ) / 1000;
const int MSTP_TJ_MAX_USAGE_DELAY = (15 * HZ) / 1000;
const int MSTP_TJ_MIN_USAGE_TIMEOUT = (20 * HZ) / 1000;
const int MSTP_TJ_MIN_ECHO_TIMEOUT = (5 * HZ) / 1000;

// Define module-level procfs and config variables:
struct proc_dir_entry *mstp_root_dir;   // com port parent dir under /proc
struct proc_dir_entry *mstp_mod_params_file;    // access to module param data
struct proc_dir_entry *mstp_genl_log_enabled_file;  // en/disable genl logs

DEFINE_MUTEX(module_mtx);
unsigned int nModuleHasExited = 1;

// Declare Function Prototypes: Allows use of symbols (function names) in
// initialization of ldisc struct immediately below. (If functions were to
// be called in other files by means OTHER than via the struct, we would
// declare their prototypes in n_mstp.h.) Note that we do NOT set these
// funcs to be static, since we may need to examine their symbols for debug,
// AND since the "mstp_" prefix pretty much prevents kernel namespace pollution:
int mstp_open(struct tty_struct *tty);
void mstp_close(struct tty_struct *tty);
ssize_t mstp_read(struct tty_struct *tty, struct file *file,
                  unsigned char *buf, size_t nr);
ssize_t mstp_write(struct tty_struct *tty, struct file *file,
                   const unsigned __user char *buf, size_t nr);
int mstp_ioctl(struct tty_struct *tty, struct file *file,
               unsigned int cmd, unsigned long arg);
void mstp_set_termios(struct tty_struct *tty, struct ktermios *old);
unsigned int mstp_poll(struct tty_struct *tty, struct file *file,
                       struct poll_table_struct *wait);
void mstp_receive_buf(struct tty_struct *tty, const unsigned char *cp,
                      char *fp, int count);
int mstp_receive_room(struct tty_struct *tty);
void mstp_write_wakeup(struct tty_struct *tty);

// ldisc number:
// TODO: use new number (above 15, and different than that for rznet)
#define N_MSTP 5                // currently, value stolen from N_X25

struct tty_ldisc_ops tty_ldisc_N_MSTP = {
    .magic = TTY_LDISC_MAGIC,   // magic
    .name = "mstp",             // name
    .num = N_MSTP,              // num
    .flags = 0,                 // flags
    .open = mstp_open,          // open
    .close = mstp_close,        // close
    .flush_buffer = 0,          // flush_buffer
    .chars_in_buffer = 0,       // chars_in_buffer
    .read = mstp_read,          // read
    .write = mstp_write,        // write
    .ioctl = mstp_ioctl,        // ioctl
    .set_termios = mstp_set_termios,    // set_termios
    .poll = mstp_poll,          // poll
    .hangup = 0,                // hangup
    .receive_buf = mstp_receive_buf,    // receive_buf
    //.receive_room = mstp_receive_room,// receive_room
    .write_wakeup = mstp_write_wakeup   // write_wakeup
};

static int mod_params_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, mod_params_show, NULL);
}


static const struct file_operations mod_params_fops = {
  .owner = THIS_MODULE,
  .open = mod_params_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int genl_log_enabled_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, genl_log_enabled_show, NULL);
}


static const struct file_operations genl_log_enabled_fops = {
  .owner = THIS_MODULE,
  .open = genl_log_enabled_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};



/*************************************************************
* Module support routines
*************************************************************/

// mstp_init() is called upon loading of the n_mstp.o/ko module, so
// it can take an attribute "__init" (kernel 2.6). However, not necy:
int mstp_init(void)
{
    int iStatus = 0;
    unsigned int n = 0, nSize = 0;

    if (mutex_trylock(&module_mtx) == 0) {
        printk("mstp_init: module_mtx already locked: Why?\n");
        iStatus = -EFAULT;
        goto mtx_already_locked;
    }
    TRACE_M("mstp_init: Start.");
    nModuleHasExited = 0;

    // FIXME: This is a kludge to deal with the currently inconsistent model
    // names/numbers for the various NBM hardware platforms. Ideally, this
    // kernel code could obtain the correct model from some other non-framework
    // code. "Kernel" means no external procfs access (eg to
    // "/proc/mediator/model"); model must be kernel-accessible:

    MPX_TYPE = "monotreme";
    // Walk array of NBM platform config structs, to find config for platform
    // on which this module is loading:
    nSize = sizeof(mpx_cfgs) / sizeof(struct mpx_cfg *);
    for (n = 0; n < nSize; n++) {
        this_mpx_cfg = mpx_cfgs[n];
        if (!strcmp(this_mpx_cfg->szMpxType, MPX_TYPE))
            break;
    }
    if (n == nSize) {
        TRACE_M("Unable to find given MPX_TYPE: %s. Bailing out of "
                "mstp_init().", MPX_TYPE);
        iStatus = -MSTP_RTN_BAD_MPX_TYPE;
        goto bad_MPX_TYPE;
    }
    for (n = 0; n < this_mpx_cfg->nNumPortCfgs; n++) {
        // Init mutexes for portcfg structs in selected mpx_cfg:
        mutex_init(&((this_mpx_cfg->port_cfgs + n)->mtx));
        spin_lock_init(&((this_mpx_cfg->port_cfgs + n)->spin));
    }

    // Create root subdir for the procfs subdirs of all of the pInfos:
    mstp_root_dir = proc_mkdir("mstp", NULL);

    // Create and initialize the "mod_params" file entry:
    mstp_mod_params_file =
        proc_create("mod_params", 0700, mstp_root_dir, &mod_params_fops);
    if (!mstp_mod_params_file) {
        remove_proc_entry("mod_params", mstp_root_dir);
        iStatus = -ENOMEM;
        goto no_mem;
    }

    //mstp_mod_params_file->data = NULL;
    //mstp_mod_params_file->read_proc = &read_mod_params; // display module params
    //mstp_mod_params_file->write_proc = NULL;

    // Create and initialize the "genl_log_enabled" file entry:
    mstp_genl_log_enabled_file =
        proc_create("genl_log_enabled", 0700, mstp_root_dir, &genl_log_enabled_fops);
    if (!mstp_genl_log_enabled_file) {
        remove_proc_entry("genl_log_enabled", mstp_root_dir);
        iStatus = -ENOMEM;
        goto no_mem;
    }

    //mstp_genl_log_enabled_file->data = NULL;
    //mstp_genl_log_enabled_file->read_proc = &read_genl_log_enabled; // display module params
    //mstp_genl_log_enabled_file->write_proc = &set_genl_log_enabled;

    // Register this linediscipline:
    iStatus = tty_register_ldisc(N_MSTP, &tty_ldisc_N_MSTP);
    if (iStatus == 0) {
        TRACE_M("ldisc (%i) registered.", N_MSTP);
    } else {
        printk(KERN_ERR
               "mstp_init: Error registering linediscipline: %i.\n",
               iStatus);
        goto bad_tty_register;
    }
  no_mem:
  bad_MPX_TYPE:
  bad_tty_register:
    TRACE_M("mstp_init: Done.");
    mutex_unlock(&module_mtx);
  mtx_already_locked:
    return iStatus;
}


static int stats_proc_open(struct inode *inode, struct  file *file) {
    return single_open(file, stats_show, PDE_DATA(inode));
}

static const struct file_operations stats_fops = {
  .owner = THIS_MODULE,
  .open = stats_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int nodes_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, nodes_show, PDE_DATA(inode));
}

static const struct file_operations nodes_fops = {
  .owner = THIS_MODULE,
  .open = nodes_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int addr_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, addr_show, PDE_DATA(inode));
}

static const struct file_operations addr_fops = {
  .owner = THIS_MODULE,
  .open = addr_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int reply_delay_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, reply_delay_show, PDE_DATA(inode));
}

static const struct file_operations reply_delay_fops = {
  .owner = THIS_MODULE,
  .open = reply_delay_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int max_frame_cnt_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, max_frame_cnt_show, PDE_DATA(inode));
}

static const struct file_operations max_frame_cnt_fops = {
  .owner = THIS_MODULE,
  .open = max_frame_cnt_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int loopback_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, loopback_show, PDE_DATA(inode));
}

static const struct file_operations loopback_fops = {
  .owner = THIS_MODULE,
  .open = loopback_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int log_enabled_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, log_enabled_show, PDE_DATA(inode));
}

static const struct file_operations log_enabled_fops = {
  .owner = THIS_MODULE,
  .open = log_enabled_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};


struct procfs_file_spec procfs_file_specs[] = {
    {"stats", &stats_fops},
    {"nodes", &nodes_fops},
    {"addr", &addr_fops},
    {"reply_delay", &reply_delay_fops},
    {"max_frame_cnt", &max_frame_cnt_fops},
    {"loopback", &loopback_fops},
    {"log_enabled", &log_enabled_fops}
};

// mstp_exit() is called upon unloading of the n_mstp.o/ko module, so
// it can take an attribute "__exit" (kernel 2.6). However, not necy:
void mstp_exit(void)
{
    int iStatus = 0, i = 0;
    unsigned int n = 0;
    char *szName = NULL;
    struct port_cfg *pPortCfg = NULL;
    struct mstp_info *pInfo = NULL;
    struct mstp_procfs *pPfs = NULL;
    struct mstp_node_entry *pNodeEntry = NULL;

    mutex_lock(&module_mtx);    // wait until locked

    TRACE_M("mstp_exit: Start.");
    nModuleHasExited = 1;

    // Remove all extant mstp_info structs from global array, and dealloc mem:
    for (n = 0; n < this_mpx_cfg->nNumPortCfgs; n++) {
        pPortCfg = (this_mpx_cfg->port_cfgs + n);
        if (!pPortCfg->pInfo)
            continue;           // current mstp_info never initialized, so move on...
        // Lock out stray procfs accesses:
        mutex_lock(&pPortCfg->mtx); // wait until locked
        pInfo = pPortCfg->pInfo;
        // Remove /procfs entries specific to the current pInfo:
        pPfs = &pInfo->procfs;
        for (i =
             sizeof(procfs_file_specs) /
             sizeof(struct procfs_file_spec) - 1; i >= 0; i--) {
            szName = (char *) procfs_file_specs[i].szName;
            remove_proc_entry(szName, pPfs->root_dir);
            printk("Rmvg '%s'\n", szName);
        }
        TRACE_M("mstp_exit: Rmvg procfs dir /proc/mstp/%s",
                pPfs->szDirName);
        remove_proc_entry(pPfs->szDirName, mstp_root_dir);  // remove parent dir
        pPfs = NULL;

        // Remove and deallocate node_entry objects from pInfo's node_list:
        while (list_empty(&pInfo->node_list) == 0) {
            TRACE_M("mstp_exit: Rmvg a node_entry from list.");
            pNodeEntry = list_entry(pInfo->node_list.next,
                                    struct mstp_node_entry, list);
            list_del(pInfo->node_list.next);
            kfree(pNodeEntry);
        }
        // procfs subtree no longer accessible, so release any waiting threads:
        kfree(pInfo);           // destroy the mstp_info completely
        pPortCfg->pInfo = NULL; // indicate port is not in use
        mutex_unlock(&pPortCfg->mtx);
        TRACE_M("mstp_exit: pInfo kfree 0x%08x", (int) pInfo);
    }
    // Remove main "/proc/mstp" and sibling dirs:
    remove_proc_entry("genl_log_enabled", mstp_root_dir);
    remove_proc_entry("mod_params", mstp_root_dir);
    remove_proc_entry("mstp", NULL);

    iStatus = tty_unregister_ldisc(N_MSTP);
    if (iStatus != 0)
        printk(KERN_ERR "mstp_exit: ERR: unregistering ldisc: %i.\n",
               iStatus);
    else
        TRACE_M("ldisc successfully unregistered.");
    TRACE_M("mstp_exit: Done.");
    mutex_unlock(&module_mtx);
}

// These calls register mstp_init() and mstp_exit() as the module entry and exit
// functions for n_mstp.o/ko (formerly fixed as "init_module()" and
// "cleanup_module()"). These calls allow the developer to name those
// functions as desired:
module_init(mstp_init);
module_exit(mstp_exit);

//******************************************************************************
// Helper Functions
//******************************************************************************
struct port_cfg *get_port_cfg(struct tty_struct *tty)
{
    unsigned int m = 0;
    struct port_cfg *pPortCfg = NULL;

    // TODO: AUTOMATICALLY obtain cfg info for port attached to given tty
    // struct, rather than having to use hardcoded lists. Disadv to hardcode:
    // NEED TO REV THIS FILE to add a new list for each new hardware version! It
    // SEEMS like we should be able to get port name (eg "com1") and IRQ num
    // (eg 9) from ioctl(), or from tty_XXX struct, but apparently not...
    dev_t this_port_dev = tty_devnum(tty);
    for (m = 0; m < this_mpx_cfg->nNumPortCfgs; m++) {
        pPortCfg = (this_mpx_cfg->port_cfgs + m);
        if (pPortCfg->port_dev == this_port_dev)
            break;
    }
    return (m < this_mpx_cfg->nNumPortCfgs ? pPortCfg : NULL);
}

int get_bit_time(struct mstp_info *pInfo)
{
//      struct serial_struct ss; // used to determine custom baud rate or not
    // pInfo must be validated, and caller must hold pInfo's related mtx:
    unsigned int nInSpeedNum = 0;
    if (!pInfo->tty) {
        TRACE_PEI("pInfo->tty NULL.");
        return -EINVAL;
    }
    nInSpeedNum = pInfo->tty->termios.c_cflag & CBAUD;
    // NB: Custom baud rates appear as "38400" in this test:
    if (nInSpeedNum > B38400 || nInSpeedNum < B2400) {
        printk("_get_bit_time: Input Speed Number must be in "
               "the range B2400 (%u) to B38400 (%u). Is %u. Not supported.\n",
               B2400, B38400, nInSpeedNum);
        return -EINVAL;
    }
    pInfo->nBitTime = (B2400_BIT_usec >> (nInSpeedNum - B2400));
    pInfo->nByteTime = pInfo->nBitTime * 10;
    return 0;
}

int create_procfs_entries(struct mstp_procfs *pPfs, struct port_cfg *pPortCfg) {
    int iRtn = 0, i = 0;
    struct proc_dir_entry *pDirEntry = NULL;
    struct procfs_file_spec *pFileSpec = NULL;
    for (; i < sizeof(procfs_file_specs) / sizeof(struct procfs_file_spec); i++) {
        pFileSpec = &procfs_file_specs[i];
        pDirEntry = proc_create_data(pFileSpec->szName, 0755, pPfs->root_dir, pFileSpec->fops, pPortCfg);
        if (!pDirEntry) {
            printk(KERN_ERR
                   "mstp: FAILED to init procfs %s file. Clearing all"
                   " for port %s.\n", pFileSpec->szName,
                   pPortCfg->szPortName);

            for (i--; i >= 0; i--)
                proc_remove(pPfs->files[i]);
            iRtn = -EFAULT;
            goto no_file;
        }
        //pDirEntry->data = pPortCfg;
        //pDirEntry->read_proc = pFileSpec->read_proc;
        //pDirEntry->write_proc = pFileSpec->write_proc;
        *(pPfs->files + i) = pDirEntry;
    }
    return i;

  no_file:
    return iRtn;
}

// create_info(): Allocate and init objects that are never destroyed while
// module is loaded. Assume port mutex is already held by calling thread:
struct mstp_info *create_info(struct tty_struct *tty,
                              struct port_cfg *pPortCfg)
{
    struct mstp_info *pInfo = NULL;
    struct mstp_procfs *pPfs = NULL;

    if (pPortCfg->pInfo != NULL) {  // Already have a pInfo available for this tty, so we're done:
        return pPortCfg->pInfo;
    }
    // Allocate kernel mem for an mstp_info structure assocd with given tty.
    // Must use GFP_ATOMIC flag, since any thread in this fn will hold the
    // global spinlock for the global list of mstp_infos; cannot sleep:
    pInfo =
        (struct mstp_info *) kmalloc(sizeof(struct mstp_info), GFP_ATOMIC);
    if (!pInfo) {
        printk(KERN_ERR
               "%s: mstp: Failed to kmalloc mstp_info structure.\n",
               pPortCfg->szPortName);
        goto no_pInfo;
    }
    // Init contents of pInfo struct to all-zero BEFORE doing specific inits:
    memset(pInfo, 0x00, sizeof(struct mstp_info));

    // Show "init not done yet" for this mstp_info struct:
    atomic_set(&pInfo->atomInitDone, 0);

    // iBarrier: For debug only, to detect compiler/linker/kernel mismatches:
    pInfo->iBarrier = 0x12345678;

    // Point back at persistent, owning port_cfg:
    pInfo->pPortCfg = pPortCfg;

    // Set loopback (echo) en/disable:
    pInfo->nLoopback = this_mpx_cfg->nLoopback;

    // Prepare waitqueue objects for reading clients (ie that set port to
    // "blocking", call into mstp_read(), and wait):
    init_waitqueue_head(&pInfo->read_wait);

    // Prep string that differentiates procfs dirs for this pInfo from those
    // for others, using major/minor device numbers for assocd tty:
    pPfs = &pInfo->procfs;
    snprintf(pPfs->szDirName, sizeof(pPfs->szDirName), "%s",
             pPortCfg->szPortName);

    // Create root subdir for the procfs subdirs for the current pInfo:
    pPfs->root_dir = proc_mkdir(pPfs->szDirName, mstp_root_dir);
    // Create procfs files under root_dir:
    if (create_procfs_entries(pPfs, pPortCfg) < 0)
        goto no_files;

    pInfo->ucTS = 0x1E;         // arbitrary initial value; caller should ioctl new addr
    pPortCfg->pInfo = pInfo;
    // Reset all statistical values. Call requires valid pPortCfg->pInfo:
    clear_stats(pPortCfg);
    return pInfo;

  no_files:
    remove_proc_entry(pPfs->szDirName, mstp_root_dir);  // remove parent dir
    kfree(pInfo);
  no_pInfo:
    return NULL;
}

// reset_info(): Called by mstp_open() in main.c, and by error-detection code
// in fsa_rf.c and fsa_mn.c. Declared in n_mstp.h. Currently, assumes that basic
// tty (and assocd structs) remains valid (since mstp_open() and mstp_close()
// are actually called by the tty's open/close functions, and do not actually
// open or close the serial port connection):
int reset_info(struct mstp_info *pInfo)
{
    struct mstp_node_entry *pNodeEntry = NULL;
    int iRtn = 0;
    struct port_cfg *pPortCfg = pInfo->pPortCfg;

    TRACE_PEP("reset_info: Start.");

    // Shut down this instance of the ldisc (ie for one port only), but leave
    // the pInfo and tty structs intact:
    pInfo->timer_restart = 0;   // order timer to not restart after next timeout
    del_timer(&pInfo->SilenceTimer);    // rmv timer from kernel list

    // Reinit variables for this pInfo:
    // Until a PFM seq occurs, we are our own successor:
    pInfo->ucNS = pInfo->ucTS;
    pInfo->ucPS = pInfo->ucTS;
    pInfo->ucReqdTS = pInfo->ucTS;  // no new addr reqd at this time

    // Force a PFM the 1st time we get the token:
    pInfo->nPfmTokenCount = MSTP_N_PFM_TKN_TRG;

    // Init:
    pInfo->nEventCount = 0;
    pInfo->nLocalEvtCnt = 0;
    pInfo->nXmtFrameCount = 0;
    pInfo->nRetryCount = 0;
    pInfo->nXmtFrameCountMax = MSTP_N_MAX_INFO_FRAMES_DEF;
    pInfo->nIndex = 0;
    memset(pInfo->pucInputBuf, 0, sizeof(pInfo->pucInputBuf));

    // We assume that there are other masters on net until we know otherwise:
    pInfo->nSoleMaster = 0;

    // Set FSA States:
    pInfo->iRfState = MSTP_RFST_IDLE;
    pInfo->iMnState = MSTP_MNST_IDLE;

    // Set vars related to Reply Delay:
    if ((iRtn = get_bit_time(pInfo)) < 0)
        return iRtn;
    pInfo->ulReplyDelay = ((MSTP_NBT_MIN_TURNAROUND * pInfo->nBitTime) / (1000 * MSEC_PER_JIFFY)) + 1;  // always round up jiffies

    pInfo->nTestReqLen = MSTP_TEST_REQ_DATA_LEN;

//      atomic_set(&pInfo->rxq_not_empty, 1); // prep to kick reader out of wait...
//      wake_up_interruptible(&pInfo->read_wait); // notify reader to call back...
//      kill(pInfo->reader_pid, SIGUSR1);
//      init_waitqueue_head(&pInfo->read_wait); // re-init waitqueue

    // Init Q indices and atomic status vars:
    pInfo->nRxqWrIdx = 0;
    pInfo->nRxqRdIdx = 0;
    atomic_set(&pInfo->rxq_not_empty, 0);

    pInfo->nTxqWrIdx = 0;
    pInfo->nTxqRdIdx = 0;
    atomic_set(&pInfo->txq_not_full, 1);
    update_txq_max_used(pInfo);

    // Leave RawEvts arrays allocated, but reset indices:
    pPortCfg->iRawEvtsWr = pPortCfg->iRawEvtsRd = 0;

    pInfo->iDbg = 0;

    // Init SilenceTimer:
    init_timer(&pInfo->SilenceTimer);
    pInfo->SilenceTimer.function = rf_timeout;
    pInfo->SilenceTimer.data = (unsigned long) (pInfo->pPortCfg);

    // Clear any lingering entries from node list:
    while (list_empty(&pInfo->node_list) == 0) {
        TRACE_PEP("reset_info: Rmvg node_entry from list.");
        pNodeEntry =
            list_entry(pInfo->node_list.next, struct mstp_node_entry,
                       list);
        list_del(pInfo->node_list.next);
        kfree(pNodeEntry);
    }

    // Start SilenceTimer for use by MasterNode FSA T_NO_TOKEN (since RFFSA
    // does not need a timer while in the IDLE state):
    pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;
    pInfo->timer_restart = 1;   // timers may run now:
    TRACE_PEP("reset_info: Done.");
    return 0;
}

struct port_cfg *validate_port_cfg(struct tty_struct *tty)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) (tty->disc_data);
    dev_t this_port_dev = tty_devnum(tty);
    if (tty->ldisc == NULL      // this tty_struct does NOT have ldisc
        || tty->ldisc->ops->num != N_MSTP)  // ldisc is NOT n_mstp
    {
        printk
            ("validate_port_cfg: ERR: tty device (%i, %i) is not using "
             "N_MSTP.\n", MAJOR(this_port_dev), MINOR(this_port_dev));
        return NULL;
    }
    if (pPortCfg == NULL) {     // tty_struct has NULL disc_data:
        printk("validate_port_cfg: ERR: NULL disc_data for tty device "
               "(%i, %i).\n", MAJOR(this_port_dev), MINOR(this_port_dev));
        return NULL;
    }
    if (pPortCfg < this_mpx_cfg->port_cfgs || pPortCfg >= (this_mpx_cfg->port_cfgs + this_mpx_cfg->nNumPortCfgs)) { //      pPortCfg is out of bounds:
        printk
            ("validate_port_cfg: ERR: pPortCfg out of bounds for tty device"
             " (%i, %i).\n", MAJOR(this_port_dev), MINOR(this_port_dev));
        return NULL;
    }
    if (pPortCfg->port_dev != this_port_dev) {
        printk
            ("validate_port_cfg: ERR: pPortCfg is for device (%i, %i), not "
             "for tty device (%i, %i).\n", MAJOR(pPortCfg->port_dev),
             MINOR(pPortCfg->port_dev), MAJOR(this_port_dev),
             MINOR(this_port_dev));
        return NULL;
    }
    return pPortCfg;
}

struct mstp_info *validate_info(struct mstp_info *pInfo, int iTty)
{
    if (!pInfo) {
        printk("validate_info: ERR: pPortCfg->pInfo was NULL.\n");
        return NULL;            // mstp_exit() got here 1st?
    }
    if (iTty && !pInfo->tty) {
        printk("validate_info: ERR: pInfo->tty is NULL.\n");
        return NULL;            // other instance of mstp_close() got here 1st?
    }
    return pInfo;
}

void unlock_port(struct port_cfg *pPortCfg)
{
    mutex_unlock(&pPortCfg->mtx);
    module_put(THIS_MODULE);
}

struct port_cfg *validate_and_lock_port_tty(struct tty_struct *tty,
                                            int *iRtn)
{
    struct port_cfg *pPortCfg = NULL;
    struct mstp_info *pInfo = NULL;
    if (!try_module_get(THIS_MODULE)) {
        *iRtn = -MSTP_RTN_MOD_BAD_GET;
        goto bad_get;
    }
    *iRtn = 0;
    if (!(pPortCfg = validate_port_cfg(tty))) {
        *iRtn = -MSTP_RTN_INVAL_PORT_CFG;
        goto invalid_port_cfg;
    }
    mutex_lock(&pPortCfg->mtx);
    if (!(pInfo = validate_info(pPortCfg->pInfo, 1))) {
        *iRtn = -MSTP_RTN_INVAL_INFO;
        goto invalid_info;
    }
    return pPortCfg;

  invalid_info:
    mutex_unlock(&pPortCfg->mtx);
  invalid_port_cfg:
    module_put(THIS_MODULE);
  bad_get:
    return NULL;
}

int validate_and_lock_port(struct port_cfg *pPortCfg, int iTty)
{
    if (!pPortCfg)
        return -MSTP_RTN_INVAL_PORT_CFG;    // caller error
    if (!try_module_get(THIS_MODULE))
        return -MSTP_RTN_MOD_BAD_GET;
    mutex_lock(&pPortCfg->mtx); // wait/sleep until locked
    if (!(validate_info(pPortCfg->pInfo, iTty))) {
        unlock_port(pPortCfg);
        return -MSTP_RTN_INVAL_INFO;    // mutex UNlocked
    }
    return 0;                   // mutex LOCKED
}

//******************************************************************************
// Linediscipline Routines:
//******************************************************************************

// mstp_open():
int mstp_open(struct tty_struct *tty)
{
    unsigned long ulFlags = 0;
    int iRtn = 0, iRingBufSz = 0;
    struct mstp_info *pInfo = NULL;
    struct port_cfg *pPortCfg = NULL;
    dev_t this_port_dev = tty_devnum(tty);
    if (!(pPortCfg = get_port_cfg(tty))) {
        TRACE_PE("mstp_open: (%i, %i) not found in mpx_cfg table.",
                 MAJOR(this_port_dev), MINOR(this_port_dev));
        iRtn = -MSTP_RTN_BAD_MPX_TYPE;
        goto bad_MPX_TYPE;
    }
    mutex_lock(&pPortCfg->mtx); // wait until locked
    if (nModuleHasExited) {
        TRACE_PEP
            ("mstp_open: FAILED: mstp_exit() has already been called.");
        iRtn = -MSTP_RTN_MOD_EXITED;
        goto module_exited;
    }
    if (!try_module_get(THIS_MODULE)) {
        iRtn = -MSTP_RTN_MOD_BAD_GET;
        goto bad_get;
    }

    TRACE_LP("mstp_open: Start. IRQ = %u.", pPortCfg->nIRQ);

    // Alloc/init RawEvts ring buf:
    spin_lock_irqsave(&pPortCfg->spin, ulFlags);

    iRingBufSz = MSTP_SZ_RAW_EVTS * MSTP_SZ_UINT;
    pPortCfg->pnRawEvts = (unsigned int *) kmalloc(iRingBufSz, GFP_ATOMIC);
    if (!pPortCfg->pnRawEvts) {
        iRtn = -ENOMEM;
        //spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);
        goto no_raw_evts_buf;
    }
    memset(pPortCfg->pnRawEvts, 0, iRingBufSz);
    pPortCfg->pnRawEvtsOut =
        (unsigned int *) kmalloc(iRingBufSz, GFP_ATOMIC);
    if (!pPortCfg->pnRawEvts) {
        iRtn = -ENOMEM;
        spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);
        goto no_raw_evts_out_buf;
    }
    memset(pPortCfg->pnRawEvtsOut, 0, iRingBufSz);
    pPortCfg->iRawEvtsWr = pPortCfg->iRawEvtsRd = 0;

    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);

    // If we do NOT find a pre-existing pInfo corresponding to the given tty's
    // _device_ (even though the tty struct itself may be different),
    // then we need to create one before proceeding with the initialization:
    if (!(pInfo = create_info(tty, pPortCfg))) {    // Kernel memory problems:
        iRtn = -ENOMEM;
        goto no_pInfo;
    }
    INIT_WORK(&pPortCfg->wq_struct, timeout_wq_fn);
    INIT_LIST_HEAD(&pInfo->node_list);  // init local list of peer node entries
    pInfo->tty = tty;           // point to given tty for get_bit_time in reset_info
    if ((iRtn = reset_info(pInfo)) < 0) // execute common reset code
        goto bad_reset;
    add_SilenceTimer(pInfo);    // start the timer
    // Give the attached tty_struct ptr to assocd port_cfg struct to hand
    // back to us when appropriate. Note that this variable remains set until
    // the next time a client EXPLICITLY sets the port's ldisc to something
    // other than mstp, EVEN IF n_mstp module is unloaded and pInfo ptr becomes
    // invalid! So, it is important for userspace code to swap N_MSTP ldisc back
    // out to N_TTY _BEFORE_ unloading n_mstp:
    tty->disc_data = pPortCfg;
    TRACE_LP("mstp_open: Done. tty=0x%p,PID=%i,disc_data=0x%p",
             tty, current->pid, tty->disc_data);
    atomic_set(&pInfo->atomInitDone, 1);
    mutex_unlock(&pPortCfg->mtx);
    return 0;

  bad_reset:
    spin_lock_irqsave(&pPortCfg->spin, ulFlags);
    pPortCfg->pInfo = NULL;
    kfree(pInfo);
    pInfo = NULL;
    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);
  no_pInfo:
    spin_lock_irqsave(&pPortCfg->spin, ulFlags);
    kfree(pPortCfg->pnRawEvtsOut);
    pPortCfg->pnRawEvtsOut = NULL;
    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);
  no_raw_evts_out_buf:
    spin_lock_irqsave(&pPortCfg->spin, ulFlags);
    kfree(pPortCfg->pnRawEvts);
    pPortCfg->pnRawEvts = NULL;
    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);
  no_raw_evts_buf:
    TRACE_PEP("mstp_open: Failed to open mstp ldisc.\n");
    module_put(THIS_MODULE);
  bad_get:
  module_exited:
    mutex_unlock(&pPortCfg->mtx);
  bad_MPX_TYPE:
    return iRtn;
}

// Do just enough deactivation and dealloc in mstp_close() to prevent problems
// at next mstp_open() (if any). Delaying dealloc till mstp_exit() allows
// last procfs info to remain for inspection during debugging, after the
// process that opened the port is killed:
void mstp_close(struct tty_struct *tty)
{
    unsigned long ulFlags = 0;
    struct mstp_info *pInfo = NULL;
    struct port_cfg *pPortCfg = validate_port_cfg(tty);
    TRACE_L("mstp_close: Start.");
    if (!pPortCfg)
        goto invalid_port_cfg;
    // Notify other threads that we're closing this instance of the ldisc:
    mutex_lock(&pPortCfg->mtx); // wait until locked
    TRACE_LP("mstp_close: Started.");
    if (!(pInfo = validate_info(pPortCfg->pInfo, 1)))
        goto invalid_info;

    // Show "init not done yet" for this mstp_info struct:
    atomic_set(&pInfo->atomInitDone, 0);

    // Remove all timers:
    pInfo->timer_restart = 0;   // order timers to not restart after next timeout
    del_timer(&pInfo->SilenceTimer);

    // tty pointer no longer usable, so make sure we get a NULL-ptr kernel panic
    // (for debug) if we ever try to use the pointer after mstp_close(), and
    // before mstp_open():
    pInfo->tty = NULL;

    // Destroy/dealloc RawEvts ring buf:
    spin_lock_irqsave(&pPortCfg->spin, ulFlags);
    kfree(pPortCfg->pnRawEvts);
    pPortCfg->pnRawEvts = NULL;
    kfree(pPortCfg->pnRawEvtsOut);
    pPortCfg->pnRawEvtsOut = NULL;
    pPortCfg->iRawEvtsWr = pPortCfg->iRawEvtsRd = 0;
    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);

    // Wake up any client waiting on incoming pkts from port, so that they can
    // bail out. Prefer to use a signal and avoid messing with other vars, but
    // neither NBM kernel supports kill() or send_sig()!!!
//      kill(pInfo->reader_pid, SIGUSR1);
    atomic_set(&pInfo->rxq_not_empty, 1);   //(pInfo->tty == NULL) kills mstp_read
    wake_up_interruptible(&pInfo->read_wait);
  invalid_info:
    unlock_port(pPortCfg);      // including decrement module refcnt
    TRACE_LP("mstp_close: Almost Done.");
  invalid_port_cfg:
    TRACE_L("mstp_close: Done.");
    return;
}

// mstp_read(): Returns positive number, indicating one integral NPDU in buf
// (prefixed with a single valid src addr byte), or negative number, indicating
// an error with nothing\garbage\partial pkt in buf. Assume that this function
// will be called by C code, rather than Python, thereby obviating the need to
// snub every other call to force a timely return to userland:
ssize_t
mstp_read(struct tty_struct * tty, struct file * file, unsigned char *buf,
          size_t nr)
{
    int iRtn = 0;
    struct mstp_npdu *pNpdu = NULL;
    struct mstp_info *pInfo = NULL;
    struct port_cfg *pPortCfg = NULL;

    // Increment module refcnt, and identify and lock relevant port_cfg:
    if (!(pPortCfg = validate_and_lock_port_tty(tty, &iRtn)))
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;
    TRACE_LP("mstp_read: Start.");
    if (atomic_read(&pInfo->rxq_not_empty) == 0) {  // If the associated file has been set to non-blocking, then we're done:
        if (file->f_flags & O_NONBLOCK) {
            TRACE_LP("mstp_read: No more to read.");
            iRtn = -EAGAIN;
            goto no_more_to_read;
        } else {                // Wait for >= 1 frame to become ready to read, as signaled by IH:
            TRACE_LP
                ("mstp_read: Client thread waiting for frame to arrive.");
            pInfo->reader_pid = current->pid;
            mutex_unlock(&pPortCfg->mtx);   // allow other threads to work...
            iRtn = wait_event_interruptible(pInfo->read_wait, (atomic_read(&pInfo->rxq_not_empty) != 0));   // sleeps
            mutex_lock(&pPortCfg->mtx); // all ours again
            // Re-validate pInfo:
            if (!(pInfo = validate_info(pPortCfg->pInfo, 1))) { // tty device closed/ing or module exited/ing while we slept:
                iRtn = -EFAULT;
                goto wokeup_cranky;
            }
            // Check for signals:
            else if (iRtn != 0) {
                TRACE_LP("mstp_read: Signal woke up client thread.");
                // TODO: We've rcvd a signal, so deal with it. May be useful
                // for unloading module after disastrous termination of client,
                // during debug (?) Unfortunately, neither NBM kernel supports
                // kill() or send_sig(), etc.:
/*				if(iRtn == SIGUSR1)
				{
					iRtn = -EFAULT;
					goto wokeup_cranky;
                                                                																												}
*/ } else                       // we got us at least one frame, so get 1st:
            {
                pNpdu = read_rxq_frame(pInfo);
            }
        }
    } else {                    // We got us at least one frame, so get 1st:
        pNpdu = read_rxq_frame(pInfo);
    }
    if (pNpdu)                  // if we got us a frame, give it to the client:
    {                           // Determine whether or not the given userland buffer is large enough to
        // contain the pkt bytes, and try to copy the data to the userland
        // buffer. (copy_to_user() returns number of UNwritten bytes.):
        if (nr < (pNpdu->nLen)) {
            TRACE_PEP("mstp_read: ERR: Rd buf too small: %i < %u.",
                      nr, pNpdu->nLen);
            iRtn = -EFAULT;
            goto bad_buf;
        }
        // Keep mtx even though copy_to_user can sleep; should be short:
        iRtn = copy_to_user(buf, (unsigned char *) pNpdu, pNpdu->nLen);
        if (iRtn != 0) {
            TRACE_PEP
                ("mstp_read: ERR: copy_to_user() failed to write %i of "
                 "%u bytes.", iRtn, pNpdu->nLen);
//                              dump_block((unsigned char*)pNpdu, pNpdu->nLen);
            iRtn = -MSTP_RTN_BAD_USER_BUF;
            goto bad_buf;
        }
        TRACE_LP("mstp_read: Read %u bytes.", pNpdu->nLen);
        iRtn = pNpdu->nLen;
        pInfo->procfs.nTotalFramesToClient++;
        //dump_block(pNpdu->pucBuf, pNpdu->nLen);
    }
  bad_buf:
  wokeup_cranky:
  no_more_to_read:
    unlock_port(pPortCfg);
  invalid_port_cfg:
    TRACE_L("mstp_read: Done.");
    return iRtn;
}

// mstp_write(): This function receives dst addr (1 byte)
// and formatted NPDU (remaining bytes) from client in given buffer:
ssize_t
mstp_write(struct tty_struct * tty, struct file * file,
           const unsigned __user char *data, size_t count)
{
    int iRtn = 0;
    struct mstp_frame_entry *pFrameEntry = NULL;
    struct mstp_frame *pFrm = NULL;
    unsigned short usDataLen = (unsigned short) (count - 1);
    unsigned short usDataCrc = 0;
    unsigned char *pucFrame = NULL, *pucDataCrc = NULL;
    struct mstp_info *pInfo = NULL;
    struct port_cfg *pPortCfg = NULL;

    TRACE_L("mstp_write: Start.");
    // Increment module refcnt, and identify and lock relevant port_cfg:
    if (!(pPortCfg = validate_and_lock_port_tty(tty, &iRtn)))
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;
    TRACE_LP("mstp_write: Start. %i bytes", count);
    // Validate incoming write request:
    // If the length of given data exceeds length of tx buffer, bail out with an
    // error:
    if (count > (MSTP_MAX_DATA_SIZE + 1)) {
        TRACE_PEP("Given NPDU (%u) > max MSTP NPDU size (%u max).",
                  count, (MSTP_MAX_DATA_SIZE + 1));
        iRtn = -ETOOSMALL;
        goto buf_too_big;
    }
    // If the txq is full, bail out with error:
    if (atomic_read(&pInfo->txq_not_full) == 0) {
        TRACE_PEP("Tx Q overrun.");
        pInfo->procfs.nTotalFramesMissedFromClient++;
        iRtn = -EAGAIN;
        goto txq_full;
    }
    // Get ptrs to current frame_entry and its buffer:
    pFrameEntry = &(pInfo->txq[pInfo->nTxqWrIdx]);
    pucFrame = pFrameEntry->pucFrame;
    // Copy given dst addr byte, and then NPDU bytes, to target locations:
    // Given "data" buffer is pre-checked by upstream tty_io driver in 2.6:
    iRtn = __get_user(pucFrame[MSTP_PKT_DST_IDX + 2], data);    // can sleep
    iRtn |=
        __copy_from_user(pucFrame + MSTP_PKT_HDR_SIZE, data + 1,
                         usDataLen);
    if (iRtn) {                 // Failed to copy some or all of the given bytes:
        TRACE_PE("mstp_write: ERR: Failed to copy some user bytes.");
        iRtn = -MSTP_RTN_BAD_USER_BUF;
        goto bad_buf;
    }
    // Incl 2 DataCRC bytes (to be calc'd later) but NOT 1 dst addr byte:
    pFrameEntry->nLen = count + MSTP_PKT_HDR_SIZE + 1;
    pFrameEntry->nRetries = 0;
    // Assemble frame:
    pFrm = (struct mstp_frame *) (pucFrame + 2);
    *(pucFrame) = MSTP_PREAMBLE1;
    *(pucFrame + 1) = MSTP_PREAMBLE2;
    pFrm->ucFrameType = MSTP_FT_DATA_NO_REPLY;
    if (pucFrame[MSTP_PKT_HDR_SIZE + 1] & MSTP_NEED_REPLY_MASK)
        pFrm->ucFrameType = MSTP_FT_DATA_REPLY;
    pFrm->ucSrcAddr = pInfo->ucTS;
    pFrm->ucDataLen1 = (usDataLen >> 8) & 0xFF;
    pFrm->ucDataLen0 = usDataLen & 0xFF;
    pFrm->ucHdrCrc = mstp_hdr_crc_buf(pucFrame + 2, MSTP_PKT_HDR_SIZE - 3);
    usDataCrc = mstp_data_crc_buf(pucFrame + MSTP_PKT_HDR_SIZE, usDataLen);
    pucDataCrc = pucFrame + MSTP_PKT_HDR_SIZE + usDataLen;
    *pucDataCrc = usDataCrc & 0xFF;
    *(pucDataCrc + 1) = usDataCrc >> 8;
    //dump_block(pucFrame, pFrameEntry->nLen);
    // Show that frame has been added to end of txq; check for full:
    pInfo->nTxqWrIdx = (pInfo->nTxqWrIdx + 1) % MSTP_TXQ_LEN;
    if (pInfo->nTxqWrIdx == pInfo->nTxqRdIdx)
        atomic_set(&pInfo->txq_not_full, 0);
    update_txq_max_used(pInfo);
    pInfo->procfs.nTotalFramesFromClient++; // increment counter
  bad_buf:
  txq_full:
  buf_too_big:
    unlock_port(pPortCfg);
  invalid_port_cfg:
    TRACE_L("mstp_write: Done.");
    return iRtn;
}

int ioctl_get_addrs(struct mstp_info *pInfo, int *pArgs)
{                               // pArgs points to int[2]: Set 1st to own addr, 2nd to next addr:
    if (put_user(pInfo->ucTS, pArgs) || put_user(pInfo->ucNS, pArgs + 1)) { // Failed to copy some or all of the given bytes:
        TRACE_PEI
            ("MSTP_IOCGADDRS: ERR: Failed to copy some kernel bytes.");
        return -MSTP_RTN_BAD_USER_BUF;
    }
    return 0;
}

int ioctl_set_addr(struct mstp_info *pInfo, int *pArgs)
{                               // pArgs pnts to reqd address
    int iRtn = 0, iReqdTS = 0;
    unsigned char ucReqdTS = 0;
    // Can sleep:
    if (__get_user(iReqdTS, pArgs)) // tty_io.c already checked user buf
    {
        TRACE_PEI
            ("MSTP_IOCSADDR: ERR: Can't get addr from uspace at %p.",
             pArgs);
        iRtn = -MSTP_RTN_BAD_USER_BUF;
        goto bad_buf;
    } else {
        ucReqdTS = (unsigned char) iReqdTS;
        iRtn = submit_addr_change(pInfo, ucReqdTS);
        TRACE_LI("MSTP_IOCSADDR: Set addr to %i.", ucReqdTS);
    }
    if (put_user(iRtn, pArgs))  // rtn status in input var; can sleep
    {
        TRACE_PEI
            ("MSTP_IOCSADDR: ERR: Can't put addr-set op result (%i) "
             "into uspace at %p.", iRtn, pArgs);
        iRtn = -MSTP_RTN_BAD_USER_BUF;
    }
  bad_buf:
    return iRtn;
}

// ioctl_get_nodes:
// Byte order does NOT matter in this ioctl handler, since the intended
// consumer(s) of the info generated herein runs on the same hardware platform.
// Assume that we own the port_cfg-specific mutex upon entry (mainly for calls
// to capture_node_list(), put_user(), and copy_to_user()):
int ioctl_get_nodes(struct mstp_info *pInfo, int *pArgs)
{
    int iNumNodes = 0;
    // Python's fcntl.fcntl() can handle MAX arg size of 1024 bytes (ie 256
    // ints), but Python's fcntl.ioctl() is not so limited:
    //********
    //* ALWAYS CALL mstp_ioctl() WITH fcntl.ioctl(), NEVER fcntl.fcntl()!
    //********
    // The pInfo node_array has only 256
    // entries, but each entry consists of an address and two time_val structs,
    // for a total of 17 bytes per node entry. Also, the 1st 4 bytes of the buf
    // will contain the number of 17-byte entries to follow. So, any caller
    // should pass in a buffer with a capacity of at least 4 + 17 * 256 = 4356.
    // Memory alloc works fastest on 2^n boundaries, so round up to 8192:
    iNumNodes = capture_node_list(pInfo);   // always <= 256
    if (put_user(iNumNodes, pArgs) || copy_to_user(pArgs + sizeof(iNumNodes), pInfo->procfs.node_array, iNumNodes * sizeof(struct mstp_node_desc))) // can sleep
        return -MSTP_RTN_BAD_USER_BUF;
    return 0;
}

// ioctl_test_req:
// Form and send Test Request. Do NOT await Test Response in ldisc code;
// instead, let calling process set timers, and await and verify a
// corresponding MSTP_FT_TEST_RESP.
// pArgs points to 1st int containing the MAC addr of the target node (device),
// and 2nd int containing the length of the data portion of the test request (0
// to MSTP_MAX_DATA_SIZE bytes):
int ioctl_test_req(struct mstp_info *pInfo, int *pArgs)
{
    int iTestReqNode = 0, iTestReqLen = 0, i = 0;
    struct mstp_frame_entry *pFrameEntry = NULL;
    struct mstp_frame *pFrm = NULL;
    unsigned char *pucFrame = NULL, *pucData = NULL, *pucDataCrc = NULL;

    if (get_user(iTestReqNode, pArgs) || get_user(iTestReqLen, pArgs))  // can sleep
        return -MSTP_RTN_BAD_USER_BUF;

    // Get ptrs to current frame_entry and its buffer:
    pFrameEntry = &(pInfo->txq[pInfo->nTxqWrIdx]);
    pucFrame = pFrameEntry->pucFrame;
    pFrameEntry->nLen = MSTP_PKT_HDR_SIZE + iTestReqLen + 2;
    pFrameEntry->nRetries = 0;
    // Assemble frame. Use a simple numeric seq as data bytes:
    pFrm = (struct mstp_frame *) (pucFrame + 2);
    *(pucFrame) = MSTP_PREAMBLE1;
    *(pucFrame + 1) = MSTP_PREAMBLE2;
    pFrm->ucFrameType = MSTP_FT_TEST_REQ;
    pFrm->ucDstAddr = iTestReqNode & 0xFF;
    pFrm->ucSrcAddr = pInfo->ucTS;
    pFrm->ucDataLen1 = iTestReqLen >> 8;
    pFrm->ucDataLen0 = iTestReqLen & 0xFF;
    pFrm->ucHdrCrc = mstp_hdr_crc_buf(pucFrame + 2, MSTP_PKT_HDR_SIZE - 3);
    if (iTestReqLen > 0) {      // Add numeric sequence as requested data portion:
        pucData = pucFrame + MSTP_PKT_HDR_SIZE;
        for (i = 0; i < iTestReqLen; i++)   // prep data bytes (num seq)
            *(pucData + i) = (i % 256);
        pucDataCrc = pucFrame + MSTP_PKT_HDR_SIZE + iTestReqLen;
        *(unsigned short *) pucDataCrc =
            mstp_data_crc_buf(pucData, iTestReqLen);
    }
    dump_block(pucFrame, pFrameEntry->nLen);
    // Show that frame has been added to txq, and look for full txq:
    pInfo->nTxqWrIdx = (pInfo->nTxqWrIdx + 1) % MSTP_TXQ_LEN;
    if (pInfo->nTxqWrIdx == pInfo->nTxqRdIdx)
        atomic_set(&pInfo->txq_not_full, 0);
    update_txq_max_used(pInfo);
    return 0;
}

int ioctl_read_log(unsigned char *pArgs)
{
    int iNumLogEntries = 0, iRtn = 0;
    // According to Python's docs, fcntl.fcntl() and fcntl.ioctl() can handle
    // MAX arg size of 1024 bytes. However, experiments show that python-mpx on
    // the PPC platform show bizarre behavior (eg not rcvg back the copied
    // buf contents) for any number of bytes over 1023. Thus, even if there are
    // more entries available at the time of a request, this fn will rtn no more
    // than 31 entries. However, if 31 entries are rtnd, and more are
    // available, then the last 4 bytes of the buffer will be 0xdeaddead. (The
    // buffer should always be submitted by the caller with those 4 bytes set
    // to 0s.) If more entries are available, the caller should call back again
    // immediately (ie don't wait for a throttling timeout.) So, always call in
    // with a 1023-byte buf.
    // NOTE: Both get_avail_log_entries() and put_user() can sleep.
    if ((iNumLogEntries = get_avail_log_entries(pArgs + sizeof(int))) < 0) {
        printk("ioctl_read_log: ERR: get_avail_log_entries %i.\n",
               iNumLogEntries);
        return -MSTP_RTN_BAD_USER_BUF;
    }
    if ((iRtn = put_user(iNumLogEntries, (int *) pArgs)) != 0) {
        printk("ioctl_read_log: ERR: put_user: %i.\n", iRtn);
        return -MSTP_RTN_BAD_USER_BUF;
    }
    return 0;
}

int ioctl_get_baud(struct mstp_info *pInfo, int *pArgs)
{
    unsigned int nBaud = (1000000 / pInfo->nBitTime);
    if (put_user((int) nBaud, pArgs)) { // Failed to copy some or all of the given bytes:
        TRACE_PEI("MSTP_IOCGBAUD: ERR: Failed to copy some kernel bytes.");
        return -MSTP_RTN_BAD_USER_BUF;
    }
    return 0;
}

int ioctl_set_baud(struct mstp_info *pInfo, int *pArgs)
{                               // pArgs pnts to reqd address
    int iRtn = 0;
    unsigned int nBaud = 0;
    // Can sleep:
    if (__get_user(nBaud, pArgs))   // tty_io.c already checked user buf
    {
        TRACE_PEI
            ("MSTP_IOCSBAUD: ERR: Can't get baud from uspace at %p.",
             pArgs);
        iRtn = -MSTP_RTN_BAD_USER_BUF;
        goto bad_buf;
    } else {                    // Adapt timing to custom baud rate:
        nBaud = (unsigned int) *pArgs;
        pInfo->nBitTime = 1000000 / nBaud;  // usec
        pInfo->nByteTime = pInfo->nBitTime * 10;    // usec
    }
  bad_buf:
    return iRtn;
}

int
mstp_ioctl(struct tty_struct *tty, struct file *file,
           unsigned int cmd, unsigned long arg)
{
    int *pArgs = (int *) arg;
    int iRtn = 0;
    struct port_cfg *pPortCfg = NULL;
    struct mstp_info *pInfo = NULL;

    if (cmd == MSTP_IOCRDLOG) { // Caller wants module-scope log, which uses a spinlock, but can sleep
        // at points when the spinlock is not held:
        if (!try_module_get(THIS_MODULE))
            return -MSTP_RTN_MOD_BAD_GET;
        iRtn = ioctl_read_log((unsigned char *) pArgs);
        module_put(THIS_MODULE);
        return iRtn;
    }
    // Increment module refcnt, and identify and lock relevant port_cfg:
    if (!(pPortCfg = validate_and_lock_port_tty(tty, &iRtn)))
        goto invalid_port_cfg;
    TRACE_LP("mstp_ioctl: Start. Cmd = 0x%08x.", cmd);
    pInfo = pPortCfg->pInfo;
    switch (cmd) {
    case MSTP_IOCGADDRS:       // get own and next addresses:
        iRtn = ioctl_get_addrs(pInfo, pArgs);
        break;
    case MSTP_IOCSADDR:        // try to set own address:
        iRtn = ioctl_set_addr(pInfo, pArgs);
        break;
    case MSTP_IOCGNODES:       // Capture snapshot of node_list:
        iRtn = ioctl_get_nodes(pInfo, pArgs);
        break;
    case MSTP_IOCTESTREQ:
        iRtn = ioctl_test_req(pInfo, pArgs);
        break;
    case MSTP_IOCGBAUD:
        iRtn = ioctl_get_baud(pInfo, pArgs);
        break;
    case MSTP_IOCSBAUD:
        iRtn = ioctl_set_baud(pInfo, pArgs);
        break;
    default:
        iRtn = -ENOTTY;
        break;
    }
    TRACE_LP("mstp_ioctl: Done. Cmd = 0x%08x.", cmd);
    unlock_port(pPortCfg);
  invalid_port_cfg:
    TRACE_L("mstp_ioctl: Done. Cmd = 0x%08x.", cmd);
    return iRtn;
}

void mstp_set_termios(struct tty_struct *tty, struct ktermios *old)
{
    TRACE_L("mstp_set_termios: NOT SUPPORTED.");
}

// mstp_poll:
// Wait for read/write-related events to indicate to userspace caller
// whether a given op will block. However, because of token-passing
// architecture, read/write-ability are divorced from line conditions; instead,
// they are related to txq and rxq fill levels. So, skip the wait, test the txq
// and rxq, and return corresponding flags immediately:
unsigned int
mstp_poll(struct tty_struct *tty, struct file *file,
          struct poll_table_struct *wait)
{
    int iRtn = 0;
    struct mstp_info *pInfo = NULL;
    struct port_cfg *pPortCfg = NULL;

    TRACE_L("mstp_poll: Start.");
    // Increment module refcnt, and identify and lock relevant port_cfg:
    if (!(pPortCfg = validate_and_lock_port_tty(tty, &iRtn)))
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;
    TRACE_LP("mstp_poll: Started.");
//      poll_wait(file, &pInfo->read_wait, wait); // SKIP IT! Not appropriate here..
    if (atomic_read(&pInfo->rxq_not_empty) != 0)
        iRtn |= (POLLIN | POLLRDNORM);
    if (atomic_read(&pInfo->txq_not_full) != 0)
        iRtn |= (POLLOUT | POLLWRNORM);
    TRACE_LP("mstp_poll: Almost Done.");
    unlock_port(pPortCfg);
  invalid_port_cfg:
    TRACE_L("mstp_poll: Done.");
    return iRtn;
}

// mstp_receive_buf():
// kernel 2.6.XX: _CALLED_FROM_ A WORK-QUEUE IN tty DRIVER: SOFTWARE
// INTERRUPT HANDLER. However, because it is a work-queue (and NOT a tasklet),
// and the calling functions explicitly release their spinlocks and enable IRQs
// before calling, we SHOULD be able to sleep in this function. (The calling
// functions re-lock their spinlocks, and re-enable IRQs, after this function
// returns.)
// Calling functions: tty_buffer.c: flush_to_ldisc()
// For comparison: n_tty.c: n_tty_receive_buf()
//    This function actually locks its OWN spinlock and disables IRQs while
//    processing raw input.
//
// Called by serial port driver when it has bytes and/or errors to pass to us.
// The cp buffer and the fp buffer both have
// the same number of bytes (count), where a given byte in cp is data, and
// the corresponding byte in fp represents bitflags indicating any errors
// associated with the data byte.
//
// Copy of part of comment from n_tty.c: n_tty_receive_buf() (emphasis mine):
// "Called by the terminal DRIVER when a block of characters has
// been received. This function must be called from SOFT CONTEXTS not from
// interrupt context. The DRIVER is responsible for making calls one at a
// time and in order (or using flush_to_ldisc)".
//
// Also, the code in tty_buffer.c: flush_to_ldisc() releases its spinlock and
// re-enables IRQs before it calls this function, and then re-locks and
// re-disables IRQs after this function returns. So, we should be able to sleep
// in this function, if necessary. The comment on the flush_to_ldisc() function
// also indicates that only one thread at a time may enter this function for
// any given instance of tty.
//
// Even though we won't get any other calls to mstp_receive_buf overrunning us,
// even if we sleep, we still need to prevent this function from stepping on
// access to shared port objects in use by other preempted threads (or having
// its own access to those objects stepped on). The port_cfg mutex for this
// tty should suffice (ie should not need to use spinlocks or disable IRQs).
//
// KERNEL 2.4.XX: Can be called EITHER DIRECTLY from IH top-half (if
// tty->low_latency != 0), OR from a deferred function (tasklet, which ALSO
// CANNOT sleep, just like the IH top-half).
//
// SYNCH WITH TIMER COMPLETION: Because the timer completion fn (rf_timeout())
// is a "top-half" IH, it cannot sleep on the per-port (or any) mutex. Instead,
// rf_timeout calls mutex_trylock. If the call fails, rf_timeout schedules a
// workqueue to handle the timeout processing. (Else, rf_timeout handles the
// timeout immediately - no problem.) HOWEVER, between a scheduling and the
// actual execution of the corresponding workqueue, mstp_receive_buf could be
// called. This out-of-order processing could cause problems. So, rf_timeout
// and this fn both feed raw events into a ring buf for _exclusive_ processing
// (ie any given event is processed EXACTLY once) in _either_ this fn or the
// timeout_wq_fn (whichever runs 1st):
//
void
mstp_receive_buf(struct tty_struct *tty, const unsigned char *cp,
                 char *fp, int count)
{
    const unsigned char *p;
    char *f = NULL, flags = TTY_NORMAL;
    int i = 0, iRtn = 0;
    struct port_cfg *pPortCfg = (struct port_cfg *) (tty->disc_data);
    unsigned int nEvt = 0;

    TRACE_L_HV("mstp_receive_buf: Start.");
    // Examine and distribute to ring buf each given event. Ring buf belongs
    // directly to port_cfg. Fns that use it check for dealloc:
    for (i = count, p = cp, f = fp; i; i--, p++) {  // If flag buffer is non-NULL, get flag byte for current index:
        if (f)
            flags = *f++;
        if (flags == TTY_NORMAL) {
            nEvt = (unsigned int) (*p); // 1st LS byte
            put_event(pPortCfg, nEvt);
        } else {
            nEvt = ((unsigned int) flags) << 8; // 2nd LS byte
            put_event(pPortCfg, nEvt);
        }
    }
    // Increment module refcnt, and identify and lock relevant port_cfg:
    if (!(pPortCfg = validate_and_lock_port_tty(tty, &iRtn)))
        goto invalid_port_cfg;
    TRACE_LP_HV("mstp_receive_buf: Started.");
    process_events(pPortCfg);
    TRACE_LP_HV("mstp_receive_buf: Almost Done.");
    unlock_port(pPortCfg);
  invalid_port_cfg:
    TRACE_L_HV("mstp_receive_buf: Done.");
    return;
}

int mstp_receive_room(struct tty_struct *tty)
{
    TRACE_L("mstp_receive_room(): Always rtns PAGE_SIZE...");
    return PAGE_SIZE;           // let 'em on in...
}

void mstp_write_wakeup(struct tty_struct *tty)
{
    TRACE_L("mstp_write_wakeup(): NOT CURRENTLY SUPPORTED.");
    return;
}

MODULE_LICENSE("GPL");

