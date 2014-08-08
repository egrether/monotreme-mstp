// procfs.c

#include "super_hdr.h"
#include "n_mstp.h"
#include "procfs.h"
#include "util.h"

// System calls that we need to use:
unsigned long (*strtoul) (const char *, char **, int);

// procfs Access Functions:
int read_nodes(char *page, char **start, off_t off, int count, int *eof,
               void *data)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    struct mstp_info *pInfo = NULL;
    int i = 0, iNumNodes = 0, len = 0;
    int limit = count - 80;     // lv a line's-worth of chars for a "too much" msg
    struct timeval tm;
    struct mstp_node_desc *pND = NULL;

    if (validate_and_lock_port(pPortCfg, 0) != 0)
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;

    do_gettimeofday(&tm);
    len =
        sprintf(page, "Current Time: %04d:%06d\n",
                (int) (tm.tv_sec) & 0x1FFF, (int) (tm.tv_usec));
    len += sprintf(page + len, "ADDR LAST_START LAST_END\n");

    iNumNodes = capture_node_list(pInfo);
    for (i = 0; i < iNumNodes; i++) {
        pND = &(pInfo->procfs.node_array[i]);

        len += sprintf(page + len, "%02x   %04d:%03d   %04d:%03d\n",
                       pND->ucAddr,
                       (int) (pND->tmStartTokenHold.tv_sec) & 0x1FFF,
                       (int) (pND->tmStartTokenHold.tv_usec) / 1000,
                       (int) (pND->tmEndTokenHold.tv_sec) & 0x1FFF,
                       (int) (pND->tmEndTokenHold.tv_usec) / 1000);

        if (len >= limit) {
            len += sprintf(page + len, "Too many nodes!");
            TRACE_PEP("Too many nodes for one page. Skipping rest...");
            break;
        }
    }
    unlock_port(pPortCfg);
  invalid_port_cfg:
    return len;
}

int set_nodes(struct file *fp, const char *buf, unsigned long count,
              void *data)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    struct mstp_info *pInfo = NULL;

    if (validate_and_lock_port(pPortCfg, 0) != 0)
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;

    // Reset the entire ldisc, to clear and rebuild table:
    reset_info(pInfo);

    unlock_port(pPortCfg);
  invalid_port_cfg:
    return count;               // return non-zero (unless count was 0), else shell hangs
}

int read_stats(char *page, char **start, off_t off, int count, int *eof,
               void *data)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    struct mstp_info *pInfo = NULL;
    int len = 0;
    unsigned int nTotalBadOctetsRcvd = 0, nLineHealthMetric = 0, nTxQUsed =
        0;
    unsigned int nMeasurementPeriod = 0;
    struct timeval tmv;

    if (validate_and_lock_port(pPortCfg, 0) != 0)
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;

    do_gettimeofday(&tmv);
    nMeasurementPeriod = (tmv.tv_sec - pInfo->procfs.tmStatsStart.tv_sec);

    nTotalBadOctetsRcvd = (pInfo->procfs.nEatAnOctet
                           + pInfo->procfs.nNotPre2Byte +
                           pInfo->procfs.nRptdPre1 +
                           pInfo->procfs.nBadHdrCrc +
                           pInfo->procfs.nBadDataCrc);

    nLineHealthMetric =
        ((pInfo->procfs.nTotalBytesRcvd - nTotalBadOctetsRcvd)
         * 100) / (pInfo->procfs.nTotalBytesRcvd + 1);  // "+ 1" prevent /0

    nTxQUsed = update_txq_max_used(pInfo);

    len = sprintf(page,
                  "RECEIVE FRAME:\n"
                  "TotalFramesFromPort = %d\n"
                  "NoDataFramesFromPort = %d\n"
                  "DataFramesFromPort = %d\n"
                  "TotalFramesToPort = %d\n"
                  "EatAnOctet = %d\n"
                  "EatAnError = %d\n"
                  "Repeated Preamble 1 = %d\n"
                  "Not Preamble 2 = %d\n"
                  "Preamble Timeout = %d\n"
                  "Preamble CommErr = %d\n"
                  "HdrTimeout = %d\n"
                  "HdrCommErr = %d\n"
                  "FrameTooLong = %d\n"
                  "BadHdrCrc = %d\n"
                  "DataTimeout = %d\n"
                  "DataCommErr = %d\n"
                  "BadDataCrc = %d\n"
                  "InvalidFrames = %d\n"
                  "\nTotalBadOctetsRcvd = %d\n"
                  "TotalOctetsRcvd = %d\n"
                  "MeasurementPeriod = %d sec\n"
                  "AvgOctetsPerSecOnBus = %d\n"
                  "LineHealthMetric = %d (0: Worst, 100: Best)\n"
                  "\nTxQ_Used = %03d %%\n"
                  "Max_TxQ_Used = %03d %%\n"
                  "\nMASTER NODE:\n"
                  "TotalFramesFromClient = %d\n"
                  "TotalFramesToClient = %d\n"
                  "TotalTokensSeen = %d\n"
                  "TotalTokensRecvd = %d\n"
                  "TotalTokensPassed = %d\n"
                  "TotalPfmsSeen = %d\n"
                  "TotalPfmsRecvd = %d\n"
                  "TotalPfmsSent = %d\n"
                  "TotalPfmsReplied = %d\n"
                  "TotalReplyPostponedOut = %d\n"
                  "TotalTestRespOut = %d\n"
                  "IdleInvalidFrame = %d\n"
                  "LostToken = %d\n"
                  "WaitReplyUnexpectedFrame = %d\n"
                  "WaitReplyTimeout = %d\n"
                  "WaitReplyInvalidFrame = %d\n"
                  "RetrySendToken = %d\n"
                  "FindNewSuccessor = %d\n"
                  "DeclareSoleMaster = %d\n"
                  "PfmUnexpectedFrame = %d\n"
                  "DelayUnwantedEvts = %d\n"
                  "TestResponse Pkts Recvd = %d\n"
                  "EchoTimeouts = %d\n"
                  "MasterNodeState = %d\n"
                  "RecvFrameState = %d\n",
                  pInfo->procfs.nTotalFramesFromPort,
                  pInfo->procfs.nNoDataFramesFromPort,
                  pInfo->procfs.nDataFramesFromPort,
                  pInfo->procfs.nTotalFramesToPort,
                  pInfo->procfs.nEatAnOctet,
                  pInfo->procfs.nEatAnError,
                  pInfo->procfs.nRptdPre1,
                  pInfo->procfs.nNotPre2Byte,
                  pInfo->procfs.nPreambTimeout,
                  pInfo->procfs.nPreambCommErr,
                  pInfo->procfs.nHdrTimeout,
                  pInfo->procfs.nHdrCommErr,
                  pInfo->procfs.nFrameTooLong,
                  pInfo->procfs.nBadHdrCrc,
                  pInfo->procfs.nDataTimeout,
                  pInfo->procfs.nDataCommErr,
                  pInfo->procfs.nBadDataCrc,
                  pInfo->procfs.nInvalidFrame,
                  nTotalBadOctetsRcvd,
                  pInfo->procfs.nTotalBytesRcvd,
                  nMeasurementPeriod,
                  pInfo->procfs.nTotalBytesRcvd / nMeasurementPeriod,
                  nLineHealthMetric,
                  nTxQUsed,
                  pInfo->procfs.nMaxTxQUsed,
                  pInfo->procfs.nTotalFramesFromClient,
                  pInfo->procfs.nTotalFramesToClient,
                  pInfo->procfs.nTotalTokensSeen,
                  pInfo->procfs.nTotalTokensRecvd,
                  pInfo->procfs.nTotalTokensPassed,
                  pInfo->procfs.nTotalPfmsSeen,
                  pInfo->procfs.nTotalPfmsRecvd,
                  pInfo->procfs.nTotalPfmsSent,
                  pInfo->procfs.nTotalPfmsReplied,
                  pInfo->procfs.nTotalReplyPostponedOut,
                  pInfo->procfs.nTotalTestRespOut,
                  pInfo->procfs.nIdleInvalidFrame,
                  pInfo->procfs.nLostToken,
                  pInfo->procfs.nWaitReplyUnexpectedFrame,
                  pInfo->procfs.nWaitReplyTimeout,
                  pInfo->procfs.nWaitReplyInvalidFrame,
                  pInfo->procfs.nRetrySendToken,
                  pInfo->procfs.nFindNewSuccessor,
                  pInfo->procfs.nDeclareSoleMaster,
                  pInfo->procfs.nPfmUnexpectedFrame,
                  pInfo->procfs.nDelayUnwantedEvts,
                  pInfo->procfs.nTestRespsRecvd,
                  pInfo->procfs.nEchoTimeout,
                  pInfo->iMnState, pInfo->iRfState);

    unlock_port(pPortCfg);
  invalid_port_cfg:
    return len;
}

int clear_stats(struct port_cfg *pPortCfg)
{
    struct mstp_info *pInfo = pPortCfg->pInfo;

    pInfo->procfs.nTotalBytesRcvd = 0;
    pInfo->procfs.nTotalFramesFromPort = 0;
    pInfo->procfs.nNoDataFramesFromPort = 0;
    pInfo->procfs.nDataFramesFromPort = 0;
    pInfo->procfs.nTotalFramesToPort = 0;
    pInfo->procfs.nEatAnOctet = 0;
    pInfo->procfs.nEatAnError = 0;
    pInfo->procfs.nRptdPre1 = 0;
    pInfo->procfs.nNotPre2Byte = 0, pInfo->procfs.nPreambTimeout = 0;
    pInfo->procfs.nPreambCommErr = 0;
    pInfo->procfs.nHdrTimeout = 0;
    pInfo->procfs.nHdrCommErr = 0;
    pInfo->procfs.nFrameTooLong = 0;
    pInfo->procfs.nBadHdrCrc = 0;
    pInfo->procfs.nDataTimeout = 0;
    pInfo->procfs.nDataCommErr = 0;
    pInfo->procfs.nBadDataCrc = 0;
    pInfo->procfs.nInvalidFrame = 0;
    pInfo->procfs.nTotalFramesFromClient = 0;
    pInfo->procfs.nTotalFramesToClient = 0;
    pInfo->procfs.nTotalTokensSeen = 0;
    pInfo->procfs.nTotalTokensRecvd = 0;
    pInfo->procfs.nTotalTokensPassed = 0;
    pInfo->procfs.nTotalPfmsSeen = 0;
    pInfo->procfs.nTotalPfmsRecvd = 0;
    pInfo->procfs.nTotalPfmsSent = 0;
    pInfo->procfs.nTotalPfmsReplied = 0;
    pInfo->procfs.nTotalPfmsReplied = 0;
    pInfo->procfs.nTotalReplyPostponedOut = 0;
    pInfo->procfs.nIdleInvalidFrame = 0;
    pInfo->procfs.nLostToken = 0;
    pInfo->procfs.nWaitReplyUnexpectedFrame = 0;
    pInfo->procfs.nWaitReplyTimeout = 0;
    pInfo->procfs.nWaitReplyInvalidFrame = 0;
    pInfo->procfs.nRetrySendToken = 0;
    pInfo->procfs.nFindNewSuccessor = 0;
    pInfo->procfs.nDeclareSoleMaster = 0;
    pInfo->procfs.nPfmUnexpectedFrame = 0;
    pInfo->procfs.nDelayUnwantedEvts = 0;
    pInfo->procfs.nTestRespsRecvd = 0;
    pInfo->procfs.nEchoTimeout = 0;

    pInfo->procfs.tmStatsStart.tv_sec = 0;
    pInfo->procfs.tmStatsStart.tv_usec = 0;
    do_gettimeofday(&pInfo->procfs.tmStatsStart);
    return 0;
}

int set_stats(struct file *fp, const char *buf, unsigned long count,
              void *data)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    if (validate_and_lock_port(pPortCfg, 0) != 0)
        goto invalid_port_cfg;
    clear_stats(pPortCfg);
    unlock_port(pPortCfg);
  invalid_port_cfg:
    return count;               // return non-zero (unless count was 0), else shell hangs
}

/******************************************************************************
 * Read/Set Value Functions and Helpers
 ******************************************************************************/
enum                            // Value Types that can be set and/or read:
{
    VT_MOD_PARAMS = 0,
    VT_ADDR,
    VT_REPLY_DELAY,
    VT_MAX_FRAME_CNT,
    VT_LOOPBACK,
    VT_LOG_ENABLED,
    VT_GENL_LOG_ENABLED,
    VT_SIZE
};

// Seq_file versions
int nodes_show(struct seq_file *m, void *v) {
    struct port_cfg *pPortCfg = (struct port_cfg *) m->private;
    struct mstp_info *pInfo = NULL;
    int i = 0, iNumNodes = 0, len = 0;
    struct timeval tm;
    struct mstp_node_desc *pND = NULL;

    if (validate_and_lock_port(pPortCfg, 0) != 0)
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;

    do_gettimeofday(&tm);
    seq_printf(m, "Current Time: %04d:%06d\n", (int) (tm.tv_sec) & 0x1FFF, (int) (tm.tv_usec));
    seq_printf(m, "ADDR LAST_START LAST_END\n");

    iNumNodes = capture_node_list(pInfo);
    for (i = 0; i < iNumNodes; i++) {
        pND = &(pInfo->procfs.node_array[i]);

        seq_printf(m, "%02x   %04d:%03d   %04d:%03d\n",
                       pND->ucAddr,
                       (int) (pND->tmStartTokenHold.tv_sec) & 0x1FFF,
                       (int) (pND->tmStartTokenHold.tv_usec) / 1000,
                       (int) (pND->tmEndTokenHold.tv_sec) & 0x1FFF,
                       (int) (pND->tmEndTokenHold.tv_usec) / 1000);

    }
    unlock_port(pPortCfg);
  invalid_port_cfg:
    return 0;
}

int stats_show(struct seq_file *m, void *v) {
    struct port_cfg *pPortCfg = (struct port_cfg *) m->private;
    struct mstp_info *pInfo = NULL;
    int len = 0;
    unsigned int nTotalBadOctetsRcvd = 0, nLineHealthMetric = 0, nTxQUsed = 0;
    unsigned int nMeasurementPeriod = 0;
    struct timeval tmv;

    if (validate_and_lock_port(pPortCfg, 0) != 0)
        goto invalid_port_cfg;
    pInfo = pPortCfg->pInfo;

    do_gettimeofday(&tmv);
    nMeasurementPeriod = (tmv.tv_sec - pInfo->procfs.tmStatsStart.tv_sec);

    nTotalBadOctetsRcvd = (pInfo->procfs.nEatAnOctet
                           + pInfo->procfs.nNotPre2Byte +
                           pInfo->procfs.nRptdPre1 +
                           pInfo->procfs.nBadHdrCrc +
                           pInfo->procfs.nBadDataCrc);

    nLineHealthMetric =
        ((pInfo->procfs.nTotalBytesRcvd - nTotalBadOctetsRcvd)
         * 100) / (pInfo->procfs.nTotalBytesRcvd + 1);  // "+ 1" prevent /0

    nTxQUsed = update_txq_max_used(pInfo);

    len = seq_printf(m,
                  "RECEIVE FRAME:\n"
                  "TotalFramesFromPort = %d\n"
                  "NoDataFramesFromPort = %d\n"
                  "DataFramesFromPort = %d\n"
                  "TotalFramesToPort = %d\n"
                  "EatAnOctet = %d\n"
                  "EatAnError = %d\n"
                  "Repeated Preamble 1 = %d\n"
                  "Not Preamble 2 = %d\n"
                  "Preamble Timeout = %d\n"
                  "Preamble CommErr = %d\n"
                  "HdrTimeout = %d\n"
                  "HdrCommErr = %d\n"
                  "FrameTooLong = %d\n"
                  "BadHdrCrc = %d\n"
                  "DataTimeout = %d\n"
                  "DataCommErr = %d\n"
                  "BadDataCrc = %d\n"
                  "InvalidFrames = %d\n"
                  "\nTotalBadOctetsRcvd = %d\n"
                  "TotalOctetsRcvd = %d\n"
                  "MeasurementPeriod = %d sec\n"
                  "AvgOctetsPerSecOnBus = %d\n"
                  "LineHealthMetric = %d (0: Worst, 100: Best)\n"
                  "\nTxQ_Used = %03d %%\n"
                  "Max_TxQ_Used = %03d %%\n"
                  "\nMASTER NODE:\n"
                  "TotalFramesFromClient = %d\n"
                  "TotalFramesToClient = %d\n"
                  "TotalTokensSeen = %d\n"
                  "TotalTokensRecvd = %d\n"
                  "TotalTokensPassed = %d\n"
                  "TotalPfmsSeen = %d\n"
                  "TotalPfmsRecvd = %d\n"
                  "TotalPfmsSent = %d\n"
                  "TotalPfmsReplied = %d\n"
                  "TotalReplyPostponedOut = %d\n"
                  "TotalTestRespOut = %d\n"
                  "IdleInvalidFrame = %d\n"
                  "LostToken = %d\n"
                  "WaitReplyUnexpectedFrame = %d\n"
                  "WaitReplyTimeout = %d\n"
                  "WaitReplyInvalidFrame = %d\n"
                  "RetrySendToken = %d\n"
                  "FindNewSuccessor = %d\n"
                  "DeclareSoleMaster = %d\n"
                  "PfmUnexpectedFrame = %d\n"
                  "DelayUnwantedEvts = %d\n"
                  "TestResponse Pkts Recvd = %d\n"
                  "EchoTimeouts = %d\n"
                  "MasterNodeState = %d\n"
                  "RecvFrameState = %d\n",
                  pInfo->procfs.nTotalFramesFromPort,
                  pInfo->procfs.nNoDataFramesFromPort,
                  pInfo->procfs.nDataFramesFromPort,
                  pInfo->procfs.nTotalFramesToPort,
                  pInfo->procfs.nEatAnOctet,
                  pInfo->procfs.nEatAnError,
                  pInfo->procfs.nRptdPre1,
                  pInfo->procfs.nNotPre2Byte,
                  pInfo->procfs.nPreambTimeout,
                  pInfo->procfs.nPreambCommErr,
                  pInfo->procfs.nHdrTimeout,
                  pInfo->procfs.nHdrCommErr,
                  pInfo->procfs.nFrameTooLong,
                  pInfo->procfs.nBadHdrCrc,
                  pInfo->procfs.nDataTimeout,
                  pInfo->procfs.nDataCommErr,
                  pInfo->procfs.nBadDataCrc,
                  pInfo->procfs.nInvalidFrame,
                  nTotalBadOctetsRcvd,
                  pInfo->procfs.nTotalBytesRcvd,
                  nMeasurementPeriod,
                  pInfo->procfs.nTotalBytesRcvd / nMeasurementPeriod,
                  nLineHealthMetric,
                  nTxQUsed,
                  pInfo->procfs.nMaxTxQUsed,
                  pInfo->procfs.nTotalFramesFromClient,
                  pInfo->procfs.nTotalFramesToClient,
                  pInfo->procfs.nTotalTokensSeen,
                  pInfo->procfs.nTotalTokensRecvd,
                  pInfo->procfs.nTotalTokensPassed,
                  pInfo->procfs.nTotalPfmsSeen,
                  pInfo->procfs.nTotalPfmsRecvd,
                  pInfo->procfs.nTotalPfmsSent,
                  pInfo->procfs.nTotalPfmsReplied,
                  pInfo->procfs.nTotalReplyPostponedOut,
                  pInfo->procfs.nTotalTestRespOut,
                  pInfo->procfs.nIdleInvalidFrame,
                  pInfo->procfs.nLostToken,
                  pInfo->procfs.nWaitReplyUnexpectedFrame,
                  pInfo->procfs.nWaitReplyTimeout,
                  pInfo->procfs.nWaitReplyInvalidFrame,
                  pInfo->procfs.nRetrySendToken,
                  pInfo->procfs.nFindNewSuccessor,
                  pInfo->procfs.nDeclareSoleMaster,
                  pInfo->procfs.nPfmUnexpectedFrame,
                  pInfo->procfs.nDelayUnwantedEvts,
                  pInfo->procfs.nTestRespsRecvd,
                  pInfo->procfs.nEchoTimeout,
                  pInfo->iMnState, pInfo->iRfState);

    unlock_port(pPortCfg);
  invalid_port_cfg:
    return 0;
}

int mod_params_show(struct seq_file *m, void *v) {
    return seq_printf(m, "MPX_TYPE = %s\n", MPX_TYPE);
}

int addr_show(struct seq_file *m, void *v) {
    struct mstp_info *pInfo = ((struct port_cfg *)m->private)->pInfo;
    if (pInfo->nLoopback)
        return seq_printf(m, "0x%02x\nEchoDelay = %lu\n", pInfo->ucTS, pInfo->procfs.ulEchoDelay);
    return seq_printf(m, "0x%02x\nEchoDelay = N/A\n", pInfo->ucTS);
}

int reply_delay_show(struct seq_file *m, void *v) {
    struct mstp_info *pInfo = ((struct port_cfg *)m->private)->pInfo;
    return seq_printf(m, "%lu msec\n", (pInfo->ulReplyDelay * MSEC_PER_JIFFY));
}

int max_frame_cnt_show(struct seq_file *m, void *v) {
    struct mstp_info *pInfo = ((struct port_cfg *)m->private)->pInfo;
    return seq_printf(m, "%u frames max\n", pInfo->nXmtFrameCountMax);
}

int loopback_show(struct seq_file *m, void *v) {
    struct mstp_info *pInfo = ((struct port_cfg *)m->private)->pInfo;
    return seq_printf(m, "%sabled\n", (pInfo->nLoopback == 0 ? "Dis" : "En"));
}

int log_enabled_show(struct seq_file *m, void *v) {
    struct mstp_info *pInfo = ((struct port_cfg *)m->private)->pInfo;
    return seq_printf(m, "%sabled\n", (pInfo->pPortCfg->iLogEnabled == 0 ? "Dis" : "En"));
}

int genl_log_enabled_show(struct seq_file *m, void *v) {
    return seq_printf(m, "%sabled\n", (iGenlLogEnabled == 0 ? "Dis" : "En"));
}




// Helper methods that execute actual value reads by generating strings from
// values borne by pInfo:
int _read_mod_params(char *page, struct mstp_info *DO_NOT_USE)
{
    return sprintf(page, "MPX_TYPE = %s\n", MPX_TYPE);
}

int _read_addr(char *page, struct mstp_info *pInfo)
{
    if (pInfo->nLoopback)
        return sprintf(page, "0x%02x\nEchoDelay = %lu\n", pInfo->ucTS,
                       pInfo->procfs.ulEchoDelay);
    return sprintf(page, "0x%02x\nEchoDelay = N/A\n", pInfo->ucTS);
}

int _read_reply_delay(char *page, struct mstp_info *pInfo)
{
    return sprintf(page, "%lu msec\n",
                   (pInfo->ulReplyDelay * MSEC_PER_JIFFY));
}

int _read_max_frame_cnt(char *page, struct mstp_info *pInfo)
{
    return sprintf(page, "%u frames max\n", pInfo->nXmtFrameCountMax);
}

int _read_loopback(char *page, struct mstp_info *pInfo)
{
    return sprintf(page, "%sabled\n",
                   (pInfo->nLoopback == 0 ? "Dis" : "En"));
}

int _read_log_enabled(char *page, struct mstp_info *pInfo)
{
    return sprintf(page, "%sabled\n",
                   (pInfo->pPortCfg->iLogEnabled == 0 ? "Dis" : "En"));
}

int _read_genl_log_enabled(char *page, struct mstp_info *pInfo)
{
    return sprintf(page, "%sabled\n",
                   (iGenlLogEnabled == 0 ? "Dis" : "En"));
}

// Array of ptrs to helper functions above, indexed by Value Type:
int (*_read_value[VT_SIZE]) (char *page, struct mstp_info * pInfo) = {
_read_mod_params,
        _read_addr,
        _read_reply_delay,
        _read_max_frame_cnt,
        _read_loopback, _read_log_enabled, _read_genl_log_enabled,};

// Wrapper function that prepares the environment, calls the helpers above, and
// breaks down the read environment:
int _read_value_wrap(char *page, void *data, int iValType)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    struct mstp_info *pInfo = NULL;
    int len = 0;

    if (pPortCfg) {
        if (validate_and_lock_port(pPortCfg, 0) != 0)
            goto invalid_port_cfg;
        pInfo = pPortCfg->pInfo;
    }

    len = _read_value[iValType] (page, pInfo);
    if (pPortCfg)
        unlock_port(pPortCfg);
  invalid_port_cfg:
    return len;
}

// Actual functions registered with procfs for callback when OS/shell reads from
// procfs:
int read_mod_params(char *page, char **w, off_t x, int y, int *z,
                    void *data)
{
    return _read_value_wrap(page, data, VT_MOD_PARAMS);
}

int read_addr(char *page, char **w, off_t x, int y, int *z, void *data)
{
    return _read_value_wrap(page, data, VT_ADDR);
}

int read_reply_delay(char *page, char **w, off_t x, int y, int *z,
                     void *data)
{
    return _read_value_wrap(page, data, VT_REPLY_DELAY);
}

int read_max_frame_cnt(char *page, char **w, off_t x, int y, int *z,
                       void *data)
{
    return _read_value_wrap(page, data, VT_MAX_FRAME_CNT);
}

int read_loopback(char *page, char **w, off_t x, int y, int *z, void *data)
{
    return _read_value_wrap(page, data, VT_LOOPBACK);
}

int read_log_enabled(char *page, char **w, off_t x, int y, int *z,
                     void *data)
{
    return _read_value_wrap(page, data, VT_LOG_ENABLED);
}

int read_genl_log_enabled(char *page, char **w, off_t x, int y, int *z,
                          void *data)
{
    return _read_value_wrap(page, data, VT_GENL_LOG_ENABLED);
}

// Helper methods that execute actual value writes with values provided by
// _set_value_wrapper() function below:
int _set_addr(struct mstp_info *pInfo, unsigned long ulValue)
{                               // Register to make change at next opportunity:
    submit_addr_change(pInfo, (unsigned char) ulValue);
    return 0;
}

int _set_reply_delay(struct mstp_info *pInfo, unsigned long ulValue)
{
    pInfo->ulReplyDelay = ulValue / MSEC_PER_JIFFY;
    return 0;
}

int _set_max_frame_cnt(struct mstp_info *pInfo, unsigned long ulValue)
{
    pInfo->nXmtFrameCountMax = (unsigned int) ulValue;
    return 0;
}

int _set_loopback(struct mstp_info *pInfo, unsigned long ulValue)
{
    pInfo->nLoopback = (unsigned int) ulValue;
    return 0;
}

int _set_log_enabled(struct mstp_info *pInfo, unsigned long ulValue)
{
    pInfo->pPortCfg->iLogEnabled = (unsigned int) ulValue;
    return 0;
}

int _set_genl_log_enabled(struct mstp_info *pInfo, unsigned long ulValue)
{
    iGenlLogEnabled = (unsigned int) ulValue;
    return 0;
}

// Array of ptrs to helper functions above, indexed by Value Type:
int (*_set_value[VT_SIZE]) (struct mstp_info * pInfo,
                            unsigned long ulValue) = {
    NULL,                       // set_mod_params() makes no sense right now...
_set_addr,
        _set_reply_delay,
        _set_max_frame_cnt,
        _set_loopback, _set_log_enabled, _set_genl_log_enabled};

// Wrapper function that prepares the environment (including conversion of the
// given string to a single unsigned long value), calls the helpers above, and
// breaks down the read environment:
int _set_value_wrap(const char *buf, unsigned long count, void *data,
                    int iValType)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    struct mstp_info *pInfo = NULL;
    unsigned long ulValue = 0, ulCBufLen = 0, ulBufLen = 0;
    char cBuf[200];

    if (pPortCfg) {
        if (validate_and_lock_port(pPortCfg, 0) != 0)
            goto invalid_port_cfg;
        pInfo = pPortCfg->pInfo;
    }

    ulCBufLen = sizeof(cBuf) - 1;
    ulBufLen = min(count, ulCBufLen);

    // Convert given string into number of msec:
    if ((count < 1) || (copy_from_user(cBuf, buf, ulBufLen))) {
        ulBufLen = 0;
        goto bad_buf;
    }
    *(cBuf + ulBufLen) = '\0';  // end string with NULL (should not be necy...)

    // Convert given string into unsigned long value. Must use special
    // variant of strtoul to do the conversion inside kernel code. User may
    // enter number as integer (no leader), hex (0x...), or octal (0...):
    ulValue = (unsigned int) simple_strtoul(cBuf, NULL, 0);
    _set_value[iValType] (pInfo, ulValue);
  bad_buf:
    if (pPortCfg)
        unlock_port(pPortCfg);
  invalid_port_cfg:
    return ulBufLen != 0 ? (int) ulBufLen : -EFAULT;
}

// Actual functions registered with procfs for callback when OS/shell writes to
// procfs:
int set_addr(struct file *fp, const char *buf, unsigned long count,
             void *data)
{
    return _set_value_wrap(buf, count, data, VT_ADDR);
}

int set_reply_delay(struct file *fp, const char *buf, unsigned long count,
                    void *data)
{
    return _set_value_wrap(buf, count, data, VT_REPLY_DELAY);
}

int set_max_frame_cnt(struct file *fp, const char *buf,
                      unsigned long count, void *data)
{
    return _set_value_wrap(buf, count, data, VT_MAX_FRAME_CNT);
}

int set_loopback(struct file *fp, const char *buf, unsigned long count,
                 void *data)
{
    return _set_value_wrap(buf, count, data, VT_LOOPBACK);
}

int set_log_enabled(struct file *fp, const char *buf, unsigned long count,
                    void *data)
{
    return _set_value_wrap(buf, count, data, VT_LOG_ENABLED);
}

int set_genl_log_enabled(struct file *fp, const char *buf,
                         unsigned long count, void *data)
{
    return _set_value_wrap(buf, count, data, VT_GENL_LOG_ENABLED);
}

