// fsa_rf.c: RecvFrame FSA methods for processing hardware events from tty
// driver. 3 possible evts: EvtRecvByte, EvtRecvErr, EvtTimeout. Also, RFFSA
// synthesizes EvtRcvdValidFrame and EvtRcvdInvalidFrame from these hardware
// events, and forwards all events to MNFSA for processing.

#include "super_hdr.h"
#include "n_mstp.h"
#include "util.h"
#include "fsa_rf.h"
#include "fsa_mn.h"

// add_SilenceTimer(): Reset next timer expiration time, based on current
// state of RFFSA and current value of pInfo->ulMnPeriodJiffs:
void add_SilenceTimer(struct mstp_info *pInfo)
{
    unsigned long ulPeriodJiffs = MSTP_TJ_MAX_FRAME_ABORT;  // inter-byte rcv TO

    if (pInfo->timer_restart == 0)
        return;                 // probably in process of stopping ldisc..

    // No need to del_timer, since timer should NEVER be running when this fn
    // is called:
    // del_timer(&pInfo->SilenceTimer);
    if (pInfo->iRfState == MSTP_RFST_IDLE) {
        ulPeriodJiffs = pInfo->ulMnPeriodJiffs;
        if (ulPeriodJiffs == 0) {   // Invalid timeout value. Scream, and backstop with default:
            TRACE_PEI("add_SilenceTimer: ulPeriodJiffs must NOT be 0! "
                      "MN state = %i.", pInfo->iMnState);
            pInfo->ulMnPeriodJiffs = ulPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;
        }
    }
    pInfo->SilenceTimer.expires = jiffies + ulPeriodJiffs;
    add_timer(&pInfo->SilenceTimer);
}

int _eval_hdr(struct mstp_info *pInfo)  // BN Spec HEADER_CRC "state":
{
    struct mstp_frame *pFrm = (struct mstp_frame *) (pInfo->pucInputBuf);
    int iRtn = 0;

    pInfo->procfs.nTotalFramesFromPort++;
    pInfo->usDataLen = pFrm->ucDataLen0 + (pFrm->ucDataLen1 << 8);
    if (pInfo->ucHdrCrc != 0x55) {  // BadCRC:
        pInfo->procfs.nBadHdrCrc++;
        pInfo->iRfState = MSTP_RFST_IDLE;
        TRACE_K("\n");          // end line containing recd bytes
        TRACE_PEI("IHC:%i", pInfo->iMnState);
        iRtn = mn_recv_invalid_frm(pInfo);
    } else if (pInfo->usDataLen > MSTP_MAX_DATA_SIZE) { // FrameTooLong:
        pInfo->procfs.nFrameTooLong++;
        pInfo->iRfState = MSTP_RFST_IDLE;
        TRACE_K("\n");          // end line containing recd bytes
        TRACE_PEI("IS:%i", pInfo->iMnState);
        iRtn = mn_recv_invalid_frm(pInfo);
    } else if (pInfo->usDataLen == 0) { // NoData:
        pInfo->procfs.nNoDataFramesFromPort++;
        pInfo->iRfState = MSTP_RFST_IDLE;
        TRACE_K("\n");          // end line containing recd bytes
        iRtn = mn_recv_valid_frm(pInfo);
    } else {                    // Data:
        pInfo->usDataCrc = 0xFFFF;  // prep to recv data bytes
        pInfo->procfs.nDataFramesFromPort++;
        pInfo->iRfState = MSTP_RFST_DATA;
        iRtn = MSTP_RTN_WAIT_FOR_DATA;
    }
    return iRtn;
}

// rf_recv_byte: Process hardware EvtRecvByte, at WQ priority:
int rf_recv_byte(struct mstp_info *pInfo, const unsigned char uc)
{
    static int iSawFF = 0;
    int iRtn = 0;
    long lNextPeriod = 0;
    TRACE_K1("%02x ", uc);
    pInfo->procfs.nTotalBytesRcvd++;
    pInfo->nEventCount++;
    // If timer is currently running, stop it and get remaining time:
    del_timer_sync(&pInfo->SilenceTimer);
    if ((lNextPeriod = pInfo->SilenceTimer.expires - jiffies) <= 0) {
        pInfo->ulMnPeriodJiffs = 0;
        TRACE_PEI("TE: now = %lu, exp = %lu, mn: %i, rf: %i", jiffies,
                  pInfo->SilenceTimer.expires, pInfo->iMnState,
                  pInfo->iRfState);
    } else
        pInfo->ulMnPeriodJiffs = lNextPeriod;
    // See if MNFSA has anything to say about this byte:
    if ((iRtn = mn_recv_event(pInfo, uc, 0)) < 0)
        goto reset_info_tag;    // mn_recv_event() reset the ldisc
    switch (pInfo->iRfState) {
    case MSTP_RFST_IDLE:       // waiting for "Preamble1" byte:
        if (uc == MSTP_PREAMBLE1)   // got it:
        {                       // Preamble1:
            pInfo->iRfState = MSTP_RFST_PREAMBLE;
            iSawFF = 0;
        } else {                // EatAnOctet:
            if (iSawFF || uc != 0xFF) { // 1st 0xFF byte after a frame is not an error:
                iSawFF = 1;
                pInfo->procfs.nEatAnOctet++;
            }
            pInfo->iRfState = MSTP_RFST_IDLE;
        }
        break;
    case MSTP_RFST_PREAMBLE:   // waiting for "Preamble2" byte:
        if (uc == MSTP_PREAMBLE2)   // got it:
        {                       // Preamble2:
            pInfo->ucHdrCrc = 0xFF; // prep to begin CRC accum/calc
            pInfo->nIndex = 0;  // prep to save incoming bytes
            pInfo->iRfState = MSTP_RFST_HEADER;
        } else if (uc == MSTP_PREAMBLE1) {  //  RepeatedPreamble1: Stay in this state, in the hopes that
            // repeat is followed by complete, valid frame:
            pInfo->procfs.nRptdPre1++;
            pInfo->iRfState = MSTP_RFST_PREAMBLE;
        } else {                // NotPreamble:
            pInfo->procfs.nNotPre2Byte++;
            pInfo->iRfState = MSTP_RFST_IDLE;
            TRACE_PEI("IP:%i", pInfo->iMnState);
            mn_recv_invalid_frm(pInfo); // mainly, to set new timeout value
        }
        break;
    case MSTP_RFST_HEADER:     // waiting for hdr bytes:
        pInfo->pucInputBuf[pInfo->nIndex++] = uc;   // save byte in hdr buf
        pInfo->ucHdrCrc = mstp_hdr_crc(uc, pInfo->ucHdrCrc);    // accum HdrCRC
        if (pInfo->nIndex > MSTP_PKT_HDR_CRC_IDX) { // We have rcvd all hdr bytes, so evaluate hdr:
            if ((iRtn = _eval_hdr(pInfo)) < 0)
                goto reset_info_tag;    // probably reset_info...
        }
        break;
    case MSTP_RFST_DATA:       // waiting for data bytes:
        pInfo->pucInputBuf[pInfo->nIndex++] = uc;   // save byte in data buf
        pInfo->usDataCrc = mstp_data_crc(uc, pInfo->usDataCrc); // accum DataCRC
        if (pInfo->nIndex > (MSTP_PKT_HDR_CRC_IDX + pInfo->usDataLen + 2)) {    // We've recvd all data bytes and both DataCRC bytes:
            TRACE_K("\n");      // end line containing recd bytes
            pInfo->iRfState = MSTP_RFST_IDLE;
            // BN Spec DATA_CRC "state":
            if (pInfo->usDataCrc != 0xF0B8) {   // BadCRC:
                pInfo->procfs.nBadDataCrc++;
                TRACE_PEI("IDC:%i", pInfo->iMnState);
                if ((iRtn = mn_recv_invalid_frm(pInfo)) != 0)
                    goto reset_info_tag;    // probably reset_info...
            } else              // GoodCRC:
            {
                if ((iRtn = mn_recv_valid_frm(pInfo)) != 0)
                    goto reset_info_tag;    // probably reset_info...
            }
        }
        break;
    default:
        TRACE_PEI("rf_recv_byte: Unknown RFFSA state: %i.",
                  pInfo->iRfState);
        break;
    }
  reset_info_tag:
    add_SilenceTimer(pInfo);
    return iRtn;
}

// rf_recv_error: Process hardware EvtRecvErr, at WQ priority:
int rf_recv_error(struct mstp_info *pInfo, const char flag)
{
    long lTmp = 0;

    TRACE_PEI("rf_recv_error: Recv error: %i.", flag);
    pInfo->nEventCount++;
    // If timer is currently running, stop it and get remaining time:
    del_timer_sync(&pInfo->SilenceTimer);
    lTmp = (long) (pInfo->SilenceTimer.expires) - (long) jiffies;
    pInfo->ulMnPeriodJiffs = (lTmp < 0 ? 0 : (unsigned long) lTmp);
    mn_recv_event(pInfo, flag, 1);  // MAY reset info, state, and/or timeout
    // Other than incrementing counters, ignore errors. If an error truly
    // killed reception of a frame, the invalid frame will be detected in
    // rf_recv_byte() and/or rf_timeout():
    switch (pInfo->iRfState) {
    case MSTP_RFST_IDLE:       // EatAnError:
        pInfo->procfs.nEatAnError++;
        break;
    case MSTP_RFST_PREAMBLE:   // (PREAMBLE) Error:
        pInfo->procfs.nPreambCommErr++;
        break;
    case MSTP_RFST_HEADER:     // (HEADER) Error:
        pInfo->procfs.nHdrCommErr++;
        break;
    case MSTP_RFST_DATA:       // (DATA) Error:
        pInfo->procfs.nDataCommErr++;
        break;
    default:
        TRACE_PEI("rf_recv_error: Unknown RecvFrame FSA state: %i.",
                  pInfo->iRfState);
        break;
    }
    add_SilenceTimer(pInfo);    // restart timer
    return 0;
}

int do_rf_timeout(struct mstp_info *pInfo)
{
    int iRtn = 0;
    // Need to del_timer_sync() here: Could be operating from a workqueue, and
    // another thread could have re-added the timer between the time we were
    // scheduled, and now:
    del_timer_sync(&pInfo->SilenceTimer);
    switch (pInfo->iRfState) {
    case MSTP_RFST_PREAMBLE:   // (PREAMBLE) Timeout:
        pInfo->procfs.nPreambTimeout++;
        break;
    case MSTP_RFST_HEADER:     // (HEADER) Timeout:
        pInfo->procfs.nHdrTimeout++;
        break;
    case MSTP_RFST_DATA:       // (DATA) Timeout:
        pInfo->procfs.nDataTimeout++;
        break;
    default:
        break;
    }
    // ANY timeout resets RFFSA to IDLE, even though not in BACnet spec. If the
    // RFFSA was NOT in MSTP_RFST_IDLE, then the timeout was for the RFFSA.
    // Else, the timeout was for MNFSA, but RFFSA was ALREADY in MSTP_RFST_IDLE:
    pInfo->iRfState = MSTP_RFST_IDLE;
    mn_timeout(pInfo);          // pInfo may be reset by this call...
    add_SilenceTimer(pInfo);    // restart timer
    return iRtn;
}

// timeout_wq_fn:
// Workqueue function (process context: can sleep) to complete rf_timout
// timeout handler (atomic context: canNOT sleep). Processes all available
// raw events:
void timeout_wq_fn(struct work_struct *work)
{
    struct port_cfg *pPortCfg = NULL;

    pPortCfg = container_of(work, struct port_cfg, wq_struct);

    if (validate_and_lock_port(pPortCfg, 1) != 0)
        return;

    TRACE_PSP("in wq");
    process_events(pPortCfg);   // pInfo still valid

    unlock_port(pPortCfg);
    return;
}

// rf_timeout: IS A SOFTWARE INTERRUPT HANDLER (top half: don't sleep)
// 2.6: schedule a work-queue to sleep on mtx and then process queued evts.
// 2.4: Lock out all other thread and IRQs, and process THIS timeout evt.
void rf_timeout(unsigned long data)
{
    struct port_cfg *pPortCfg = (struct port_cfg *) data;
    TRACE_PSP("rf_to start.");
    if (!pPortCfg)
        return;                 // tty port is closed/ing or module is unloaded/ing
    if (!try_module_get(THIS_MODULE))
        goto bad_get;
    // Schedule a workqueue to sleep on mutex:
    put_event(pPortCfg, MSTP_EVT_TIMEOUT);
    schedule_work(&pPortCfg->wq_struct);
    TRACE_PSP("sched wq");
    module_put(THIS_MODULE);
  bad_get:
    TRACE_PSP("rf_to end.");
    return;
}

// Workqueue Business Logic: Consumes and processes RAW events (EvtRecvByte,
// EvtRecvErr, EvtTimeout) in workqueue ("process") context (ie can sleep
// waiting for mutex). Event though event sources are disparate combined
// processing allows best attempt at serializing event processing.
//
// SYNCH WITH TIMER COMPLETION: Because the timer completion fn (rf_timeout())
// is a "top-half" IH, it cannot sleep on the per-port (or any) mutex. Instead,
// rf_timeout calls mutex_trylock. If the call fails, rf_timeout schedules a
// workqueue to handle the timeout processing. (Else, rf_timeout handles the
// timeout immediately - no problem.) HOWEVER, between a scheduling and the
// actual execution of the corresponding workqueue, mstp_receive_buf could be
// called. This out-of-order processing could cause problems. So, rf_timeout
// must set a pInfo member flag whenever scheduling a workq, and this fn must
// check that flag immediately after locking the mutex. If the flag is set, this
// fn clears the flag, and processes the timeout, before processing the events
// that led the tty driver to call this fn in the 1st place:
//

#define MSTP_EVTS_WRAP(x) ( (x) & (MSTP_SZ_RAW_EVTS - 1) )

// put_events:
// (1) Wr always exits on an empty slot.
// (2) If Rd == Wr, then the buffer is completely empty.
// (3) If Rd = MOD(Wr - 1), then the buffer is completely full.
// (4) If a write op overruns Rd, then it pushes Rd one slot ahead.
// (5) port_cfg mtx NEVER locked during this call. RawEvts arrays are initd for
//     a given port_cfg in mstp_open, and are protected by port_cfg's spinlock.
int put_event(struct port_cfg *pPortCfg, unsigned int nEvt)
{
    unsigned long ulFlags = 0;
    unsigned int nEvtOrg = 0;
    unsigned int *pnWr = NULL;

    spin_lock_irqsave(&pPortCfg->spin, ulFlags);
    if (!pPortCfg->pnRawEvts || !pPortCfg->pnRawEvtsOut) {
        TRACE_PEP("put_event: RawEvents bufs not allocated right now...");
        goto shutting_down;     // must be shutting down...
    }
    pnWr = pPortCfg->pnRawEvts + pPortCfg->iRawEvtsWr;
    nEvtOrg = *pnWr;
    *pnWr = nEvt;
    pPortCfg->iRawEvtsWr = MSTP_EVTS_WRAP(pPortCfg->iRawEvtsWr + 1);
    if (pPortCfg->iRawEvtsWr == pPortCfg->iRawEvtsRd) {
        TRACE_PEP("put_event: Overwrote/lost oldest event 0x%08x.",
                  nEvtOrg);
        pPortCfg->iRawEvtsRd = MSTP_EVTS_WRAP(pPortCfg->iRawEvtsRd + 1);
    }

  shutting_down:
    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);

    return 0;
}

//
// (1) port_cfg mtx (2.6 only) ALWAYS locked throughout this call.
//
unsigned int get_events(struct port_cfg *pPortCfg)
{
    unsigned int *pnRd = NULL;
    int iDiff = 0;
    unsigned int nEvtsToRead = 0, nToEnd = 0;

    unsigned long ulFlags = 0;
    spin_lock_irqsave(&pPortCfg->spin, ulFlags);

    pnRd = pPortCfg->pnRawEvts + pPortCfg->iRawEvtsRd;
    iDiff = pPortCfg->iRawEvtsWr - pPortCfg->iRawEvtsRd;
    nEvtsToRead = mstp_index_wrap(iDiff, MSTP_SZ_RAW_EVTS);
    if (iDiff == 0)
        goto empty;             // buf is empty
    if (iDiff < 0) {            // Read index is between Write index and end of buf:
        nToEnd = MSTP_SZ_RAW_EVTS - pPortCfg->iRawEvtsRd;
        memcpy(pPortCfg->pnRawEvtsOut, pnRd, nToEnd * MSTP_SZ_UINT);
        memcpy((unsigned char *) (pPortCfg->pnRawEvtsOut + nToEnd),
               pPortCfg->pnRawEvts, (nEvtsToRead - nToEnd) * MSTP_SZ_UINT);
    } else {                    // Read index is between start of buf and Write index:
        memcpy(pPortCfg->pnRawEvtsOut, pnRd, nEvtsToRead * MSTP_SZ_UINT);
    }
    pPortCfg->iRawEvtsRd = pPortCfg->iRawEvtsWr;    // show buf now empty

  empty:
    spin_unlock_irqrestore(&pPortCfg->spin, ulFlags);
    return nEvtsToRead;
}

//
// (1) port_cfg mtx  (2.6) ALWAYS locked throughout this call.
// (2) Each evt int: B0=data, B1=flags, B2=NA, B3=EvtType.
//
int process_events(struct port_cfg *pPortCfg)
{
    unsigned int nEvt = 0, n = 0, nNumEvts = 0;
    struct mstp_info *pInfo = pPortCfg->pInfo;

    TRACE_LI_HV("process_events: Started.");

    nNumEvts = get_events(pPortCfg);    // uses spinlock and blocks IRQs
    for (n = 0; n < nNumEvts; n++) {
        nEvt = pPortCfg->pnRawEvtsOut[n];
        if (nEvt & MSTP_EVT_TIMEOUT)
            do_rf_timeout(pInfo);
        else if (nEvt & 0xFF00)
            rf_recv_error(pInfo, (nEvt & 0xFF00) >> 8);
        else
            rf_recv_byte(pInfo, nEvt & 0xFF);
    }
    TRACE_LP_HV("process_events: Done.");
    return 0;
}

