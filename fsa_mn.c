// fsa_recv.c

#include "super_hdr.h"
#include "n_mstp.h"
#include "procfs.h"
#include "util.h"
#include "fsa_rf.h"
#include "fsa_mn.h"


/*
 * TEST FRAMES:
unsigned char g_ReqObjName[] =
{
	0x01, 0x0c, 0x00, 0x0f, 0x06, 0x00, 0x80, 0xe4, 0x00, 0x02, 0x6a, 0x02, 0x03, 0x65, 0x0c, 0x0c,
	0x02, 0x00, 0x01, 0x59, 0x19, 0x4d
};

unsigned char g_RespObjName[] =
{
	0x01, 0x20, 0x00, 0x0f, 0x06, 0x00, 0x80, 0xe4, 0x00, 0x02, 0x6a, 0xff, 0x30, 0x08, 0x0c, 0x0c,
	0x02, 0x00, 0x01, 0x59, 0x19, 0x4d, 0x3e, 0x75, 0x09, 0x00, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74,
	0x6f, 0x72, 0x3f
};
*/

void _format_tx_frame(struct mstp_info *pInfo, unsigned char ucFrameType,
                      unsigned char ucDstAddr, unsigned short usDataLen,
                      unsigned char *pucData)
{
    unsigned short usDataCrc = 0;
    unsigned char *pucFrame = pInfo->send_frame.pucFrame;
    struct mstp_frame *pFrame = (struct mstp_frame *) (pucFrame + 2);   // cookie cutter

    // Form pkt into buffer:
    pInfo->send_frame.nLen = MSTP_PKT_HDR_SIZE;

    pucFrame[0] = MSTP_PREAMBLE1;
    pucFrame[1] = MSTP_PREAMBLE2;

    pFrame->ucFrameType = ucFrameType;
    pFrame->ucDstAddr = ucDstAddr;
    pFrame->ucSrcAddr = pInfo->ucTS;
    pFrame->ucDataLen1 = 0;
    pFrame->ucDataLen0 = 0;

    // For normal ops, the ldisc does NOT use the following formatting for data.
    // However, could be useful for test versions of ldisc:
    if (usDataLen != 0 && pucData != NULL) {
        pFrame->ucDataLen1 = (usDataLen >> 8) & 0xFF;
        pFrame->ucDataLen0 = usDataLen & 0xFF;
        pInfo->send_frame.nLen += usDataLen;    // do NOT incl. DataCRC bytes YET
        usDataCrc = mstp_data_crc_buf(pucData, usDataLen);
        memcpy(pucFrame + MSTP_PKT_HDR_SIZE, pucData, usDataLen);
        *(unsigned short *) (pucFrame + pInfo->send_frame.nLen) =
            usDataCrc;
        pInfo->send_frame.nLen += 2;    // incl. DataCRC bytes NOW
    }
    // Calc hdr CRC AFTER ucDataLen0/1 have been set to final values:
    pFrame->ucHdrCrc =
        mstp_hdr_crc_buf(pucFrame + 2, MSTP_PKT_HDR_SIZE - 3);
    pInfo->pSendFrame = &(pInfo->send_frame);   // pt to frame to send
}

int _handle_valid_frame_in_LO_XXX(struct mstp_info *pInfo);

int _send_frame(struct mstp_info *pInfo)
{
    int iLen = (int) (pInfo->pSendFrame->nLen), iWritten = 0;
    unsigned int ulPeriodJiffsOrg = pInfo->ulMnPeriodJiffs;
    unsigned char *pucFrame = pInfo->pSendFrame->pucFrame;

    // Set next SilenceTimer period: (length of sent frame) * (msec per byte).
    pInfo->ulMnPeriodJiffs = (unsigned long)
        (((iLen * pInfo->nByteTime) / (1000 * MSEC_PER_JIFFY)));
    if (pInfo->ulMnPeriodJiffs < MSTP_TJ_MIN_ECHO_TIMEOUT)
        pInfo->ulMnPeriodJiffs = MSTP_TJ_MIN_ECHO_TIMEOUT;
    pInfo->nLocalEvtCnt = 0;    // debug var
    pInfo->procfs.ulStartWrite = jiffies;   //start: time-reqd-to-get-1st-echo-byte
    iWritten = pInfo->tty->driver->ops->write(pInfo->tty, pucFrame, iLen);
    if (iWritten < iLen) {      // Failed to write as many bytes as ordered, so reset ldisc:
        TRACE_PEI("_send_frame: ERR: Tried %i, wrote %i.", iLen, iWritten);
        reset_info(pInfo);
        return -MSTP_RTN_RESET_LDISC;
    }
    if (pInfo->nLoopback == 0) {    // No echo chkg, so assume correct xmssn and move along to next state
        // and (cumulative) timeout values:
        pInfo->ulMnPeriodJiffs += ulPeriodJiffsOrg;
        return _handle_valid_frame_in_LO_XXX(pInfo);
    }
    return 0;
}

int _pass_token(struct mstp_info *pInfo)
{
    _format_tx_frame(pInfo, MSTP_FT_TOKEN, pInfo->ucNS, 0, NULL);
    pInfo->iMnState = MSTP_MNST_LO_TKN;
    pInfo->nRetryCount = 0;
    pInfo->nEventCount = 0;
    return _send_frame(pInfo);
}

int _send_PFM(struct mstp_info *pInfo)
{
    pInfo->nRetryCount = 0;
    _format_tx_frame(pInfo, MSTP_FT_PFM, pInfo->ucPS, 0, NULL);
    pInfo->iMnState = MSTP_MNST_LO_PFM;
    return _send_frame(pInfo);
}

// TODO: MOVE TO HANDLERS FOR ECHO_DATA AND ECHO_NEED_REPLY
void _incr_txq(struct mstp_info *pInfo)
{                               // Just sent a frame from TxQ, so maintain TxQ:
    pInfo->nTxqRdIdx = (pInfo->nTxqRdIdx + 1) % MSTP_TXQ_LEN;
    atomic_set(&pInfo->txq_not_full, 1);    // we consumed a frame, so txq CANNOT be full
    update_txq_max_used(pInfo);
}

void _post_data_to_client(struct mstp_info *pInfo)
{
    unsigned int nNextRxqWrIdx = (pInfo->nRxqWrIdx + 1) % MSTP_RXQ_LEN;
    struct mstp_npdu *pNpdu = NULL;
    TRACE_PEI("R:%u", pInfo->usDataLen);
    TRACE_LI
        ("_post_data_to_client: Start. MN State = %i. FrameDataSize = %u.",
         pInfo->iMnState, pInfo->usDataLen);
    // If rxq is full, then bail out with error:
    if (nNextRxqWrIdx == pInfo->nRxqRdIdx) {
        TRACE_PEI("Rx Q overrun.");
        pInfo->procfs.nTotalFramesMissedToClient++;
    } else {
        pNpdu = &(pInfo->rxq[pInfo->nRxqWrIdx]);
        memcpy(pNpdu->pucBuf, pInfo->pucInputBuf + MSTP_PKT_HDR_SIZE - 2,
               pInfo->usDataLen);
        pNpdu->nLen = pInfo->usDataLen + 1; // incl src addr byte in len
        pNpdu->ucSrcAddr = pInfo->pucInputBuf[MSTP_PKT_SRC_IDX];
        pInfo->nRxqWrIdx = nNextRxqWrIdx;
    }

    atomic_set(&pInfo->rxq_not_empty, 1);
    // If client waits in mstp_read(), wake it up:
    wake_up_interruptible(&(pInfo->read_wait));
    TRACE_LI("_post_data_to_client: Done.");
}

// use_token(): Implements most of the logic for BACnet Spec's USE_TOKEN and
// DONE_WITH_TOKEN states and their assocd transitions:
int _use_token(struct mstp_info *pInfo)
{
    struct mstp_frame *pNextTxqFrm = NULL;
    unsigned char ucTemp = 0;
    int iRtn = 0;
    unsigned int n = 0;

    pInfo->nRetryCount = 0;
    // If nLoopback, send <= 1 data frame. Else, send as many DATA_NO_REPLY
    // frames as are available in the txq, or max allowed per-token-hold, in
    // this loop:
    for (n = 0; pInfo->nXmtFrameCount < pInfo->nXmtFrameCountMax; n++) {    // SendAnotherFrame
        if (pInfo->nTxqWrIdx != pInfo->nTxqRdIdx || atomic_read(&pInfo->txq_not_full) == 0) {   // At least 1 frame waiting for xmssn in txq:
            pInfo->pSendFrame = &(pInfo->txq[pInfo->nTxqRdIdx]);
            pNextTxqFrm =
                (struct mstp_frame *) (pInfo->pSendFrame->pucFrame + 2);
            // Do NOT yet incr nXmtFrameCount; wait till we see echo...
            switch (pNextTxqFrm->ucFrameType) {
            case MSTP_FT_DATA_REPLY:
                if (pNextTxqFrm->ucDstAddr != MSTP_BCAST_ADDR) {    // SendAndWait:
                    pInfo->iMnState = MSTP_MNST_LO_NEED_REPLY;
                    break;
                }
            case MSTP_FT_DATA_NO_REPLY:
            case MSTP_FT_TEST_RESP:
                pInfo->iMnState = MSTP_MNST_LO_DATA;
                break;          // SendNoWait:
            case MSTP_FT_TEST_REQ:
                pInfo->iMnState = MSTP_MNST_LO_NEED_REPLY;
                break;          // SendAndWait:
            default:           // ERR: Unsupported FrameType in txq. Reset ldisc:
                TRACE_PEI("_use_token: Found frame in txq with invalid "
                          "FrameType: 0x%02x.", pNextTxqFrm->ucFrameType);
                reset_info(pInfo);
                return -MSTP_RTN_RESET_LDISC;
            }
            if ((iRtn = _send_frame(pInfo)) < 0)    // sets ulMnPeriodJiffs
                return iRtn;
            TRACE_PEI("SD:%lu", pInfo->ulMnPeriodJiffs);
            // Do not send any more frames if we need to await loopback, OR
            // we just sent a frame that was NOT an MSTP_FT_DATA_NO_REPLY:
            if (pInfo->nLoopback || pInfo->iMnState != MSTP_MNST_LO_DATA)
                break;
        } else                  // NothingToSend: Indicate "txq is empty" to next section of code:
        {
            pInfo->nXmtFrameCount = pInfo->nXmtFrameCountMax;   // end loop
        }
    }
    if (pInfo->nXmtFrameCount >= pInfo->nXmtFrameCountMax) {    // SendAnotherFrame/NothingToSend:
        if ((pInfo->ucNS == MSTP_MASTER_WRAP(pInfo->ucTS + 1))
            || (pInfo->nPfmTokenCount < (MSTP_N_PFM_TKN_TRG - 1))) {
            if (pInfo->nSoleMaster == 1) {  // SoleMaster:
                pInfo->nPfmTokenCount = MSTP_N_PFM_TKN_TRG - 1;
            } else {            // SendToken:
                return _pass_token(pInfo);
            }
        }
        if (pInfo->nPfmTokenCount >= (MSTP_N_PFM_TKN_TRG - 1)) {
            ucTemp = MSTP_MASTER_WRAP(pInfo->ucPS + 1);
            if (ucTemp != pInfo->ucNS) {    // SendMaintenancePFM:
                pInfo->ucPS = ucTemp;
                return _send_PFM(pInfo);
            } else if (pInfo->nSoleMaster == 0) {   // ResetMaintenancePFM:
                pInfo->ucPS = pInfo->ucTS;
                pInfo->nPfmTokenCount = 1;
                return _pass_token(pInfo);
            } else              // pInfo->nSoleMaster == 1:
            {                   //  SoleMasterRestartMaintenancePFM:
                if (pInfo->ucReqdTS != pInfo->ucTS)
                    change_addr(pInfo);
                pInfo->nEventCount = 0;
                pInfo->nPfmTokenCount = 1;
                pInfo->ucPS = MSTP_MASTER_WRAP(pInfo->ucNS + 1);
                pInfo->ucNS = pInfo->ucTS;
                return _send_PFM(pInfo);
            }
        }
    }
    return 0;
}

int _find_next(struct mstp_info *pInfo)
{
    unsigned char ucBase = 0;
    if (pInfo->ucReqdTS != pInfo->ucTS)
        change_addr(pInfo);
    ucBase = pInfo->ucNS;
    if (pInfo->iMnState == MSTP_MNST_NO_TOKEN)
        ucBase = pInfo->ucTS;
    pInfo->ucPS = MSTP_MASTER_WRAP(ucBase + 1);
    pInfo->ucNS = pInfo->ucTS;  // no known successor
    pInfo->nRetryCount = 0;
    pInfo->nPfmTokenCount = 0;
    _format_tx_frame(pInfo, MSTP_FT_PFM, pInfo->ucPS, 0, NULL);
    pInfo->iMnState = MSTP_MNST_LO_PFM;
    return _send_frame(pInfo);  // sets ulPeriodJiffs to XmtTime
}

int _handle_valid_frame_in_LO_XXX(struct mstp_info *pInfo)
{
    pInfo->procfs.nTotalFramesToPort++;
    switch (pInfo->iMnState) {  // Rcvd valid frame identical to last sent in one of these wait states:
    case MSTP_MNST_LO_TKN:
        TRACE_PSI("T");
        pInfo->procfs.nTotalTokensPassed++;
        pInfo->procfs.nNoDataFramesToPort++;
        pInfo->nPfmTokenCount++;    // saw the token leave us
        update_nodes(pInfo, pInfo->ucTS, pInfo->ucNS);
        // If NO loopback, accumulate (rather than replace) timeouts:
        if (pInfo->nLoopback)
            pInfo->ulMnPeriodJiffs = 0;
        pInfo->ulMnPeriodJiffs += MSTP_TJ_MIN_USAGE_TIMEOUT;    // 20 msec
        pInfo->iMnState = MSTP_MNST_PASS_TOKEN;
        break;
    case MSTP_MNST_LO_DATA:
        TRACE_PEI("D");
        pInfo->procfs.nDataFramesToPort++;
        pInfo->nXmtFrameCount++;    // saw the xmttd frame leave us
        _incr_txq(pInfo);       // successful xmssn => incr read ptr for txq
        // No addl accum of timeout for !Loopback necy at this point...
        return (pInfo->nLoopback ? _use_token(pInfo) : 0);
    case MSTP_MNST_LO_NEED_REPLY:
        TRACE_PEI("R");
        pInfo->procfs.nDataFramesToPort++;
        pInfo->nXmtFrameCount++;    // saw the xmttd frame leave us
        _incr_txq(pInfo);       // successful xmssn => incr read ptr for txq
        // If NO loopback, accumulate (rather than replace) timeouts:
        if (pInfo->nLoopback)
            pInfo->ulMnPeriodJiffs = 0;
        pInfo->ulMnPeriodJiffs += MSTP_TJ_MIN_REPLY_TIMEOUT;    // 300 msec
        pInfo->iMnState = MSTP_MNST_WAIT_REPLY;
        break;
    case MSTP_MNST_LO_PFM:
        if (pInfo->ucNS == pInfo->ucTS)
            TRACE_LI("P:%02x", pInfo->ucPS);
        else
            TRACE_PSI("P:%02x", pInfo->ucPS);
        pInfo->procfs.nTotalPfmsSeen++;
        pInfo->procfs.nTotalPfmsSent++;
        pInfo->procfs.nNoDataFramesToPort++;
        // If NO loopback, accumulate (rather than replace) timeouts:
        if (pInfo->nLoopback)
            pInfo->ulMnPeriodJiffs = 0;
        pInfo->ulMnPeriodJiffs += MSTP_TJ_MIN_USAGE_TIMEOUT;    // 20 msec
        pInfo->iMnState = MSTP_MNST_PFM;
        break;
    case MSTP_MNST_LO_PFM_REPLY:
        TRACE_LI("Y");
        pInfo->procfs.nTotalPfmsReplied++;
        pInfo->procfs.nNoDataFramesToPort++;
        // If NO loopback, accumulate (rather than replace) timeouts:
        if (pInfo->nLoopback)
            pInfo->ulMnPeriodJiffs = 0;
        pInfo->ulMnPeriodJiffs += MSTP_TJ_MAX_NO_TOKEN; // 500 msec
        pInfo->iMnState = MSTP_MNST_IDLE;
        break;
    case MSTP_MNST_LO_REPLY_POST:
        pInfo->procfs.nTotalReplyPostponedOut++;
        pInfo->procfs.nNoDataFramesToPort++;
        // If NO loopback, accumulate (rather than replace) timeouts:
        if (pInfo->nLoopback)
            pInfo->ulMnPeriodJiffs = 0;
        pInfo->ulMnPeriodJiffs += MSTP_TJ_MAX_NO_TOKEN; // 500 msec
        pInfo->iMnState = MSTP_MNST_IDLE;
        break;
    case MSTP_MNST_LO_TEST_RESP:
        pInfo->procfs.nTotalTestRespOut++;
        pInfo->procfs.nNoDataFramesToPort++;
        // If NO loopback, accumulate (rather than replace) timeouts:
        if (pInfo->nLoopback)
            pInfo->ulMnPeriodJiffs = 0;
        pInfo->ulMnPeriodJiffs += MSTP_TJ_MAX_NO_TOKEN; // 500 msec
        pInfo->iMnState = MSTP_MNST_IDLE;
        break;
    default:
        TRACE_PEI("mn_recv_valid_frm: MSTP_MNST_LO_XXX: Rcvd frame in "
                  "unknown LO_XXX: %i.", pInfo->iMnState);
        reset_info(pInfo);
        return -MSTP_RTN_RESET_LDISC;   // indicate "reset"
    }
    return 0;                   // indicate "handled"
}

int _handle_valid_frame_in_IDLE(struct mstp_info *pInfo)
{
    struct mstp_frame *pRcvdFrm =
        (struct mstp_frame *) (pInfo->pucInputBuf);
    unsigned short usDataLen = 0;

    if (pRcvdFrm->ucFrameType == MSTP_FT_TOKEN) {   // It's a token. Maybe not for us, but update node table anyway:
        update_nodes(pInfo, pRcvdFrm->ucSrcAddr, pRcvdFrm->ucDstAddr);
        pInfo->nSoleMaster = 0; // definitely NOT SoleMaster (anymore)
    }
    if (pRcvdFrm->ucDstAddr != pInfo->ucTS && (pRcvdFrm->ucDstAddr != MSTP_BCAST_ADDR || pRcvdFrm->ucFrameType == MSTP_FT_TOKEN || pRcvdFrm->ucFrameType == MSTP_FT_TEST_REQ)) {    // ReceivedUnwantedFrame: Not directly to us, and not an allowed bcast:
        pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // reset timeout value
        return 0;               // state already set to IDLE
    }
    switch (pRcvdFrm->ucFrameType) {
    case MSTP_FT_TOKEN:        // ReceivedToken:
        TRACE_PSI("RT");
        pInfo->procfs.nTotalTokensRecvd++;
        pInfo->nXmtFrameCount = 0;
        pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
        pInfo->iMnState = MSTP_MNST_XMT_DLY_TKN;
        // If addr change is waiting, do it now:
        if (pInfo->ucReqdTS != pInfo->ucTS)
            change_addr(pInfo);
        break;
    case MSTP_FT_PFM:          // ReceivedPFM:
        TRACE_LI("RP");
        pInfo->procfs.nTotalPfmsRecvd++;
        _format_tx_frame(pInfo, MSTP_FT_PFM_REPLY, pRcvdFrm->ucSrcAddr, 0,
                         NULL);
        pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
        pInfo->iMnState = MSTP_MNST_XMT_DLY_PFM_REPLY;
        break;
    case MSTP_FT_DATA_REPLY:
        _post_data_to_client(pInfo);    // Data NPDU contained in pucInputBuf
        if (pRcvdFrm->ucDstAddr != MSTP_BCAST_ADDR) {   // ReceivedDataNeedingReply:
            _format_tx_frame(pInfo, MSTP_FT_REPLY_POSTPONED,
                             pRcvdFrm->ucSrcAddr, 0, NULL);
            pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
            pInfo->iMnState = MSTP_MNST_XMT_DLY_REPLY_POST;
        } else {                //  BroadcastDataNeedingReply:
            pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // 500 msec
            pInfo->iMnState = MSTP_MNST_IDLE;
        }
        break;
    case MSTP_FT_TEST_REQ:     // TestRequest:
        // Send data right back at 'em:
        usDataLen = (pRcvdFrm->ucDataLen1 << 8) + pRcvdFrm->ucDataLen0;
        _format_tx_frame(pInfo, MSTP_FT_TEST_RESP, pRcvdFrm->ucSrcAddr,
                         usDataLen, pInfo->pucInputBuf);
        pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
        pInfo->iMnState = MSTP_MNST_XMT_DLY_TEST_RESP;
        break;
    case MSTP_FT_TEST_RESP:    // TestResponse:
    case MSTP_FT_DATA_NO_REPLY:    // DataNoReply:
        // Data NPDU is contained in pucInputBuf:
        _post_data_to_client(pInfo);
        break;                  // state already set to IDLE, timeout already set to NO_TOKEN
    default:                   // ReceivedUnwantedFrame. Note but otherwise ignore:
        TRACE_PEI("mn_recv_valid_frm: MSTP_MNST_IDLE: Unknown FrameType "
                  "rcvd: 0x%02x.", pRcvdFrm->ucFrameType);
        break;                  // state already set to IDLE, timeout already set to NO_TOKEN
    }
    return 0;
}

int _handle_failed_PFM(struct mstp_info *pInfo)
{
    pInfo->ulMnPeriodJiffs = 0; // we were waiting for PFM_REPLY; didn't get it
    if (pInfo->nSoleMaster == 1) {  // SoleMaster:
        pInfo->nXmtFrameCount = 0;
        return _use_token(pInfo);
    } else if (pInfo->ucNS != pInfo->ucTS) {    // DoneWithPFM:
        pInfo->nEventCount = 0;
        pInfo->nRetryCount = 0;
        return _pass_token(pInfo);
    } else if (MSTP_MASTER_WRAP(pInfo->ucPS + 1) != pInfo->ucTS) {  // SendNextPFM:
        pInfo->ucPS = MSTP_MASTER_WRAP(pInfo->ucPS + 1);
        pInfo->nRetryCount = 0;
        return _send_PFM(pInfo);
    } else {                    // DeclareSoleMaster:
        pInfo->procfs.nDeclareSoleMaster++;
        pInfo->nSoleMaster = 1;
        pInfo->nXmtFrameCount = 0;
        return _use_token(pInfo);
    }
    return 0;
}

int mn_recv_event(struct mstp_info *pInfo, const unsigned char ucEvt,
                  int iErr)
{
    int iMnState = pInfo->iMnState;
    unsigned long ulTmp = 0;

    pInfo->nLocalEvtCnt++;
    if (iMnState >= MSTP_MNST_XMT_DLY_1ST && iMnState <= MSTP_MNST_XMT_DLY_LAST && ucEvt != 0xFF)   // allow filler byte
    {                           // BAAAAD Error: rcvd a byte or error while holding token and delaying
        // a xmssn:
        TRACE_PEI
            ("mn_recv_event: MSTP_MNST_XMT_DLY_XXX: Rcvd byte or error"
             " event (0x%02x) while delaying a reply xmssn. State = %i.",
             ucEvt, iMnState);
        pInfo->procfs.nDelayUnwantedEvts++;
        reset_info(pInfo);
        return -MSTP_RTN_RESET_LDISC;
    } else if (iMnState >= MSTP_MNST_LO_1ST
               && iMnState <= MSTP_MNST_LO_LAST) {
        if (pInfo->procfs.ulStartWrite != 0) {
            ulTmp = jiffies - pInfo->procfs.ulStartWrite;
            if (ulTmp > pInfo->procfs.ulEchoDelay)
                pInfo->procfs.ulEchoDelay = ulTmp;
            pInfo->procfs.ulStartWrite = 0;
        }
    }
    switch (iMnState) {
    case MSTP_MNST_PASS_TOKEN:
    case MSTP_MNST_NO_TOKEN:
        if (pInfo->nEventCount > MSTP_N_MIN_OCTETS_ACTIVE)
            pInfo->iMnState = MSTP_MNST_IDLE;   // continue timeout in IDLE
        break;
    default:
        break;
    }
    return 0;
}

int mn_recv_valid_frm(struct mstp_info *pInfo)
{
    int iMnState = pInfo->iMnState, iRtn = 1;
    struct mstp_frame *pRcvdFrm =
        (struct mstp_frame *) (pInfo->pucInputBuf);
    struct mstp_frame_entry *pSentFrmEntry = pInfo->pSendFrame;
    unsigned int nIndex = pInfo->nIndex;

    if (iMnState >= MSTP_MNST_LO_1ST && iMnState <= MSTP_MNST_LO_LAST) {    // Verify that the rcvd frame is identical to the last frame sent:
        if (pSentFrmEntry->nLen != (nIndex + 2) // 1st 2 bytes sent are preambles
            || memcmp(pSentFrmEntry->pucFrame + 2, pRcvdFrm, nIndex) != 0) {    // Rcvd valid frame while in LO_XXX state, but frame did not
            // match last frame sent. Likely hardware error, so reset ldisc:
            TRACE_PEI
                ("mn_recv_valid_frm: MSTP_MNST_XMT_LO_XXX: Rcvd valid "
                 "frame, but not same as last sent. From 0x%02x. Type 0x%02x"
                 ".", pRcvdFrm->ucSrcAddr, pRcvdFrm->ucFrameType);
            pInfo->procfs.nInvalidEchoes++;
            // Xns: 17, 20, 23, 33, 36, 46, 47, 56
            reset_info(pInfo);
            return -MSTP_RTN_RESET_LDISC;   // indicate "reset_info"
        }
        iRtn = _handle_valid_frame_in_LO_XXX(pInfo);
    }
    if (iRtn <= 0) {
        return iRtn;            // <0: reset_info, =0: handled event
    }
    switch (iMnState) {
    case MSTP_MNST_IDLE:       // waiting for recvd reply-needed frame, recvd token, or lost token:
        return _handle_valid_frame_in_IDLE(pInfo);
    case MSTP_MNST_WAIT_REPLY:
        if (pRcvdFrm->ucDstAddr == pInfo->ucTS) {
            switch (pRcvdFrm->ucFrameType) {
            case MSTP_FT_TEST_RESP:    // ReceivedReply:
                pInfo->procfs.nTestRespsRecvd++;
            case MSTP_FT_DATA_NO_REPLY:    // ReceivedReply:
                _post_data_to_client(pInfo);    // Data NPDU is contained in pucInputBuf
            case MSTP_FT_REPLY_POSTPONED:  // ReceivedPostpone:
                pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
                pInfo->iMnState = MSTP_MNST_XMT_DLY_TKN;
                break;
            default:           // ReceivedUnexpectedFrame:
                TRACE_PEI("mn_recv_valid_frm: MSTP_MNST_WAIT_REPLY: "
                          "Rcvd reply with bad FrameType: 0x%02x.",
                          pRcvdFrm->ucFrameType);
                pInfo->procfs.nWaitReplyUnexpectedFrame++;
                pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;
                pInfo->iMnState = MSTP_MNST_IDLE;
                break;
            }
        } else {                // ReceivedUnexpectedFrame:
            TRACE_PEI("mn_recv_valid_frm: MSTP_MNST_WAIT_REPLY: Rcvd "
                      "frame for 0x%02x, not us.", pRcvdFrm->ucDstAddr);
            pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // 500 msec
            pInfo->iMnState = MSTP_MNST_IDLE;
        }
        break;
    case MSTP_MNST_PFM:
        if ((pRcvdFrm->ucDstAddr == pInfo->ucTS)    // if it's for us...
            && (pRcvdFrm->ucFrameType == MSTP_FT_PFM_REPLY)) {  // ReceivedReplyToPFM:
            pInfo->nSoleMaster = 0; // the reply means that we CANNOT be the SoleMaster anymore
            pInfo->ucNS = pRcvdFrm->ucSrcAddr;
            pInfo->nEventCount = 0;
            pInfo->ucPS = pInfo->ucTS;
            pInfo->nPfmTokenCount = 0;
            pInfo->nRetryCount = 0;
            TRACE_LI("NS = %02x", pInfo->ucNS);
            // Force token pass after delay:
            pInfo->nXmtFrameCount = pInfo->nXmtFrameCountMax;
            pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
            pInfo->iMnState = MSTP_MNST_XMT_DLY_TKN;
        } else                  // ReceivedUnexpectedFrame:
        {
            TRACE_PEI("mn_recv_valid_frm: MSTP_MNST_PFM: Rcvd "
                      "frame for 0x%02x (we are 0x%02x).\n FrameType 0x%02x"
                      " (expecting 0x%02x).", pRcvdFrm->ucDstAddr,
                      pInfo->ucTS, pRcvdFrm->ucFrameType,
                      MSTP_FT_PFM_REPLY);
            pInfo->procfs.nPfmUnexpectedFrame++;
            pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // 500 msec
            pInfo->iMnState = MSTP_MNST_IDLE;
        }
        break;
    default:
        TRACE_PEI("mn_recv_valid_frm: Current MN State unknown or can't "
                  "handle EvtValidFrame: %i.", pInfo->iMnState);
        pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // 500 msec
        pInfo->iMnState = MSTP_MNST_IDLE;
        break;
    }
    return 0;
}

int mn_recv_invalid_frm(struct mstp_info *pInfo)
{
    int iMnState = pInfo->iMnState;

    pInfo->procfs.nInvalidFrame++;
    if (iMnState >= MSTP_MNST_LO_1ST && iMnState <= MSTP_MNST_LO_LAST) {
        pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // 500 msec
        pInfo->iMnState = MSTP_MNST_IDLE;
        return 0;
    }
    switch (iMnState) {
    case MSTP_MNST_IDLE:       // ReceivedInvalidFrame:
        pInfo->procfs.nIdleInvalidFrame++;
        break;
    case MSTP_MNST_WAIT_REPLY: // InvalidFrame:
        pInfo->procfs.nWaitReplyInvalidFrame++;
        // Need to delay because we just finished receiving an invalid
        // frame. However, there is no guarantee that the device that sent
        // the invalid frame will not continue to send invalid bytes while
        // we wait for it to stop talking. In this case, the ldisc's FSAs
        // will reset themselves and wait for an opportunity to fix the
        // MSTP bus token pass:
        pInfo->ulMnPeriodJiffs = pInfo->ulReplyDelay;
        pInfo->iMnState = MSTP_MNST_XMT_DLY_TKN;
        break;
    case MSTP_MNST_PFM:
        return _handle_failed_PFM(pInfo);
    default:
        TRACE_PEI("mn_recv_invalid_frm: Current MN State unknown or "
                  "can't handle EvtInvalidFrame: %i.", pInfo->iMnState);
        pInfo->ulMnPeriodJiffs = MSTP_TJ_MAX_NO_TOKEN;  // 500 msec
        pInfo->iMnState = MSTP_MNST_IDLE;
        break;
    }
    return 0;
}

// Process hardware EvtTimeout:
int mn_timeout(struct mstp_info *pInfo)
{
    int iMnState = pInfo->iMnState;
    TRACE_K1("mn_to: state = %i", iMnState);
    switch (iMnState) {
    case MSTP_MNST_XMT_DLY_TKN:
        return _use_token(pInfo);
    case MSTP_MNST_XMT_DLY_PFM_REPLY:
        pInfo->iMnState = MSTP_MNST_LO_PFM_REPLY;
        return _send_frame(pInfo);
    case MSTP_MNST_XMT_DLY_REPLY_POST:
        pInfo->iMnState = MSTP_MNST_LO_REPLY_POST;
        return _send_frame(pInfo);
    case MSTP_MNST_XMT_DLY_TEST_RESP:
        pInfo->iMnState = MSTP_MNST_LO_TEST_RESP;
        return _send_frame(pInfo);
    case MSTP_MNST_LO_TKN:
    case MSTP_MNST_LO_DATA:
    case MSTP_MNST_LO_NEED_REPLY:
    case MSTP_MNST_LO_PFM:
    case MSTP_MNST_LO_PFM_REPLY:
    case MSTP_MNST_LO_REPLY_POST:
    case MSTP_MNST_LO_TEST_RESP:
        pInfo->procfs.nEchoTimeout++;
        TRACE_PEI("mn_timeout: Echo-chkg failed in state %i. "
                  "nLocalEvtCnt = %u.", iMnState, pInfo->nLocalEvtCnt);
        reset_info(pInfo);      // echo chkg failed
        return -MSTP_RTN_RESET_LDISC;
    case MSTP_MNST_IDLE:       // LostToken:
        pInfo->procfs.nLostToken++;
        pInfo->ulMnPeriodJiffs = (MSTP_TJ_SLOT * pInfo->ucTS);
        pInfo->iMnState = MSTP_MNST_NO_TOKEN;
        return 0;
    case MSTP_MNST_WAIT_REPLY:
        pInfo->procfs.nWaitReplyTimeout++;
        pInfo->nXmtFrameCount = pInfo->nXmtFrameCountMax;
        return _use_token(pInfo);
    case MSTP_MNST_PASS_TOKEN:
        TRACE_PEI("MTO_PT:%lu", pInfo->ulMnPeriodJiffs);
        if (++(pInfo->nRetryCount) > MSTP_N_RETRY_TOKEN) {  // FindNewSuccessor:
            pInfo->procfs.nFindNewSuccessor++;
            return _find_next(pInfo);
        }
        // RetrySendToken:
        pInfo->procfs.nRetrySendToken++;
        pInfo->iMnState = MSTP_MNST_LO_TKN;
        return _send_frame(pInfo);  // resends last frame sent (token)
    case MSTP_MNST_PFM:
        return _handle_failed_PFM(pInfo);
    case MSTP_MNST_NO_TOKEN:   // GenerateToken:
        return _find_next(pInfo);
    default:
        TRACE_PEI("mn_timeout: ERR: Got timeout in MNFSA state %i.",
                  pInfo->iMnState);
        reset_info(pInfo);
        return -MSTP_RTN_RESET_LDISC;
    }
    return 0;
}

