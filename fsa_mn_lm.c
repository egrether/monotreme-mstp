// fsa_recv.c

#include "super_hdr.h"
#include "procfs.h"
#include "n_mstp.h"
#include "util.h"
#include "fsa_rf.h"
#include "fsa_mn.h"

void post_data_to_client(struct mstp_info *pInfo)
{
    //@FIXME: add code...
}

// Process hardware EvtRecvByte and EvtRecvErr:
void recv_byte_mn(struct mstp_info *pInfo)
{
    struct mstp_pkt *pPkt = (struct mstp_pkt *) (pInfo->pucHdrBuf); // cookie cutter

    if (pInfo->nRecvdInvalFrame != 0) {
        pInfo->procfs.nIdleInvalidFrame++;
        pInfo->nRecvdInvalFrame = 0;
    } else if (pInfo->nRecvdValidFrame != 0) {
        post_data_to_client(pInfo); // DataNeeding Reply NPDU is contained in pucInputBuf
        if (pPkt->ucFrameType == MSTP_TOKEN) {
            update_nodes(pInfo, pPkt->ucSrcAddr, pPkt->ucDstAddr);
        }

        pInfo->nRecvdValidFrame = 0;
    }
}

void mstp_timeout_mn(struct mstp_info *pInfo)
{
}
