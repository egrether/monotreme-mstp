// util.c

#include "super_hdr.h"
#include <linux/prefetch.h>
#include "n_mstp.h"
#include "util.h"

unsigned short endian_swap_2(unsigned short us)
{
#ifdef __BIG_ENDIAN_OS__
    // From big-endian (eg PPC) to little-endian (eg Intel):
    return ((us >> 8) | (us << 8));
#else
    return us;                  // already little-endian
#endif
}

unsigned int endian_swap_4(unsigned int n)
{
#ifdef __BIG_ENDIAN_OS__
    // From big-endian (eg PPC) to little-endian (eg Intel):
    return ((n >> 24) | ((n << 8) & 0x00FF0000) | ((n >> 8) & 0x0000FF00) |
            (n << 24));
#else
    return n;                   // already little-endian
#endif
}

// dump_block(): Formats and "printk"s block of bytes as space-separated hex
// digit pairs, with 16 pairs per line:
void dump_block(const unsigned char *block, unsigned int length)
{
    unsigned int i, j;
    char linebuf[16 * 3 + 1];

    for (i = 0; i < length; i += 16) {
        for (j = 0; (j < 16) && (j + i < length); j++) {
            sprintf(linebuf + 3 * j, "%02x ", block[i + j]);
        }
        linebuf[3 * j] = '\0';
        printk("%s\n", linebuf);
    }
}

// mstp_hdr_crc():
unsigned char mstp_hdr_crc(unsigned char ucDataVal, unsigned char ucCrcVal)
{
    unsigned short usCrc = 0;

    usCrc = ucCrcVal ^ ucDataVal;
    usCrc =
        usCrc ^ (usCrc << 1) ^ (usCrc << 2) ^ (usCrc << 3) ^ (usCrc << 4)
        ^ (usCrc << 5) ^ (usCrc << 6) ^ (usCrc << 7);
    return (usCrc & 0xFE) ^ ((usCrc >> 8) & 1);
}

// mstp_data_crc():
unsigned short mstp_data_crc(unsigned char ucDataVal,
                             unsigned short usCrcVal)
{
    unsigned short usCrcLow = 0;

    usCrcLow = (usCrcVal & 0xFF) ^ ucDataVal;
    return (usCrcVal >> 8) ^ (usCrcLow << 8) ^ (usCrcLow << 3)
        ^ (usCrcLow << 12) ^ (usCrcLow >> 4) ^ (usCrcLow & 0x0F)
        ^ ((usCrcLow & 0x0F) << 7);
}

// mstp_hdr_crc_buf(): Apply mstp_hdr_crc() to each byte in given buffer:
unsigned char mstp_hdr_crc_buf(unsigned char *pBuf, unsigned int nLen)
{
    unsigned char ucCrc = 0xFF;
    unsigned int n = 0;

    for (n = 0; n < nLen; n++)
        ucCrc = mstp_hdr_crc(pBuf[n], ucCrc);

    return ~ucCrc;
}

// mstp_data_crc_buf(): Apply mstp_data_crc() to each byte in given buffer:
unsigned short mstp_data_crc_buf(unsigned char *pBuf, unsigned int nLen)
{
    unsigned short usCrc = 0xFFFF;
    unsigned int n = 0;

    for (n = 0; n < nLen; n++)
        usCrc = mstp_data_crc(pBuf[n], usCrc);
//#ifndef __BIG_ENDIAN_OS__
//  usCrc = (usCrc >> 8) | (usCrc << 8);
//#endif
    return ~usCrc;
}

// add_node_before(): Support function called ONLY by update_nodes() below.
// Allocates, inits, and adds a mstp_node_entry (with given addr) "before" the
// given pLst element. (Note that lists are circular.):
struct list_head *add_node_before(struct list_head *pLst,
                                  unsigned char ucAddr)
{
    struct mstp_node_entry *pNewNode = NULL;

    pNewNode = (struct mstp_node_entry *) kmalloc(sizeof(struct mstp_node_entry), GFP_ATOMIC);  // prevent sleeping: use ONLY GFP_ATOMIC flag
    if (pNewNode == NULL) {
        printk(KERN_ERR
               "mstp: failed to kmalloc an mstp_node_entry struct!\n");
        return NULL;            // big trouble now, boy...
    }

    memset(pNewNode, 0, sizeof(struct mstp_node_entry));
    INIT_LIST_HEAD(&pNewNode->list);
    pNewNode->node_desc.ucAddr = ucAddr;

    list_add_tail(&pNewNode->list, pLst);   // inserts pNewNode->list before pLst
    return &pNewNode->list;
}

void remove_node_at(struct mstp_info *pInfo, struct list_head **ppCurElem)
{
    struct list_head *pCurElem = *ppCurElem, *pTmpElem = NULL;
    struct mstp_node_entry *pCurNode = NULL;

    pTmpElem = pCurElem->next;
    pCurNode = list_entry(pCurElem, struct mstp_node_entry, list);
    list_del(pCurElem);
    kfree(pCurNode);
    *ppCurElem = pTmpElem;
}

struct list_head *insert_dst_btwn(struct mstp_info *pInfo,
                                  unsigned char ucAddr,
                                  struct list_head *pStartElem,
                                  struct list_head *pEndElem)
{
    struct list_head *pCurElem = pStartElem->next, *pInsElem = NULL;
    struct mstp_node_entry *pCurNode = NULL;

    while (1) {
        if (pCurElem == pEndElem) { // Reached end of search region. Create/insert new entry:
            pInsElem = add_node_before(pEndElem, ucAddr);
            break;
        }
        pCurNode = list_entry(pCurElem, struct mstp_node_entry, list);
        if (ucAddr == pCurNode->node_desc.ucAddr) { // Found existing matching entry:
            pInsElem = pCurElem;
            break;
        }
        if (ucAddr < pCurNode->node_desc.ucAddr) {  // Reached proper insertion point. Create/insert new entry:
            pInsElem = add_node_before(pCurElem, ucAddr);
            break;
        }
        // Else, we found a node that must be removed from list:
        remove_node_at(pInfo, &pCurElem);   // moves pCurElem to next in list
    }
    return pInsElem;
}

// update_nodes(): Outside of this function, node_list can NEVER have EXACTLY 1
// entry. Entries are added/updated 2 at a time, so node_list can have 0, 2, or
// more entries at any given time:
void update_nodes(struct mstp_info *pInfo, unsigned char ucSrcAddr,
                  unsigned char ucDstAddr)
{
    struct mstp_node_entry *pCurNode = NULL;
    struct list_head *pCurElem = NULL;
    struct list_head *pSrcElem = NULL, *pDstElem = NULL;
    struct timeval tmCur;
    int iTvSize = sizeof(struct timeval);

    pInfo->procfs.nTotalTokensSeen++;
    // If params are invalid:
    if (ucSrcAddr == ucDstAddr)
        return;

    if (list_empty(&pInfo->node_list) != 0) {   // List is currently empty, so add both src and dst nodes:
        pSrcElem = add_node_before(&pInfo->node_list, ucSrcAddr);
        pDstElem = add_node_before(((ucDstAddr > ucSrcAddr) ?
                                    &pInfo->node_list : pSrcElem),
                                   ucDstAddr);
    } else {                    // At least one (and should be at least 2) data elem(s) in list:
        pCurElem = pInfo->node_list.next;
        while (1) {             // Walk list from head to find or create/insert pSrcElem:
            pCurNode = list_entry(pCurElem, struct mstp_node_entry, list);
            if (ucSrcAddr == pCurNode->node_desc.ucAddr) {  // Found existing matching entry:
                pSrcElem = pCurElem;
                break;
            }
            if ((ucSrcAddr < pCurNode->node_desc.ucAddr)
                || ((pCurElem = pCurElem->next) == &pInfo->node_list)) {    // Create/insert new entry:
                pSrcElem = add_node_before(pCurElem, ucSrcAddr);
                break;
            }
        }
        // Now that we have pSrcElem in list, find/insert pDstElem, and remove
        // all elements from after pSrcElem to before pDstElem, excluding head:
        if (ucSrcAddr > ucDstAddr) {    // pSrcElem -> pDstElem wraps through list head:
            pCurElem = pSrcElem->next;
            while (pCurElem != &pInfo->node_list) { // Rmv all nodes between pSrcElem and head:
                remove_node_at(pInfo, &pCurElem);
            }
            // Find or create/insert pDstElem, and remove all other nodes
            // between head and pDstElem's proper position:
            pDstElem = insert_dst_btwn(pInfo, ucDstAddr, &pInfo->node_list,
                                       pSrcElem);
        } else {                // Find or create/insert pDstElem between pSrcElem and end of list,
            // and remove all other nodes between them:
            pDstElem = insert_dst_btwn(pInfo, ucDstAddr, pSrcElem,
                                       &pInfo->node_list);
        }
    }
    if ((pSrcElem == NULL) || (pDstElem == NULL)) { // Memory or coding problem occurred:
        TRACE_PEI("NULL node entry pointer!");
        return;
    }
    // Set transition times. Src just passed tkn, and dst just rcvd tkn:
    do_gettimeofday(&tmCur);
    pCurNode = list_entry(pSrcElem, struct mstp_node_entry, list);
    memcpy(&pCurNode->node_desc.tmEndTokenHold, &tmCur, iTvSize);
    pCurNode = list_entry(pDstElem, struct mstp_node_entry, list);
    memcpy(&pCurNode->node_desc.tmStartTokenHold, &tmCur, iTvSize);
}

// capture_node_list(): Capture node info from working list into array for
// non-invasive perusal:
int capture_node_list(struct mstp_info *pInfo)
{
    int i = 0;
    struct list_head *pCurElem = NULL;
    struct mstp_node_desc *pND = NULL;
    int iDescSize = sizeof(struct mstp_node_desc);

    list_for_each(pCurElem, &pInfo->node_list) {
        pND =
            &list_entry(pCurElem, struct mstp_node_entry, list)->node_desc;
        memcpy(&(pInfo->procfs.node_array[i]), pND, iDescSize);
        if ((++i) > 255) {      // Something is horribly wrong: > 255 nodes, with a space of 255
            // addrs, and only 127 of those can be masters...
            TRACE_PEI("Node list contains > 255 entries: Not allowed.");
            reset_info(pInfo);
            return 0;
        }
    }
    return i;
}

// read_rxq_frame():
struct mstp_npdu *read_rxq_frame(struct mstp_info *pInfo)
{
    struct mstp_npdu *pNpdu = NULL;

    if (pInfo->nRxqRdIdx != pInfo->nRxqWrIdx)   // if there is >= 1 pkt in rxq:
    {
        pNpdu = &(pInfo->rxq[pInfo->nRxqRdIdx]);
        pInfo->nRxqRdIdx = (pInfo->nRxqRdIdx + 1) % MSTP_RXQ_LEN;
        if (pInfo->nRxqRdIdx == pInfo->nRxqWrIdx) {
            atomic_set(&pInfo->rxq_not_empty, 0);
        }
    }

    return pNpdu;
}

// submit_addr_change(): Submit given addr as pot'l replacement for cur addr:
int submit_addr_change(struct mstp_info *pInfo, unsigned char ucReqdTS)
{
    int iRslt = 0, iNumNodes = 0, i = 0;
    struct mstp_node_desc *pND = NULL;

    // No change necy if reqd addr is same as current.
    if (ucReqdTS == pInfo->ucTS) {
        goto same_addr;
    }
    // No change allowed if reqd addr is same as another node on net:
    iNumNodes = capture_node_list(pInfo);
    for (i = 0; i < iNumNodes; i++) {
        pND = &(pInfo->procfs.node_array[i]);
        if (pND->ucAddr == ucReqdTS) {
            iRslt = -EINVAL;    // no change allowed
            goto same_addr;
        } else if (pND->ucAddr < ucReqdTS)
            break;
    }

    // Post a request to implement change at such time as:
    // (1) We are not currently participating in a token-pass, OR
    // (2) We rcv token.
    pInfo->ucReqdTS = ucReqdTS; // prep for change

    // If we we have not yet joined the token-pass seq, do change now:
    if ((pInfo->ucTS == pInfo->ucNS)) {
        change_addr(pInfo);     // do change
    }
//bad_addr:
  same_addr:
    return iRslt;
}

// change_addr(): Change addr, prep for discovery (active and passive):
void change_addr(struct mstp_info *pInfo)
{
    pInfo->ucTS = pInfo->ucReqdTS;  // do change, and also show change is done
    pInfo->ucNS = pInfo->ucTS;
    pInfo->ucPS = pInfo->ucTS;
}

// Update max Tx Q capacity used ("high-water mark"). Rtns current nTxQUsed:
unsigned int update_txq_max_used(struct mstp_info *pInfo)
{
    int iTmp = 0;
    unsigned int nTmp = 0, nTxQUsed = 0;

    iTmp = (int) (pInfo->nTxqWrIdx) - (int) (pInfo->nTxqRdIdx);
    nTmp = (iTmp < 0 ? MSTP_TXQ_LEN + iTmp : (unsigned int) iTmp);
    nTxQUsed = (nTmp * 100) / MSTP_TXQ_LEN;
    if ((nTxQUsed == 0) && (atomic_read(&pInfo->txq_not_full) == 0))
        nTxQUsed = 100;
    if (nTxQUsed > pInfo->procfs.nMaxTxQUsed)
        pInfo->procfs.nMaxTxQUsed = nTxQUsed;
    return nTxQUsed;
}


// These utility functions MAY be useful when ldisc runs on CPU with an accurate
// short-period timer (ie at least a Pentium-class machine, NOT ZFx86). Note
// that ZFx86 does not have a time-stamp counter register, and subsequent calls
// to gettimeofday() yield DECREASED values 1 time in 10 (though the problem is
// more systematic than probabilistic):
/*
static void subtract_tv(struct timeval* pTm0, struct timeval* pTm1,
		struct timeval* pTmOut)
{
	pTmOut->tv_usec = pTm0->tv_usec - pTm1->tv_usec;
	pTmOut->tv_sec =  pTm0->tv_sec - pTm1->tv_sec;

	if(pTmOut->tv_usec < 0)
	{
		pTmOut->tv_sec--;
		pTmOut->tv_usec = -pTmOut->tv_usec;
	}
}


static int cmp_tv(struct timeval* pTm0, struct timeval* pTm1)
{
	if(pTm0->tv_sec < pTm1->tv_sec)
		return -1;
	if(pTm0->tv_sec > pTm1->tv_sec)
		return 1;

	if(pTm0->tv_sec < pTm1->tv_sec)
		return -1;
	if(pTm0->tv_sec > pTm1->tv_sec)
		return 1;

	return 0;
}

static void add_tv(struct timeval* pTm0, struct timeval* pTm1, struct timeval* pTmOut)
{
	pTmOut->tv_usec = pTm0->tv_usec + pTm1->tv_usec;
	pTmOut->tv_sec =  pTm0->tv_sec + pTm1->tv_sec;

	if(pTmOut->tv_usec >= 1000000)
	{
		pTmOut->tv_sec++;
		pTmOut->tv_usec %= 1000000;
	}
}

static void shift_tv(struct timeval* pTm0, int iShifts, struct timeval* pTmOut)
{
	int iCarry = 0, i = 0, iEnd = 0;

	memcpy(pTmOut, pTm0, sizeof(struct timeval));

	if(iShifts < 0) // if shift is to right:
	{
		for(i = 0, iEnd = -iShifts; i < iEnd; i++)
		{
			if(pTmOut->tv_sec & 1)
				iCarry = 1;
			pTmOut->tv_sec >>= 1;
			pTmOut->tv_usec >>= 1;
			if(iCarry)
				pTmOut->tv_usec += 500000; // given shift above, cannot yield more than 999998 usec
		}
	}
	else // else, shift is to left:
	{
		//@fixme: Not needed yet...
	}
}
*/

