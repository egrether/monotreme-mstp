// util.h

#ifndef __UTIL_H__
#define __UTIL_H__

#define __BIG_ENDIAN_OS__       // comment out for Intel Linux; leave active for PPC Linux

unsigned short endian_swap_2(unsigned short us);
unsigned int endian_swap_4(unsigned int n);

// dump_block(): Formats and "printk"s block of bytes as space-separated hex
// digit pairs, with 16 pairs per line:
void dump_block(const unsigned char *block, unsigned int length);

// mstp_hdr_crc():
unsigned char mstp_hdr_crc(unsigned char ucDataVal,
                           unsigned char ucCrcVal);

// mstp_data_crc():
unsigned short mstp_data_crc(unsigned char ucDataVal,
                             unsigned short usCrcVal);

// mstp_hdr_crc_buf(): Apply mstp_hdr_crc() to each byte in given buffer:
unsigned char mstp_hdr_crc_buf(unsigned char *pBuf, unsigned int nLen);

// mstp_data_crc_buf(): Apply mstp_hdr_crc() to each byte in given buffer:
unsigned short mstp_data_crc_buf(unsigned char *pBuf, unsigned int nLen);

// add_node_entry(): Creates node_entry with given addr, and adds it to
// pInfo's node_list. If entry with addr already exists, does nothing. Returns
// ptr to new/existing node_entry:
void update_nodes(struct mstp_info *pInfo, unsigned char ucSrcAddr,
                  unsigned char ucDstAddr);

// capture_node_list(): captures node data from working list to static array.
// Called by read_nodes() for /procfs and by mstp_ioctl() to respond to
// query by client.
int capture_node_list(struct mstp_info *pInfo);

// parse_npdu():
//int parse_npdu(struct mstp_info *pInfo, unsigned char *pucFrame);

// read_rxq_frame():
struct mstp_npdu *read_rxq_frame(struct mstp_info *pInfo);

// submit_addr_change(): Submit given addr as potential replacemt for current addr:
int submit_addr_change(struct mstp_info *pInfo, unsigned char ucReqdTS);

// change_addr(): Change addr, prep for discovery (active and passive):
void change_addr(struct mstp_info *pInfo);

// Update max Tx Q capacity used ("high-water mark"). Rtns current nTxQUsed:
unsigned int update_txq_max_used(struct mstp_info *pInfo);

// struct timeval manipulators could be useful on a CPU with accurate
// short-tick timers, but not on ZFx86:
/*
static void subtract_tv(struct timeval* pTm0, struct timeval* pTm1, struct timeval* pTmOut);
static int cmp_tv(struct timeval* pTm0, struct timeval* pTm1);
static void add_tv(struct timeval* pTm0, struct timeval* pTm1, struct timeval* pTmOut);
static void shift_tv(struct timeval* pTm0, int iShifts, struct timeval* pTmOut);
*/

#endif                          // __UTIL_H__
