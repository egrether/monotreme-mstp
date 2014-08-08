// fsa.h

#ifndef __FSA_MN_H__
#define __FSA_MN_H__

int mn_recv_event(struct mstp_info *pInfo, const unsigned char ucEvt,
                  int iErr);

int mn_recv_valid_frm(struct mstp_info *pInfo);

int mn_recv_invalid_frm(struct mstp_info *pInfo);

int mn_timeout(struct mstp_info *pInfo);


#endif                          // __FSA_MN_H__
