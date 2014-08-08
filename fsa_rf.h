// fsa.h

#ifndef __FSA_RF_H__
#define __FSA_RF_H__

// Called by mstp_open:
void add_SilenceTimer(struct mstp_info *pInfo);
// Used in mstp_open to init timer:
void rf_timeout(unsigned long data);
void timeout_wq_fn(struct work_struct *work);
// Called by mstp_receive_buf:
int put_event(struct port_cfg *pPortCfg, unsigned int nEvt);
int process_events(struct port_cfg *pPortCfg);

#endif                          // __FSA_RF_H__
