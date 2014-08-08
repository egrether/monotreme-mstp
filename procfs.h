// procfs.h

#ifndef __PROCFS_H__
#define __PROCFS_H__

int mod_params_show(struct seq_file *m, void *v);
int nodes_show(struct seq_file *m, void *v);
int stats_show(struct seq_file *m, void *v);
int addr_show(struct seq_file *m, void *v);
int reply_delay_show(struct seq_file *m, void *v);
int max_frame_cnt_show(struct seq_file *m, void *v);
int loopback_show(struct seq_file *m, void *v);
int log_enabled_show(struct seq_file *m, void *v);
int genl_log_enabled_show(struct seq_file *m, void *v);
 
int read_mod_params(char *page, char **start, off_t off, int count,
                    int *eof, void *data);

int read_stats(char *page, char **start, off_t off, int count, int *eof,
               void *data);
int clear_stats(struct port_cfg *pPortCfg);
int set_stats(struct file *fp, const char *buf, unsigned long count,
              void *data);

int read_nodes(char *page, char **start, off_t off, int count, int *eof,
               void *data);
int set_nodes(struct file *fp, const char *buf, unsigned long count,
              void *data);

int read_addr(char *page, char **start, off_t off, int count, int *eof,
              void *data);
int set_addr(struct file *fp, const char *buf, unsigned long count,
             void *data);

int read_reply_delay(char *page, char **start, off_t off, int count,
                     int *eof, void *data);
int set_reply_delay(struct file *fp, const char *buf, unsigned long count,
                    void *data);

int read_max_frame_cnt(char *page, char **start, off_t off, int count,
                       int *eof, void *data);
int set_max_frame_cnt(struct file *fp, const char *buf,
                      unsigned long count, void *data);

int read_loopback(char *page, char **start, off_t off, int count, int *eof,
                  void *data);
int set_loopback(struct file *fp, const char *buf, unsigned long count,
                 void *data);

int read_log_enabled(char *page, char **start, off_t off, int count,
                     int *eof, void *data);
int set_log_enabled(struct file *fp, const char *buf, unsigned long count,
                    void *data);

int read_genl_log_enabled(char *page, char **start, off_t off, int count,
                          int *eof, void *data);
int set_genl_log_enabled(struct file *fp, const char *buf,
                         unsigned long count, void *data);

#endif                          // __PROCFS_H__
