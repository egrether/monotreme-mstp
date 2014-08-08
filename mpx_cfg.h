// mpx_cfg.h: Config variables for MPX.

#ifndef __LINUX_MPX_CFG_H__
#define __LINUX_MPX_CFG_H__

// Declare a global module parameter for Mediator type. May be specified by caller of insmod n_mstp:
extern char *MPX_TYPE;

// Declare an array to hold all of the possible config structs:
extern struct mpx_cfg *mpx_cfgs[5];

// Declare a global ptr to a struct containing config for this Mediator:
extern struct mpx_cfg *this_mpx_cfg;    // set by XXX_init() of ldisc

#endif                          // __LINUX_MPX_CFG_H__
