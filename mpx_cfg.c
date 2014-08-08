// mpx_cfg.c: Config variables for MPX.

#include "super_hdr.h"
#include "n_mstp.h"
#include "mpx_cfg.h"

// Global Module Parameter for Mediator Type: May be specified by caller of
// "insmod n_mstp MPX_TYPE=<type_string>":
char *MPX_TYPE = "5000";
module_param(MPX_TYPE, charp, S_IRUGO);

// SOME EXPLANATIONS ABOUT IRQ ASSIGNMENTS:
// Note that in all port_cfg instances below, all of the com ports for a given
// device share the same IRQ line. Reason: They use a standalone UART chip that
// communicates with the CPU (or co-CPU) via PCIe (which is a high-speed serial
// bus). Although PCIe offers the option of inband (ie message-based) "IRQs",
// none of the hardware is currently configured for that. Instead, the hardware
// uses a single PCI interrupt line (A, B, C, or D) for all interrupts generated
// by the UART when it detects events (eg byte arrives at any port, transmit
// buf for any port empty, error detected on a port, etc.). This situation means
// that the kernel calls _all_ tty IH instances sharing a given IRQ, with the
// ID of the device that pulled down the IRQ line. The tty IH instances ignore
// calls that do not include their device IDs, such that only one instance of
// "mstp_receive_buf()" is called by the tty that saw its ID in the call from
// the kernel. However, any calls to "spin_lock_irqsave()" in the ldisc DO
// disable ALL IRQs on the CPU (ie not just the shared IRQ for the ttys).

// PORT_CFG_INIT:
// This macro cannot init mutex (2.6) or spinlock (" error: initializer
// element is not constant"). So, call mutex_init() (2.6) in mstp_init():
#define PORT_CFG_INIT(J, N, I, P) \
	{	.port_dev = MKDEV( (J) , (N) ) , \
		.nIRQ = (I) , \
		.szPortName = "com" #P , \
		.ulFlags = 0, \
		.iLogEnabled = 0, \
		.pnRawEvts = NULL, \
		.pnRawEvtsOut = NULL, \
		.iRawEvtsWr = 0, \
		.iRawEvtsRd = 0, \
		.pInfo = NULL }

struct port_cfg port_cfg_array_monotreme[] = {
    PORT_CFG_INIT(188, 0, 16, 1),
    PORT_CFG_INIT(188, 1, 16, 2),
    PORT_CFG_INIT(188, 2, 16, 3),
    PORT_CFG_INIT(188, 3, 16, 4),
};

struct mpx_cfg mpx_cfg_monotreme = {
    0, "monotreme", port_cfg_array_monotreme,
    sizeof(port_cfg_array_monotreme) / sizeof(struct port_cfg), 0
};

// Define a struct to hold all of the config sructs:
struct mpx_cfg *mpx_cfgs[] = {
    &mpx_cfg_monotreme
};

// Default value of this_mpx_cfg may be changed by mstp_init():
struct mpx_cfg *this_mpx_cfg = &mpx_cfg_monotreme;


