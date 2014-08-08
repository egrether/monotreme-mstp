# A correct makefile for building a 2.6 kernel module...

ifndef MYPWD
MYPWD = $(shell pwd)
endif

KERNEL_SRC := $(MYPWD)/../linux-3.12.9


EXTRA_CFLAGS += -I$(MYPWD) -D__KERNEL__  -DMODULE
EXTRA_LDFLAGS += -s

# Leave these here for kernel-y correctness.
obj-m += n_mstp.o

n_mstp-objs :=	main.o \
		mpx_cfg.o \
		procfs.o \
		util.o \
		fsa_rf.o \
		fsa_mn.o \
		bacnet_lib.o

clean-files := *.o *.ko *.mod.c

all:
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$$PWD modules MYPWD=$(MYPWD)

clean:
	-rm -f *.o *.ko *.mod.c *.mod.o *.o.gz *.cmd .*.cmd
	-rm -rf .tmp_versions

# vim: ts=8 noexpandtab syntax=make
