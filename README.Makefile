Make a Makefile symbolic link to the proper makefile.  This is especially
important if you're building this for the 2.6 kernel, as the kernel's module
builder *expects* to find a file named "Makefile".

The Makefile should already point to the correct kernel source directory if it was checked
out as a peer named megatron kernel
