// Test file for AArch64 GAS -- dtprel_lo12_nc for LDST64

func:
	// BFD_RELOC_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC
	ldr  x27, [x4, #:dtprel_lo12_nc:sym]

