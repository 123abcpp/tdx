/* cpuid_features bits */
pub const CPUID_FP87: u32 = 1 << 0;
pub const CPUID_VME: u32 = 1 << 1;
pub const CPUID_DE: u32 = 1 << 2;
pub const CPUID_PSE: u32 = 1 << 3;
pub const CPUID_TSC: u32 = 1 << 4;
pub const CPUID_MSR: u32 = 1 << 5;
pub const CPUID_PAE: u32 = 1 << 6;
pub const CPUID_MCE: u32 = 1 << 7;
pub const CPUID_CX8: u32 = 1 << 8;
pub const CPUID_APIC: u32 = 1 << 9;
pub const CPUID_SEP: u32 = 1 << 11; /* sysenter/sysexit */
pub const CPUID_MTRR: u32 = 1 << 12;
pub const CPUID_PGE: u32 = 1 << 13;
pub const CPUID_MCA: u32 = 1 << 14;
pub const CPUID_CMOV: u32 = 1 << 15;
pub const CPUID_PAT: u32 = 1 << 16;
pub const CPUID_PSE36: u32 = 1 << 17;
pub const CPUID_PN: u32 = 1 << 18;
pub const CPUID_CLFLUSH: u32 = 1 << 19;
pub const CPUID_DTS: u32 = 1 << 21;
pub const CPUID_ACPI: u32 = 1 << 22;
pub const CPUID_MMX: u32 = 1 << 23;
pub const CPUID_FXSR: u32 = 1 << 24;
pub const CPUID_SSE: u32 = 1 << 25;
pub const CPUID_SSE2: u32 = 1 << 26;
pub const CPUID_SS: u32 = 1 << 27;
pub const CPUID_HT: u32 = 1 << 28;
pub const CPUID_TM: u32 = 1 << 29;
pub const CPUID_IA64: u32 = 1 << 30;
pub const CPUID_PBE: u32 = 1 << 31;

pub const CPUID_EXT_SSE3: u32 = 1 << 0;
pub const CPUID_EXT_PCLMULQDQ: u32 = 1 << 1;
pub const CPUID_EXT_DTES64: u32 = 1 << 2;
pub const CPUID_EXT_MONITOR: u32 = 1 << 3;
pub const CPUID_EXT_DSCPL: u32 = 1 << 4;
pub const CPUID_EXT_VMX: u32 = 1 << 5;
pub const CPUID_EXT_SMX: u32 = 1 << 6;
pub const CPUID_EXT_EST: u32 = 1 << 7;
pub const CPUID_EXT_TM2: u32 = 1 << 8;
pub const CPUID_EXT_SSSE3: u32 = 1 << 9;
pub const CPUID_EXT_CID: u32 = 1 << 10;
pub const CPUID_EXT_RESERVED: u32 = 1 << 11;
pub const CPUID_EXT_FMA: u32 = 1 << 12;
pub const CPUID_EXT_CX16: u32 = 1 << 13;
pub const CPUID_EXT_XTPR: u32 = 1 << 14;
pub const CPUID_EXT_PDCM: u32 = 1 << 15;
pub const CPUID_EXT_PCID: u32 = 1 << 17;
pub const CPUID_EXT_DCA: u32 = 1 << 18;
pub const CPUID_EXT_SSE41: u32 = 1 << 19;
pub const CPUID_EXT_SSE42: u32 = 1 << 20;
pub const CPUID_EXT_X2APIC: u32 = 1 << 21;
pub const CPUID_EXT_MOVBE: u32 = 1 << 22;
pub const CPUID_EXT_POPCNT: u32 = 1 << 23;
pub const CPUID_EXT_TSC_DEADLINE_TIMER: u32 = 1 << 24;
pub const CPUID_EXT_AES: u32 = 1 << 25;
pub const CPUID_EXT_XSAVE: u32 = 1 << 26;
pub const CPUID_EXT_OSXSAVE: u32 = 1 << 27;
pub const CPUID_EXT_AVX: u32 = 1 << 28;
pub const CPUID_EXT_F16C: u32 = 1 << 29;
pub const CPUID_EXT_RDRAND: u32 = 1 << 30;
pub const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;

pub const CPUID_EXT2_FPU: u32 = 1 << 0;
pub const CPUID_EXT2_VME: u32 = 1 << 1;
pub const CPUID_EXT2_DE: u32 = 1 << 2;
pub const CPUID_EXT2_PSE: u32 = 1 << 3;
pub const CPUID_EXT2_TSC: u32 = 1 << 4;
pub const CPUID_EXT2_MSR: u32 = 1 << 5;
pub const CPUID_EXT2_PAE: u32 = 1 << 6;
pub const CPUID_EXT2_MCE: u32 = 1 << 7;
pub const CPUID_EXT2_CX8: u32 = 1 << 8;
pub const CPUID_EXT2_APIC: u32 = 1 << 9;
pub const CPUID_EXT2_SYSCALL: u32 = 1 << 11;
pub const CPUID_EXT2_MTRR: u32 = 1 << 12;
pub const CPUID_EXT2_PGE: u32 = 1 << 13;
pub const CPUID_EXT2_MCA: u32 = 1 << 14;
pub const CPUID_EXT2_CMOV: u32 = 1 << 15;
pub const CPUID_EXT2_PAT: u32 = 1 << 16;
pub const CPUID_EXT2_PSE36: u32 = 1 << 17;
pub const CPUID_EXT2_MP: u32 = 1 << 19;
pub const CPUID_EXT2_NX: u32 = 1 << 20;
pub const CPUID_EXT2_MMXEXT: u32 = 1 << 22;
pub const CPUID_EXT2_MMX: u32 = 1 << 23;
pub const CPUID_EXT2_FXSR: u32 = 1 << 24;
pub const CPUID_EXT2_FFXSR: u32 = 1 << 25;
pub const CPUID_EXT2_PDPE1GB: u32 = 1 << 26;
pub const CPUID_EXT2_RDTSCP: u32 = 1 << 27;
pub const CPUID_EXT2_LM: u32 = 1 << 29;
pub const CPUID_EXT2_3DNOWEXT: u32 = 1 << 30;
pub const CPUID_EXT2_3DNOW: u32 = 1 << 31;

pub const CPUID_EXT3_LAHF_LM: u32 = 1 << 0;
pub const CPUID_EXT3_CMP_LEG: u32 = 1 << 1;
pub const CPUID_EXT3_SVM: u32 = 1 << 2;
pub const CPUID_EXT3_EXTAPIC: u32 = 1 << 3;
pub const CPUID_EXT3_CR8LEG: u32 = 1 << 4;
pub const CPUID_EXT3_ABM: u32 = 1 << 5;
pub const CPUID_EXT3_SSE4A: u32 = 1 << 6;
pub const CPUID_EXT3_MISALIGNSSE: u32 = 1 << 7;
pub const CPUID_EXT3_3DNOWPREFETCH: u32 = 1 << 8;
pub const CPUID_EXT3_OSVW: u32 = 1 << 9;
pub const CPUID_EXT3_IBS: u32 = 1 << 10;
pub const CPUID_EXT3_XOP: u32 = 1 << 11;
pub const CPUID_EXT3_SKINIT: u32 = 1 << 12;
pub const CPUID_EXT3_WDT: u32 = 1 << 13;
pub const CPUID_EXT3_LWP: u32 = 1 << 15;
pub const CPUID_EXT3_FMA4: u32 = 1 << 16;
pub const CPUID_EXT3_TCE: u32 = 1 << 17;
pub const CPUID_EXT3_NODEID: u32 = 1 << 19;
pub const CPUID_EXT3_TBM: u32 = 1 << 21;
pub const CPUID_EXT3_TOPOEXT: u32 = 1 << 22;
pub const CPUID_EXT3_PERFCORE: u32 = 1 << 23;
pub const CPUID_EXT3_PERFNB: u32 = 1 << 24;

pub const CPUID_SVM_NPT: u32 = 1 << 0;
pub const CPUID_SVM_LBRV: u32 = 1 << 1;
pub const CPUID_SVM_SVMLOCK: u32 = 1 << 2;
pub const CPUID_SVM_NRIPSAVE: u32 = 1 << 3;
pub const CPUID_SVM_TSCSCALE: u32 = 1 << 4;
pub const CPUID_SVM_VMCBCLEAN: u32 = 1 << 5;
pub const CPUID_SVM_FLUSHASID: u32 = 1 << 6;
pub const CPUID_SVM_DECODEASSIST: u32 = 1 << 7;
pub const CPUID_SVM_PAUSEFILTER: u32 = 1 << 10;
pub const CPUID_SVM_PFTHRESHOLD: u32 = 1 << 12;
pub const CPUID_SVM_AVIC: u32 = 1 << 13;
pub const CPUID_SVM_V_VMSAVE_VMLOAD: u32 = 1 << 15;
pub const CPUID_SVM_VGIF: u32 = 1 << 16;
pub const CPUID_SVM_SVME_ADDR_CHK: u32 = 1 << 28;

/* Support RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE */
pub const CPUID_7_0_EBX_FSGSBASE: u32 = 1 << 0;
/* Support for TSC adjustment MSR 0x3B */
pub const CPUID_7_0_EBX_TSC_ADJUST: u32 = 1 << 1;
/* Support SGX */
pub const CPUID_7_0_EBX_SGX: u32 = 1 << 2;
/* 1st Group of Advanced Bit Manipulation Extensions */
pub const CPUID_7_0_EBX_BMI1: u32 = 1 << 3;
/* Hardware Lock Elision */
pub const CPUID_7_0_EBX_HLE: u32 = 1 << 4;
/* Intel Advanced Vector Extensions 2 */
pub const CPUID_7_0_EBX_AVX2: u32 = 1 << 5;
/* Supervisor-mode Execution Prevention */
pub const CPUID_7_0_EBX_SMEP: u32 = 1 << 7;
/* 2nd Group of Advanced Bit Manipulation Extensions */
pub const CPUID_7_0_EBX_BMI2: u32 = 1 << 8;
/* Enhanced REP MOVSB/STOSB */
pub const CPUID_7_0_EBX_ERMS: u32 = 1 << 9;
/* Invalidate Process-Context Identifier */
pub const CPUID_7_0_EBX_INVPCID: u32 = 1 << 10;
/* Restricted Transactional Memory */
pub const CPUID_7_0_EBX_RTM: u32 = 1 << 11;
/* Cache QoS Monitoring */
pub const CPUID_7_0_EBX_PQM: u32 = 1 << 12;
/* Memory Protection Extension */
pub const CPUID_7_0_EBX_MPX: u32 = 1 << 14;
/* Resource Director Technology Allocation */
pub const CPUID_7_0_EBX_RDT_A: u32 = 1 << 15;
/* AVX-512 Foundation */
pub const CPUID_7_0_EBX_AVX512F: u32 = 1 << 16;
/* AVX-512 Doubleword & Quadword Instruction */
pub const CPUID_7_0_EBX_AVX512DQ: u32 = 1 << 17;
/* Read Random SEED */
pub const CPUID_7_0_EBX_RDSEED: u32 = 1 << 18;
/* ADCX and ADOX instructions */
pub const CPUID_7_0_EBX_ADX: u32 = 1 << 19;
/* Supervisor Mode Access Prevention */
pub const CPUID_7_0_EBX_SMAP: u32 = 1 << 20;
/* AVX-512 Integer Fused Multiply Add */
pub const CPUID_7_0_EBX_AVX512IFMA: u32 = 1 << 21;
/* Persistent Commit */
pub const CPUID_7_0_EBX_PCOMMIT: u32 = 1 << 22;
/* Flush a Cache Line Optimized */
pub const CPUID_7_0_EBX_CLFLUSHOPT: u32 = 1 << 23;
/* Cache Line Write Back */
pub const CPUID_7_0_EBX_CLWB: u32 = 1 << 24;
/* Intel Processor Trace */
pub const CPUID_7_0_EBX_INTEL_PT: u32 = 1 << 25;
/* AVX-512 Prefetch */
pub const CPUID_7_0_EBX_AVX512PF: u32 = 1 << 26;
/* AVX-512 Exponential and Reciprocal */
pub const CPUID_7_0_EBX_AVX512ER: u32 = 1 << 27;
/* AVX-512 Conflict Detection */
pub const CPUID_7_0_EBX_AVX512CD: u32 = 1 << 28;
/* SHA1/SHA256 Instruction Extensions */
pub const CPUID_7_0_EBX_SHA_NI: u32 = 1 << 29;
/* AVX-512 Byte and Word Instructions */
pub const CPUID_7_0_EBX_AVX512BW: u32 = 1 << 30;
/* AVX-512 Vector Length Extensions */
pub const CPUID_7_0_EBX_AVX512VL: u32 = 1 << 31;

/* AVX-512 Vector Byte Manipulation Instruction */
pub const CPUID_7_0_ECX_AVX512_VBMI: u32 = 1 << 1;
/* User-Mode Instruction Prevention */
pub const CPUID_7_0_ECX_UMIP: u32 = 1 << 2;
/* Protection Keys for User-mode Pages */
pub const CPUID_7_0_ECX_PKU: u32 = 1 << 3;
/* OS Enable Protection Keys */
pub const CPUID_7_0_ECX_OSPKE: u32 = 1 << 4;
/* UMONITOR/UMWAIT/TPAUSE Instructions */
pub const CPUID_7_0_ECX_WAITPKG: u32 = 1 << 5;
/* Additional AVX-512 Vector Byte Manipulation Instruction */
pub const CPUID_7_0_ECX_AVX512_VBMI2: u32 = 1 << 6;
/* CET SHSTK feature */
pub const CPUID_7_0_ECX_CET_SHSTK: u32 = 1 << 7;
/* Galois Field New Instructions */
pub const CPUID_7_0_ECX_GFNI: u32 = 1 << 8;
/* Vector AES Instructions */
pub const CPUID_7_0_ECX_VAES: u32 = 1 << 9;
/* Carry-Less Multiplication Quadword */
pub const CPUID_7_0_ECX_VPCLMULQDQ: u32 = 1 << 10;
/* Vector Neural Network Instructions */
pub const CPUID_7_0_ECX_AVX512VNNI: u32 = 1 << 11;
/* Support for VPOPCNT[B,W] and VPSHUFBITQMB */
pub const CPUID_7_0_ECX_AVX512BITALG: u32 = 1 << 12;
/* Intel Total Memory Encryption */
pub const CPUID_7_0_ECX_TME: u32 = 1 << 13;
/* POPCNT for vectors of DW/QW */
pub const CPUID_7_0_ECX_AVX512_VPOPCNTDQ: u32 = 1 << 14;
/* Placeholder for bit 15 */
pub const CPUID_7_0_ECX_FZM: u32 = 1 << 15;
/* 5-level Page Tables */
pub const CPUID_7_0_ECX_LA57: u32 = 1 << 16;
/* MAWAU for MPX */
pub const CPUID_7_0_ECX_MAWAU: u32 = 31 << 17;
/* Read Processor ID */
pub const CPUID_7_0_ECX_RDPID: u32 = 1 << 22;
/* KeyLocker */
pub const CPUID_7_0_ECX_KEYLOCKER: u32 = 1 << 23;
/* Bus Lock Debug Exception */
pub const CPUID_7_0_ECX_BUS_LOCK_DETECT: u32 = 1 << 24;
/* Cache Line Demote Instruction */
pub const CPUID_7_0_ECX_CLDEMOTE: u32 = 1 << 25;
/* Move Doubleword as Direct Store Instruction */
pub const CPUID_7_0_ECX_MOVDIRI: u32 = 1 << 27;
/* Move 64 Bytes as Direct Store Instruction */
pub const CPUID_7_0_ECX_MOVDIR64B: u32 = 1 << 28;
/* ENQCMD and ENQCMDS instructions */
pub const CPUID_7_0_ECX_ENQCMD: u32 = 1 << 29;
/* Support SGX Launch Control */
pub const CPUID_7_0_ECX_SGX_LC: u32 = 1 << 30;
/* Protection Keys for Supervisor-mode Pages */
pub const CPUID_7_0_ECX_PKS: u32 = 1 << 31;

/* AVX512 Neural Network Instructions */
pub const CPUID_7_0_EDX_AVX512_4VNNIW: u32 = 1 << 2;
/* AVX512 Multiply Accumulation Single Precision */
pub const CPUID_7_0_EDX_AVX512_4FMAPS: u32 = 1 << 3;
/* Fast Short Rep Mov */
pub const CPUID_7_0_EDX_FSRM: u32 = 1 << 4;
/* User Interrupt Support*/
pub const CPUID_7_0_EDX_UNIT: u32 = 1 << 5;
/* AVX512 Vector Pair Intersection to a Pair of Mask Registers */
pub const CPUID_7_0_EDX_AVX512_VP2INTERSECT: u32 = 1 << 8;
/* SERIALIZE instruction */
pub const CPUID_7_0_EDX_SERIALIZE: u32 = 1 << 14;
/* TSX Suspend Load Address Tracking instruction */
pub const CPUID_7_0_EDX_TSX_LDTRK: u32 = 1 << 16;
/* PCONFIG instruction */
pub const CPUID_7_0_EDX_PCONFIG: u32 = 1 << 18;
/* Architectural LBRs */
pub const CPUID_7_0_EDX_ARCH_LBR: u32 = 1 << 19;
/* CET IBT feature */
pub const CPUID_7_0_EDX_CET_IBT: u32 = 1 << 20;
/* Intel AMX BF16 Support */
pub const CPUID_7_0_EDX_AMX_BF16: u32 = 1 << 22;
/* AVX512_FP16 instruction */
pub const CPUID_7_0_EDX_AVX512_FP16: u32 = 1 << 23;
/* AMX tile (two-dimensional register; */
pub const CPUID_7_0_EDX_AMX_TILE: u32 = 1 << 24;
/* Intel AMX INT8 Support */
pub const CPUID_7_0_EDX_AMX_INT8: u32 = 1 << 25;
/* Speculation Control */
pub const CPUID_7_0_EDX_SPEC_CTRL: u32 = 1 << 26;
/* Single Thread Indirect Branch Predictors */
pub const CPUID_7_0_EDX_STIBP: u32 = 1 << 27;
/* Arch Capabilities */
pub const CPUID_7_0_EDX_ARCH_CAPABILITIES: u32 = 1 << 29;
/* Core Capability */
pub const CPUID_7_0_EDX_CORE_CAPABILITY: u32 = 1 << 30;
/* Speculative Store Bypass Disable */
pub const CPUID_7_0_EDX_SPEC_CTRL_SSBD: u32 = 1 << 31;

/* AVX VNNI Instruction */
pub const CPUID_7_1_EAX_AVX_VNNI: u32 = 1 << 4;
/* AVX512 BFloat16 Instruction */
pub const CPUID_7_1_EAX_AVX512_BF16: u32 = 1 << 5;
/* CMPCCXADD Instructions */
pub const CPUID_7_1_EAX_CMPCCXADD: u32 = 1 << 7;
/* Fast Zero REP MOVS */
pub const CPUID_7_1_EAX_FZRM: u32 = 1 << 10;
/* Fast Short REP STOS */
pub const CPUID_7_1_EAX_FSRS: u32 = 1 << 11;
/* Fast Short REP CMPS/SCAS */
pub const CPUID_7_1_EAX_FSRC: u32 = 1 << 12;
/* Support Tile Computational Operations on FP16 Numbers */
pub const CPUID_7_1_EAX_AMX_FP16: u32 = 1 << 21;
/* Support for VPMADD52[H,L]UQ */
pub const CPUID_7_1_EAX_AVX_IFMA: u32 = 1 << 23;

/* Support for VPDPB[SU,UU,SS]D[,S] */
pub const CPUID_7_1_EDX_AVX_VNNI_INT8: u32 = 1 << 4;
/* AVX NE CONVERT Instructions */
pub const CPUID_7_1_EDX_AVX_NE_CONVERT: u32 = 1 << 5;
/* AMX COMPLEX Instructions */
pub const CPUID_7_1_EDX_AMX_COMPLEX: u32 = 1 << 8;
/* PREFETCHIT0/1 Instructions */
pub const CPUID_7_1_EDX_PREFETCHITI: u32 = 1 << 14;

/* Do not exhibit MXCSR Configuration Dependent Timing (MCDT; behavior */
pub const CPUID_7_2_EDX_MCDT_NO: u32 = 1 << 5;

/* XFD Extend Feature Disabled */
pub const CPUID_D_1_EAX_XFD: u32 = 1 << 4;

/* Packets which contain IP payload have LIP values */
pub const CPUID_14_0_ECX_LIP: u32 = 1 << 31;

/* CLZERO instruction */
pub const CPUID_8000_0008_EBX_CLZERO: u32 = 1 << 0;
/* Always save/restore FP error pointers */
pub const CPUID_8000_0008_EBX_XSAVEERPTR: u32 = 1 << 2;
/* Write back and do not invalidate cache */
pub const CPUID_8000_0008_EBX_WBNOINVD: u32 = 1 << 9;
/* Indirect Branch Prediction Barrier */
pub const CPUID_8000_0008_EBX_IBPB: u32 = 1 << 12;
/* Indirect Branch Restricted Speculation */
pub const CPUID_8000_0008_EBX_IBRS: u32 = 1 << 14;
/* Single Thread Indirect Branch Predictors */
pub const CPUID_8000_0008_EBX_STIBP: u32 = 1 << 15;
/* Speculative Store Bypass Disable */
pub const CPUID_8000_0008_EBX_AMD_SSBD: u32 = 1 << 24;

pub const CPUID_XSAVE_XSAVEOPT: u32 = 1 << 0;
pub const CPUID_XSAVE_XSAVEC: u32 = 1 << 1;
pub const CPUID_XSAVE_XGETBV1: u32 = 1 << 2;
pub const CPUID_XSAVE_XSAVES: u32 = 1 << 3;

pub const CPUID_6_EAX_ARAT: u32 = 1 << 2;

/* CPUID[0x80000007].EDX flags: */
pub const CPUID_APM_INVTSC: u32 = 1 << 8;
