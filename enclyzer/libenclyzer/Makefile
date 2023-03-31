#################### COMMANDS TO USE ####################

.PHONY: header all clean

#################### SGX SDK SETTINGS ####################

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CCFLAGS)), -m32)
SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
SGX_COMMON_CFLAGS := -m32
SGX_LIBRARY_PATH := $(SGX_SDK)/lib
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
SGX_COMMON_CFLAGS += -O2 -g -Wall $(ADDL_COMMON_CFLAGS)
else
SGX_COMMON_CFLAGS += -O2 -Wall $(ADDL_COMMON_CFLAGS)
endif

#################### LIBRARY COMPILATION ####################

C_FILES := attack.c flush_reload.c info.c lfb.c memory.c pt.c system.c template.c

C_UH_FILES := $(patsubst %.c, %_u.h, $(C_FILES))
C_TH_FILES := $(patsubst %.c, %_t.h, $(C_FILES))

C_URTS_OBJECTS := $(patsubst %.c, %_urts.o, $(C_FILES))
C_TRTS_OBJECTS := $(patsubst %.c, %_trts.o, $(C_FILES))

URTS_INCLUDE_PATHS := -I. -I../..  -I$(SGX_SDK)/include
URTS_CFLAGS := $(SGX_COMMON_CFLAGS) $(URTS_INCLUDE_PATHS) -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_NO

TRTS_INCLUDE_PATHS := -I. -I../.. -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
TRTS_CFLAGS := $(SGX_COMMON_CFLAGS) $(TRTS_INCLUDE_PATHS) -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_YES -nostdinc -fno-builtin -fvisibility=hidden -fpie -fstack-protector

URTS_LIBRARY := libenclyzer_urts.a
TRTS_LIBRARY := libenclyzer_trts.a

header: $(C_UH_FILES) $(C_TH_FILES)

all: header $(URTS_LIBRARY) $(TRTS_LIBRARY)

%_u.h: %.edl $(SGX_EDGER8R)
	@$(SGX_EDGER8R) --untrusted $< --untrusted-dir . --search-path ../.. --search-path $(SGX_SDK)/include --header-only

%_t.h: %.edl $(SGX_EDGER8R)
	@$(SGX_EDGER8R) --trusted $< --trusted-dir . --search-path ../.. --search-path $(SGX_SDK)/include --header-only

%_urts.o: %.c
	@$(CC) $(URTS_CFLAGS) -c $< -o $@

%_trts.o: %.c
	@$(CC) $(TRTS_CFLAGS) -c $< -o $@

$(URTS_LIBRARY): $(C_URTS_OBJECTS)
	@$(AR) -rc $@ $^

$(TRTS_LIBRARY): $(C_TRTS_OBJECTS)
	@$(AR) -rc $@ $^

clean:
	@rm -rf $(C_UH_FILES) $(C_TH_FILES) $(C_URTS_OBJECTS) $(C_TRTS_OBJECTS) $(URTS_LIBRARY) $(TRTS_LIBRARY)