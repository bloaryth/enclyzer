#################### COMMANDS TO USE ####################

.PHONY: all run dump clean

#################### ADDITIONAL SETTINGS ####################

ADDL_BUILD := build_libenclyzer 
ADDL_RUN := disable_prefetcher build_kenclyzer 
ADDL_CLEAN := clean_libenclyzer enable_prefetcher clean_kenclyzer

.PHONY: build_libenclyzer build_kenclyzer disable_prefetcher \
	clean_libenclyzer clean_kenclyzer enable_prefetcher

build_libenclyzer:
	@make -C ../enclyzer/libenclyzer clean all --quiet
	@sleep 5

clean_libenclyzer:
	@make -C ../enclyzer/libenclyzer clean --quiet

build_kenclyzer:
	@sudo make -C ../kenclyzer clean all load --quiet

clean_kenclyzer:
	@sudo make -C ../kenclyzer clean --quiet

disable_prefetcher:
	@sudo modprobe msr
	@sudo wrmsr -a 0x1a4 0xf

enable_prefetcher:
	@sudo modprobe msr
	@sudo wrmsr -a 0x1a4 0x0

ADDL_APP_RUN_FLAGS := --verbose -j1 

ADDL_APP_CFLAGS := -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_NO
ADDL_ENCLAVE_CFLAGS := -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_YES

ADDL_APP_LINK_FLAGS := -Llibenclyzer -lenclyzer_urts -lcriterion
ADDL_ENCLAVE_LINK_FLAGS := -Llibenclyzer -lenclyzer_trts

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

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

#################### APP OBJECTS ####################

ifneq ($(SGX_MODE), HW)
URTS_LIBRARY_NAME := sgx_urts_sim
else
URTS_LIBRARY_NAME := sgx_urts
endif

APP_NAME := sgx_app

APP_C_FILES := app/app.c app/l1tf.c app/mds.c app/meltdown.c app/shared.c app/spectre.c app/system.c app/taa.c app/verw.c
APP_C_OBJECTS := $(APP_C_FILES:.c=.o)

APP_INCLUDE_PATHS := -I.. -Iapp -I$(SGX_SDK)/include

APP_CFLAGS := $(SGX_COMMON_CFLAGS) $(ADDL_APP_CFLAGS) $(APP_INCLUDE_PATHS) -fPIC -Wno-attributes -Wno-unknown-pragmas
ifeq ($(SGX_DEBUG), 1)
APP_CFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
APP_CFLAGS += -DNDEBUG -DEDEBUG -UDEBUG
else
APP_CFLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

APP_LINK_FLAGS := $(SGX_COMMON_CFLAGS) $(ADDL_APP_LINK_FLAGS) -L$(SGX_LIBRARY_PATH) -l$(URTS_LIBRARY_NAME) -lpthread
ifneq ($(SGX_MODE), HW)
APP_LINK_FLAGS += -lsgx_uae_service_sim
else
APP_LINK_FLAGS += -lsgx_uae_service
endif

enclave/enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	@$(SGX_EDGER8R) --untrusted enclave/enclave.edl --untrusted-dir enclave --search-path .. --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_u.o: enclave/enclave_u.c
	@$(CC) $(APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

app/%.o: app/%.c
	@$(CC) $(APP_CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(APP_NAME): enclave/enclave_u.o $(APP_C_OBJECTS)
	@$(CC) $^ -o $@ $(APP_LINK_FLAGS) -I$(SGX_SDK)/include/
	@echo "LINK =>  $@"

#################### ENCLAVE OBJECTS ####################

ifneq ($(SGX_MODE), HW)
TRTS_LIBRARY_NAME := sgx_trts_sim
SERVICE_LIBRARY_NAME := sgx_tservice_sim
else
TRTS_LIBRARY_NAME := sgx_trts
SERVICE_LIBRARY_NAME := sgx_tservice
endif
CRYPTO_LIBRARY_NAME := sgx_tcrypto

ENCLAVE_NAME := enclave.so
SIGNED_ENCLAVE_NAME := enclave.signed.so
ENCLAVE_CONFIG_FILE := enclave/enclave.config.xml

ENCLAVE_C_FILES := enclave/enclave.c
ENCLAVE_C_OBJECTS := $(ENCLAVE_C_FILES:.c=.o)

ENCLAVE_INCLUDE_PATHS := -I.. -Ienclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
ENCLAVE_CFLAGS := $(SGX_COMMON_CFLAGS) $(ADDL_ENCLAVE_CFLAGS) $(ENCLAVE_INCLUDE_PATHS) -nostdinc -fno-builtin -fvisibility=hidden -fpie -fstack-protector
ENCLAVE_LINK_FLAGS := $(SGX_COMMON_CFLAGS) $(ADDL_ENCLAVE_LINK_FLAGS) \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(TRTS_LIBRARY_NAME) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(CRYPTO_LIBRARY_NAME) -l$(SERVICE_LIBRARY_NAME) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
	-Wl,--version-script=enclave/enclave.lds

enclave/enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	@$(SGX_EDGER8R) --trusted enclave/enclave.edl --trusted-dir enclave --search-path .. --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) $(ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.c
	@echo "CC  <=  $<"
	@$(CC) $(ENCLAVE_CFLAGS) -c $< -o $@

$(ENCLAVE_NAME): enclave/enclave_t.o $(ENCLAVE_C_OBJECTS)
	@echo "LINK =>  $@"
	@$(CC) $^ -o $@ $(ENCLAVE_LINK_FLAGS)

$(SIGNED_ENCLAVE_NAME): $(ENCLAVE_NAME)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave $(ENCLAVE_NAME) -out $@ -config $(ENCLAVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

#################### PHONY OBJECTS ####################

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
build_mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
build_mode = HW_PRERELEASE
else
build_mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
build_mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
build_mode = SIM_PRERELEASE
else
build_mode = SIM_RELEASE
endif
endif

ifeq ($(build_mode), HW_RELEASE)
all: $(ADDL_BUILD) $(APP_NAME) $(ENCLAVE_NAME)
	@echo "The project has been built in release hardware mode." 
	@echo "Please sign the $(ENCLAVE_NAME) first with your signing key before you run the $(APP_NAME) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(ENCLAVE_NAME) -out <$(SIGNED_ENCLAVE_NAME)> -config $(ENCLAVE_CONFIG_FILE)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(ADDL_BUILD) $(APP_NAME) $(SIGNED_ENCLAVE_NAME)
ifeq ($(build_mode), HW_DEBUG) 
	@echo "The project has been built in debug hardware mode."
else ifeq ($(build_mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(build_mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(build_mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all $(ADDL_RUN)
ifneq ($(build_mode), HW_RELEASE)
	-$(CURDIR)/$(APP_NAME) $(ADDL_APP_RUN_FLAGS)
	@echo "RUN  =>  $(APP_NAME) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

run_quiet: all $(ADDL_RUN)
ifneq ($(build_mode), HW_RELEASE)
	-$(CURDIR)/$(APP_NAME) $(ADDL_APP_RUN_FLAGS) > $(APP_NAME).txt 2>&1
	sed -i -r "s/\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]//g" $(APP_NAME).txt
	@echo "RUN  =>  $(APP_NAME) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

dump:
	objdump -d $(APP_NAME) > $(APP_NAME).dump
	objdump -d $(ENCLAVE_NAME) > $(ENCLAVE_NAME).dump
	objdump -d $(ENCLAVE_C_OBJECTS) > $(ENCLAVE_C_OBJECTS).dump

clean: $(ADDL_CLEAN)
	@rm -f $(APP_NAME) $(ENCLAVE_NAME) $(SIGNED_ENCLAVE_NAME) $(APP_C_OBJECTS) enclave/enclave_u.* $(ENCLAVE_C_OBJECTS) enclave/enclave_t.* $(APP_NAME).txt
