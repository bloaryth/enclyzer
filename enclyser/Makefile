#################### ADDITIONAL SETTINGS ####################

.PHONY: libenclyser kenclyser disable-prefetcher

ADDITIONAL_APP_RUN_FLAGS := --verbose -j1 

ADDITIONAL_COMMON_C_FLAGS := 
ADDITIONAL_COMMON_INCLUDE_PATHS := -I.. -I../include

ADDITIONAL_APP_C_FLAGS := -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_NO
ADDITIONAL_ENCLAVE_C_FLAGS := -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_YES

ADDITIONAL_APP_LINK_FLAGS := -Llibenclyser -lenclyser_urts -lcriterion
ADDITIONAL_ENCLAVE_LINK_FLAGS := -Llibenclyser -lenclyser_trts

ADDITIONAL_TARGETS := libenclyser kenclyser disable-prefetcher

libenclyser:
	@make -C ../enclyser/libenclyser --quiet

kenclyser:
	@sudo make -C ../kenclyser clean all load --quiet

disable-prefetcher:
	@sudo modprobe msr
	@sudo wrmsr -a 0x1a4 0xf

#################### COMMANDS TO USE ####################

.PHONY: all run dump clean

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
SGX_COMMON_C_FLAGS := -m32
SGX_LIBRARY_PATH := $(SGX_SDK)/lib
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
SGX_COMMON_C_FLAGS := -m64
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
SGX_COMMON_C_FLAGS += -O2 -g -Wall $(ADDITIONAL_COMMON_C_FLAGS)
else
SGX_COMMON_C_FLAGS += -O2 -Wall $(ADDITIONAL_COMMON_C_FLAGS)
endif

#################### APP OBJECTS ####################

ifneq ($(SGX_MODE), HW)
URTS_LIBRARY_NAME := sgx_urts_sim
else
URTS_LIBRARY_NAME := sgx_urts
endif

APP_C_FILES := app/app.c
APP_INCLUDE_PATHS := $(ADDITIONAL_COMMON_INCLUDE_PATHS) -Iapp -I$(SGX_SDK)/include

APP_C_FLAGS := $(SGX_COMMON_C_FLAGS) $(ADDITIONAL_APP_C_FLAGS) -fPIC -Wno-attributes -Wno-unknown-pragmas $(APP_INCLUDE_PATHS)

ifeq ($(SGX_DEBUG), 1)
APP_C_FLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
APP_C_FLAGS += -DNDEBUG -DEDEBUG -UDEBUG
else
APP_C_FLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

APP_LINK_FLAGS := $(SGX_COMMON_C_FLAGS) $(ADDITIONAL_APP_LINK_FLAGS) -L$(SGX_LIBRARY_PATH) -l$(URTS_LIBRARY_NAME) -lpthread

ifneq ($(SGX_MODE), HW)
APP_LINK_FLAGS += -lsgx_uae_service_sim
else
APP_LINK_FLAGS += -lsgx_uae_service
endif

APP_C_OBJECTS := $(APP_C_FILES:.c=.o)

APP_NAME := sgx_app

app/enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	@echo "GEN  =>  $@"
	@cd app && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include

app/enclave_u.o: app/enclave_u.c
	@$(CC) $(APP_C_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

app/%.o: app/%.c
	@$(CC) $(APP_C_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(APP_NAME): app/enclave_u.o $(APP_C_OBJECTS)
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

ENCLAVE_C_FILES := enclave/enclave.c
ENCLAVE_INCLUDE_PATHS := $(ADDITIONAL_COMMON_INCLUDE_PATHS) -IInclude -Ienclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

ENCLAVE_C_FLAGS := $(SGX_COMMON_C_FLAGS) $(ADDITIONAL_ENCLAVE_C_FLAGS) $(ENCLAVE_INCLUDE_PATHS) -nostdinc -fvisibility=hidden -fpie -fstack-protector

ENCLAVE_LINK_FLAGS := $(SGX_COMMON_C_FLAGS) $(ADDITIONAL_ENCLAVE_LINK_FLAGS) \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(TRTS_LIBRARY_NAME) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(CRYPTO_LIBRARY_NAME) -l$(SERVICE_LIBRARY_NAME) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/enclave.lds

ENCLAVE_C_OBJECTS := $(ENCLAVE_C_FILES:.c=.o)

ENCLAVE_NAME := enclave.so
SIGNED_ENCLAVE_NAME := enclave.signed.so
ENCLAVE_CONFIG_FILE := enclave/enclave.config.xml

enclave/enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) $(ENCLAVE_C_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.c
	@$(CC) $(ENCLAVE_C_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(ENCLAVE_NAME): enclave/enclave_t.o $(ENCLAVE_C_OBJECTS)
	@$(CC) $^ -o $@ $(ENCLAVE_LINK_FLAGS)
	@echo "LINK =>  $@"

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
all: $(ADDITIONAL_TARGETS) $(APP_NAME) $(ENCLAVE_NAME)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(ENCLAVE_NAME) first with your signing key before you run the $(APP_NAME) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(ENCLAVE_NAME) -out <$(SIGNED_ENCLAVE_NAME)> -config $(ENCLAVE_CONFIG_FILE)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(ADDITIONAL_TARGETS) $(APP_NAME) $(SIGNED_ENCLAVE_NAME)
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

run: all
ifneq ($(build_mode), HW_RELEASE)
	@-$(CURDIR)/$(APP_NAME) $(ADDITIONAL_APP_RUN_FLAGS) > $(APP_NAME).txt 2>&1
	@sed -i -r "s/\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]//g" $(APP_NAME).txt
	@echo "RUN  =>  $(APP_NAME) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

dump:
	objdump -d $(APP_NAME) > $(APP_NAME).dump
	objdump -d $(ENCLAVE_NAME) > $(ENCLAVE_NAME).dump
	objdump -d $(ENCLAVE_C_OBJECTS) > $(ENCLAVE_C_OBJECTS).dump

clean:
	@rm -f $(APP_NAME) $(ENCLAVE_NAME) $(SIGNED_ENCLAVE_NAME) $(APP_C_OBJECTS) app/enclave_u.* $(ENCLAVE_C_OBJECTS) enclave/enclave_t.* $(APP_NAME).txt
