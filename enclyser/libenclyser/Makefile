#################### COMMANDS TO USE ####################

.PHONY: all clean

#################### LIBRARY COMPILATION ####################

C_FILES := attack.c flush_reload.c info.c lfb.c memory.c pt.c system.c template.c
C_URTS_OBJECTS := $(patsubst %.c, %_urts.o, $(C_FILES))
C_TRTS_OBJECTS := $(patsubst %.c, %_trts.o, $(C_FILES))

COMMON_CLAGS := -O2 -Wall -I. -I../.. -I../../include
URTS_C_FLAGS := $(COMMON_CLAGS) -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_NO
TRTS_C_FLAGS := $(COMMON_CLAGS) -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_YES

URTS_LIBRARY := libsgxanalyser_urts.a
TRTS_LIBRARY := libsgxanalyser_trts.a

all: $(URTS_LIBRARY) $(TRTS_LIBRARY)

%_urts.o : %.c
	$(CC) $(URTS_C_FLAGS) -c $< -o $@

%_trts.o : %.c
	$(CC) $(TRTS_C_FLAGS) -c $< -o $@

$(URTS_LIBRARY): $(C_URTS_OBJECTS)
	$(AR) -rc $@ $^

$(TRTS_LIBRARY): $(C_TRTS_OBJECTS)
	$(AR) -rc $@ $^

clean:
	rm -f $(C_URTS_OBJECTS) $(C_TRTS_OBJECTS) $(URTS_LIBRARY) $(TRTS_LIBRARY)