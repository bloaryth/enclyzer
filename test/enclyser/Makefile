#################### ADDITIONAL SETTINGS ####################

.PHONY: libenclyser

ADDITIONAL_INCLUDE_PATHS := -I../..
ADDITIONAL_COMPILE_FLAGS := -DNAMESPACE_SGX_SHARED -DNAMESPACE_SGX_YES -DNAMESPACE_SGX_NO
ADDITIONAL_LINK_FLAGS := -L../../enclyser/libenclyser -lenclyser_urts -lenclyser_trts
ADDITIONAL_LIBRARIES := libenclyser

libenclyser:
	make -C ../../enclyser/libenclyser

#################### COMMANDS TO USE ####################

.PHONY: all clean

#################### TEST COMPILATION ####################

TEST_C_FILES := test-enclyser-libenclyser-attack.c test-enclyser-libenclyser-memory.c \
	test-enclyser-libenclyser-lfb.c test-enclyser-libenclyser-flush_reload.c
TEST_C_OBJECTS := $(patsubst %.c, %.o, $(TEST_C_FILES))

TEST_INCLUDE_PATHS := $(ADDITIONAL_INCLUDE_PATHS)
TEST_COMPILE_FLAGS := -O2 -Wall $(ADDITIONAL_COMPILE_FLAGS) $(TEST_INCLUDE_PATHS)
TEST_LINK_FLAGS := -lcriterion $(ADDITIONAL_LINK_FLAGS)

TEST_EXECUTABLE := test

all: $(ADDITIONAL_LIBRARIES) $(TEST_EXECUTABLE)

%.o : %.c
	$(CC) $(TEST_COMPILE_FLAGS) -c $< -o $@

$(TEST_EXECUTABLE): $(TEST_C_OBJECTS)
	$(CC) $^ -o $(TEST_EXECUTABLE) $(TEST_LINK_FLAGS)

run:
	sudo $(CURDIR)/$(TEST_EXECUTABLE) --verbose -j1

clean:
	rm -rf *.o $(TEST_EXECUTABLE)