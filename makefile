CC = gcc
CFLAGS = -g 
DBGFLAGS = -Ddebug_mode
OUTPUT_NAME = tracer
OBJS = attach.c memory_op.c functable.c

all: memory_op.h
	$(CC) $(OBJS) $(CFLAGS) -o $(OUTPUT_NAME) -ludis86

all_dbg: memory_op.h
	$(CC) $(OBJS) $(CFLAGS) $(DBGFLAGS) -o $(OUTPUT_NAME) -ludis86

clean:
	rm -rf *.dSYM
	rm tracer
