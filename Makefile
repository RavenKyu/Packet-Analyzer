CC = gcc -g
OBJECTS = network.o \
	hex_viewer.o 

all: BEGIN $(OBJECTS)
	@$(CC) -o network $(OBJECTS) -lpcap
	@echo Compilation is done.

BEGIN:
	@echo Compilation will start soon..

network.o : network.c
	@$(CC) -c network.c

hex_viewer.o : hex_viewer.c
	@$(CC) -c hex_viewer.c

file_io.o : file_io.c
	@$(CC) -c file_io.c

clean :
	@rm -rf $(OBJECTS)
