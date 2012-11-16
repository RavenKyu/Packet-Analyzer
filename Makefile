CC = gcc -g
OBJECTS = network.o \
	hex_viewer.o \
	basement.o \
	level_1.o \
	level_2.o \
	level_3.o \
	print_result.o \

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

basement.o : basement.c
	@$(CC) -c basement.c

level_1.o : level_1.c
	@$(CC) -c level_1.c

level_2.o : level_2.c
	@$(CC) -c level_2.c

level_3.o : level_3.c
	@$(CC) -c level_3.c

print_result.o : print_result.c
	@$(CC) -c print_result.c

clean :
	@rm -rf $(OBJECTS)
