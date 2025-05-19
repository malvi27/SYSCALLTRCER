PROG = syscall_gui
SRC = syscall_gui.c
CC = gcc
CFLAGS = `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0`

$(PROG): $(SRC)
	$(CC) $(CFLAGS) -o $(PROG) $(SRC) $(LIBS)

clean:
	rm -f $(PROG)

