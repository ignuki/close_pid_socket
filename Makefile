CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -pedantic -O3

all: close_pid_socket

close_pid_socket: close_pid_socket.c
	$(CC) $(CFLAGS) close_pid_socket.c -o close_pid_socket

clean:
	rm close_pid_socket
