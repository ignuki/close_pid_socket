#define _POSIX_SOURCE

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <linux/limits.h>

typedef union _pid_int {
	int n;
	pid_t pid;
} pid_int;

typedef struct _maps_list {
	unsigned long start;
	unsigned long end;
	unsigned int perms;
	unsigned long offset;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long inode;
	char path[PATH_MAX];
	struct _maps_list * next;
	struct _maps_list * prev;
} maps_list;

#define UPDATE_MAPS_LIST(h, t, k) t = ((t = (h = h ? h : k))->next = k)->prev = t)->next

typedef struct _state {
	struct user_regs_struct * registers;
	struct _maps_list * maps;
	unsigned long syscall_addr;
	unsigned long signal;
} ptrace_state;

int parse_int(char * s);
int pid_attach(pid_t pid, ptrace_state * state);
int read_maps(pid_t pid, maps_list * maps);

/* argv[1] = pid */
/* argv[2] = fd  */

int main(int argc, char ** argv){

	if (argc < 3){
		return 1;
	}

	pid_int pid;
	int fd, sig;

	pid.n = parse_int(argv[1]);
	fd = parse_int(argv[2]);

	struct user_regs_struct registers;
	ptrace_state state = {&registers, NULL, 0, 0};

	if (pid_attach(pid.pid, registers)) {
		return 1;
	}

	// igual en rip no hay una syscall, habria que rastrear los mapas de
	// memoria del proceso. Comprobar con PEEKTEXT
	registers.rax = 4; //__NR_close;
	registers.rdi = fd;
	// registers.rip = syscall_addr;


	ptrace(PTRACE_SETREGS, pid.pid, NULL, &registers);
retry:
	ptrace(PTRACE_SINGLESTEP, pid.pid, NULL, NULL);

	int status = 0;
	waitpid(pid.pid, &status, 0);

	if (status){
		if (WIFSTOPPED(status)){
			if (WSTOPSIG(status) != SIGTRAP){
				sig = status;
				goto retry;
			}
		}
	}
	if (sig){
		kill(pid.pid, sig);
	}

	ptrace(PTRACE_DETACH, pid.pid, NULL, NULL);

	return 0;

}

int parse_int(char * s){

	int r = 0;

	while (*s){
		r *= 10;
		r += (*s++ - '0');
	}

	return r;

}

int pid_attach(pid_t pid, state * state){

	int ret, status;
	siginfo_t siginfo = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)){
		if(ptrace(PTRACE_ATTACH, pid.pid, NULL, NULL) == -1){
			return -1;
		}
		if(waitpid(pid.pid, &status, 0) <= 0){
			return -1;
		}
		if(!WIFSTOPPED(status)){
			return -1;
		}
	} else {
		if(siginfo.si_signo != SIGTRAP){
			return -1;
		}
	}

	if (ptrace(PTRACE_GETREGS, pid.pid, NULL, state->registers)){
		return -1:
	}

	/* is the next instruction a syscall? */
	unsigned long data = ptrace(PTRACE_PEEKTEXT, pid,
				    state->registers->rip - 2, NULL);
	/* the syscall interrupt code is 2 bytes long (0x050f) */
	if ((0x000000000000ffff & data) == 0x050f){
		/* Success finding the syscall interrupt address*/
		state->syscall_addr = state->registers->rip - 2;
		return 0;
	}

	/* find the interrupt address across the memory maps of the process */
	maps_list * maps = NULL;
	if (read_maps(pid, maps)){
		return -1;
	}

	return 0;

}

int read_maps(pid_t pid, maps_list * maps){

	maps_list * head = maps, * tail = maps, * tmp;
	char * buffer, * p;
	int fd, buf_len = getpagesize();

	if ((buffer = malloc(buf_len * sizeof(buffer[0]))) == NULL){
		return -1;
	}

	p = buffer;
	snprintf(buffer, (PATH_MAX - 1), "/proc/%d/maps", pid);

	if((fd = open(buffer, O_RDONLY)) == -1){
		free(buffer);
		return -1;
	}

	while (read(fd, p, 1) > 0){
		if (p++ != '\n'){
			continue;
		}
		*(p - 1) = 0;
		tmp = parse_line(buffer);
		if (tmp == NULL){
			goto err;
		}
		UPDATE_MAPS_LIST(head, tail, tmp);
		p = buffer;
	}

	close(fd);
	free(buffer);

	return 0;

err:
	close(fd);
	free(buffer);
	free_maps_list(maps);

	return -1;

}

maps_list * parse_line(char * buffer){

	maps_list new = NULL;
	char * p, * q;

	if ((new = malloc(sizeof(new[0]))) == NULL){
		return NULL;
	}



	return new;

}
