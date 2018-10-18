#define _GNU_SOURCE

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
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

typedef struct _state {
	struct user_regs_struct * registers;
	struct _maps_list * maps;
	unsigned long syscall_addr;
	unsigned long signal;
} ptrace_state;

int parse_int(char * s);
unsigned int parse_ui_hex(char * s);
unsigned long parse_ul_hex(char * s);
int pid_attach(pid_t pid, ptrace_state * state);
int pid_detach(pid_t pid, ptrace_state * state);
int read_maps(pid_t pid, maps_list ** maps);
maps_list * parse_map(char * buffer);
void print_maps(maps_list * maps);
void free_maps(maps_list * maps);

/* argv[1] = pid */
/* argv[2] = fd  */

int main(int argc, char ** argv){

	if (argc < 3){
		return 1;
	}

	pid_int pid;
	int fd;

	pid.n = parse_int(argv[1]);
	fd = parse_int(argv[2]);

    printf("pid: %i\nfd: %i\n", pid.n, fd);

	struct user_regs_struct registers;
	ptrace_state state = {&registers, NULL, 0, 0};

	if (pid_attach(pid.pid, &state)) {
        printf("Error attaching\n");
		return 1;
	}

    print_maps(state.maps);

	if (pid_detach(pid.pid, &state)) {
        printf("Error detaching\n");
		return 1;
	}
//
//	// igual en rip no hay una syscall, habria que rastrear los mapas de
//	// memoria del proceso. Comprobar con PEEKTEXT
//	registers.rax = 4; //__NR_close;
//	registers.rdi = fd;
//	// registers.rip = syscall_addr;
//
//
//	ptrace(PTRACE_SETREGS, pid.pid, NULL, &registers);
//retry:
//	ptrace(PTRACE_SINGLESTEP, pid.pid, NULL, NULL);
//
//	int status = 0;
//	waitpid(pid.pid, &status, 0);
//
//	if (status){
//		if (WIFSTOPPED(status)){
//			if (WSTOPSIG(status) != SIGTRAP){
//				sig = status;
//				goto retry;
//			}
//		}
//	}
//	if (sig){
//		kill(pid.pid, sig);
//	}
//
//	ptrace(PTRACE_DETACH, pid.pid, NULL, NULL);

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

unsigned int parse_ui_hex(char * s){
    
    unsigned int r = 0;
    
    while (*s){
        r *= 16;
        if (*s <= '9'){
            r += (*s++ - '0');
        } else if (*s <= 'F'){
            r += (*s++ - 'A') + 10;
        } else {
            r += (*s++ - 'a') + 10;
        }
    }

    return r;

}

unsigned long parse_ul_hex(char * s){
    
    unsigned long r = 0;
    
    while (*s){
        r *= 16;
        if (*s <= '9'){
            r += (*s++ - '0');
        } else if (*s <= 'F'){
            r += (*s++ - 'A') + 10;
        } else {
            r += (*s++ - 'a') + 10;
        }
    }

    return r;

}

int pid_attach(pid_t pid, ptrace_state * state){

    if (state == NULL){
        return -1;
    }

	int status;
	siginfo_t siginfo = {0};

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)){
		if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
			return -1;
		}
		if(waitpid(pid, &status, 0) <= 0){
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

	if (ptrace(PTRACE_GETREGS, pid, NULL, state->registers)){
		return -1;
	}

//	/* is the next instruction a syscall? */
//	unsigned long data = ptrace(PTRACE_PEEKTEXT, pid,
//				    state->registers->rip - 2, NULL);
//	/* the syscall interrupt code is 2 bytes long (0x050f) */
//	if ((0x000000000000ffff & data) == 0x050f){
//		/* Success finding the syscall interrupt address*/
//		state->syscall_addr = state->registers->rip - 2;
//        printf("Lucky\n");
//		return 0;
//	}

	/* find the interrupt address across the memory maps of the process */
	maps_list * maps = NULL;
	if (read_maps(pid, &maps)){
		return -1;
	}
    state->maps = maps;

	return 0;

}

int pid_detach(pid_t pid, ptrace_state * state){

    if (state == NULL){
        return -1;
    }
    
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
    free_maps(state->maps);

    return 0;

}

int read_maps(pid_t pid, maps_list ** maps){

    if (maps == NULL){
        return -1;
    }

	maps_list * head = *maps, * tail = *maps, * tmp = NULL;
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
		if (*p++ != '\n'){
			continue;
		}
		*(p - 1) = 0;
		tmp = parse_map(buffer);
		if (tmp == NULL){
			goto err;
		}
        if (head == NULL){
            head = tmp;
            tail = tmp;
        } else {
            tail->next = tmp;
            tmp->prev = tail;
            tail = tmp;
        }
		p = buffer;
	}
    *maps = head;

	close(fd);
	free(buffer);

	return 0;

err:
	close(fd);
	free(buffer);
	free_maps(*maps);
    *maps = NULL;

	return -1;

}

maps_list * parse_map(char * buffer){

	maps_list * new = NULL;
	char * p, * q;

    if (buffer == NULL){
        return NULL;
    }

	if ((new = calloc(1, sizeof(new[0]))) == NULL){
		return NULL;
	}

    p = q = buffer;
    while (*++q != '-');
    *q = 0;
    new->start = parse_ul_hex(p);

    p = ++q;
    while (*++q != ' ');
    *q = 0;
    new->end = parse_ul_hex(p);

    p = ++q;
    while (*++q != ' ');
    *q = 0;
    new->perms = 0;
    if (*p++ == 'r') new->perms |= 4;
    if (*p++ == 'w') new->perms |= 2;
    if (*p++ == 'x') new->perms |= 1;
    if (*p == 'p') new->perms |= 8;
    if (*p == 's') new->perms |= 16;

    p = ++q;
    while (*++q != ' ');
    *q = 0;
    new->offset = parse_ul_hex(p);

    p = ++q;
    while (*++q != ':');
    *q = 0;
    new->dev_major = parse_ui_hex(p);

    p = ++q;
    while (*++q != ' ');
    *q = 0;
    new->dev_minor = parse_ui_hex(p);
    
    p = ++q;
    while (*++q != ' ');
    *q = 0;
    new->inode = parse_ul_hex(p);

    while (*++q == ' ');
    p = q;
    snprintf(new->path, (PATH_MAX - 1), "%s", p);

	return new;

}

void print_maps(maps_list * head){
    while(head){
        printf("--------------------------------------------------------------------------------\n");   
        printf("node: %lx\n", (unsigned long) head);
        printf("--------------------------------------------------------------------------------\n");   
        printf("start_address:\t\t%lx\n", head->start);
        printf("end_address:\t\t%lx\n", head->end);
        printf("perms:\t\t\t%u\n", head->perms);
        printf("offset:\t\t\t%lx\n", head->offset);
        printf("dev_major:\t\t%u\n", head->dev_major);
        printf("dev_minor:\t\t%u\n", head->dev_minor);
        printf("inode:\t\t\t%lx\n", head->inode);
        printf("pathname:\t\t%s\n", head->path);
        printf("parse_maps *next:\t%lx\n", (unsigned long) head->next);
        printf("parse_maps *previous:\t%lx\n", (unsigned long) head->prev);
        printf("\n");
        head = head->next;
    }
}

void free_maps(maps_list * maps){
    
    if (maps == NULL){
        return;
    }
    maps_list * tmp;

    while(maps){
        tmp = maps->next;
        free(maps);
        maps = tmp;
    }

    return;

}
