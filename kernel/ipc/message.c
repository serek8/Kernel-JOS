#ifdef BONUS_LAB5

#include <kernel/message.h>
#include <kernel/sched/task.h>
#include <kernel/monitor.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <assert.h>
#include <error.h>
#include <stdio.h>
#include <string.h>

#define IPC_MSG_SENDER_ERROR -1

extern struct list runq;

void* process_va2kernel_va(void *va){
    physaddr_t *entry;
    struct page_info *p = page_lookup(cur_task->task_pml4, ROUNDDOWN(va, PAGE_SIZE), &entry);
    void *kva = page2kva(p) + ((uint64_t)va & (PAGE_SIZE-1));
    return kva;
}

int sys_port_open(int pid){
    cprintf("port opened\n");
    if(pid == 0){
        cur_task->fd_table[0].flags = FD_OPEN;
        return 0;
    } else{
        struct task *other_task = pid2task(pid, 0);
        if((other_task->fd_table[0].flags & FD_OPEN) != FD_OPEN){
             panic("Process #PID(%d) doesn't have listening port opened!\n", pid);
        }
        if(cur_task->fd_table[1].flags == FD_OPEN){
            panic("Currently, a process can only open up to one sender! Close the current port!\n");
        }
        cur_task->fd_table[1].flags = FD_OPEN;
        cur_task->fd_table[1].pid = pid;
        other_task->fd_table[0].pid = cur_task->task_pid;
        return 1;
    }
    return 0;
}

int sys_close(int fd){
    if(fd == 0){
        cur_task->fd_table[0].flags = 0;
    } else if(fd == 1){
        cur_task->fd_table[1].flags = 0;
        cur_task->fd_table[1].pid = 0;
    } else{
        panic("Invalid fd!\n");
    }
    return 0;
}


int sys_read(int fd, void *buf, int nbyte){
    if(fd != 0){
        panic("Cant read from writer ports!\n");
    } else if(fd == 0){ // '0' is always reader
        int writer_pid = cur_task->fd_table[fd].pid; 
        struct task *writer_task = pid2task(writer_pid, 0);
        struct fd *writer_fd = &writer_task->fd_table[1]; // '1' is always the sender
        if((writer_fd->flags & FD_READY) == FD_READY){ // writer is already waiting
            int read_nbyte = nbyte > writer_fd->nbytes ? writer_fd->nbytes : nbyte;
            memcpy(buf, writer_fd->bytes, read_nbyte);
            writer_fd->flags |= FD_DONE;
            writer_task->task_status = TASK_RUNNABLE;
            writer_task->task_frame.rax = read_nbyte > writer_fd->nbytes ? read_nbyte : IPC_MSG_SENDER_ERROR;
            list_push_left(&runq, &writer_task->task_node);
            return read_nbyte;
        } else{ // reader needs to wait for the writer
            struct fd *reader_fd = &cur_task->fd_table[fd];
            reader_fd->nbytes = nbyte;
            reader_fd->bytes = process_va2kernel_va((void*)buf); // convert addr to support foreign processes
            reader_fd->flags |= FD_READY;
            cur_task->task_status = TASK_NOT_RUNNABLE;
            sched_set_expired();
            sched_yield();
        }
    } else{
        panic("Invalid fd!\n");
    }
    return 0;
}


int sys_write(int fd, const void *buf, int nbyte){
    if(fd == 0){
        panic("Cant write to itself!\n");
    } else if(fd == 1){ // Description table is size of FILE_DESCRIPTION_TABLE_SIZE (2). 0 is a reader, 1 is a writer
        int reader_pid = cur_task->fd_table[fd].pid; 
        struct task *reader_task = pid2task(reader_pid, 0);
        struct fd *reader_fd = &reader_task->fd_table[0];
        if((reader_fd->flags & FD_READY) == FD_READY){ // reader is already waiting
            int allowed_nbyte = reader_fd->nbytes <= nbyte ? reader_fd->nbytes : nbyte;
            memcpy(reader_fd->bytes, buf, allowed_nbyte);
            reader_fd->flags |= FD_DONE;
            reader_task->task_status = TASK_RUNNABLE;
            reader_task->task_frame.rax = allowed_nbyte;
            list_push_left(&runq, &reader_task->task_node);
            if(reader_fd->nbytes < nbyte){ // writer buffer is bigger than reader's
                return -1;
            }
            return nbyte;
        } else{ // writer needs to wait for the reader
            struct fd *writer_fd = &cur_task->fd_table[fd];
            writer_fd->nbytes = nbyte;
            writer_fd->bytes = process_va2kernel_va((void*)buf);
            writer_fd->flags |= FD_READY;
            cur_task->task_status = TASK_NOT_RUNNABLE;
            sched_set_expired();
            sched_yield();
        }
    } else{
        panic("Invalid fd!\n");
        return -1;
    }
    return -1;
}

#endif

/* Sample program
int main(void)
{
	pid_t child;
	child = fork();

	if (child > 0) { // Parent reader
		int pid = getpid();
		printf("[PID %5u] I am the parent!\n", pid);
		int fd = port_open(0);
		sched_yield();
		const int BUFFER_SIZE = 30;
		char buf[BUFFER_SIZE];
		int read_ret = read(fd, buf, BUFFER_SIZE);
		printf("[PID %5u] received a message. Return val=%d, buf='%.*s'\n", pid, read_ret, read_ret, buf);
		close(fd);

	} else { // Child sender
		int pid = getpid();
		printf("[PID %5u] I am the child!\n", pid);
		int fd = port_open(1);
		sched_yield();
		char *str = "Greetings from the child";
		printf("[PID %5u] will send a message '%s'\n", pid, str);
		int write_ret = write(fd, str, strlen(str));
		printf("[PID %5u] sent a message. Return value of write=%d\n", pid, write_ret);
		close(fd);
	}
	return 0;
}
*/