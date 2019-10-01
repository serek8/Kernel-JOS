int sys_port_open(int pid);
int sys_close(int fd);
int sys_read(int fd, void *buf, int nbyte);
int sys_write(int fd, const void *buf, int nbyte);