#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <fcntl.h>
#include <asm/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <pwd.h>
#include "db.h"

#define TM_FMT "%Y-%m-%d %H:%M:%S"

#define NETLINK_TEST 29
#define TASK_COMM_LEN 16
#define MAX_LENGTH 256
#define MAX_PAYLOAD 4096  /* maximum payload size*/
int sock_fd;
struct msghdr msg;
struct nlmsghdr *nlh = NULL;
struct sockaddr_nl src_addr, dest_addr;
struct iovec iov;

// distinguish log from netlink socket
char *syscall_name[] = {"open", "read", "write", "close", "kill", "mkdir", "fchmodat", "fchownat", "unlinkat"}; 

void LogOpen(char *commandname, int uid, int pid, char *file_path, int flags, int ret);
void LogRead(char *commandname, int uid, int pid, char *file_path, char *fd_name, int ret);
void LogWrite(char *commandname, int uid, int pid, char *file_path, char *fd_name, int ret);
void LogClose(char *commandname, int uid, int pid, char *file_path, int flags, int ret);
void LogKill(char *commandname, int uid, int pid, char *file_path, int ret, int gid, int sig, int pid_);
void LogMkdir(char *commandname, int uid, int pid, char *file_path, int mode, int ret);
void LogFchmodat(char *commandname, int uid, int pid, char *file_path, int mod, int ret, int dirfd);
void LogFchownat(char *commandname, int uid, int pid, char *file_path, int flags, int ret, int dirfd, int gid, int user_id);
void LogUnlinkat(char *commandname, int uid, int pid, char *file_path, int mod, int ret, int dirfd);

void LogOpen(char *commandname, int uid, int pid, char *file_path, int flags, int ret) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret > 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	char opentype[16];
	if (flags & O_RDONLY ) strcpy(opentype, "Read");
	else if (flags & O_WRONLY ) strcpy(opentype, "Write");
	else if (flags & O_RDWR ) strcpy(opentype, "Read/Write");
	else strcpy(opentype,"other");

	printf("OPEN username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\" opentype:%s result:%s\n",
		username,uid,commandname,pid,logtime,file_path,opentype, result);
    insert_open(username, uid, commandname, pid, logtime, file_path, result, opentype);
}

void LogRead(char *commandname, int uid, int pid, char *file_path, char *fd_name, int ret) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret >= 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username, pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("READ username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  fd_name:%s  result:%s\n",
		username,uid,commandname,pid,logtime,file_path,fd_name,result);
	insert_read(username,uid,commandname,pid,logtime,file_path,fd_name,result);
}

void LogWrite(char *commandname, int uid, int pid, char *file_path, char *fd_name, int ret) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret >= 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username, pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("WRITE username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\" fd_name:%s  result:%s\n",
		username,uid,commandname,pid,logtime,file_path,fd_name,result);
	insert_write(username,uid,commandname,pid,logtime,file_path,fd_name,result);
}

void LogClose(char *commandname, int uid, int pid, char *file_path, int flags, int ret) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret == 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	char closetype[16];
	if (flags & O_RDONLY ) strcpy(closetype, "Read");
	else if (flags & O_WRONLY ) strcpy(closetype, "Write");
	else if (flags & O_RDWR ) strcpy(closetype, "Read/Write");
	else strcpy(closetype,"other");

	printf("CLOSE username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  closetype:%s  result:%s\n",
		username,uid,commandname,pid,logtime,file_path,closetype, result);
	insert_close(username,uid,commandname,pid,logtime,file_path,closetype, result);
}

void LogKill(char *commandname, int uid, int pid, char *file_path, int ret, int gid, int sig, int pid_) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret == 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("KILL username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  result:%s  gid:%d  sig:%d  pid_:%d\n",
		username,uid,commandname,pid,logtime,file_path, result, gid, sig, pid_);
    insert_kill(username,uid,commandname,pid,logtime,file_path, result, gid, sig, pid_);
}

void LogMkdir(char *commandname, int uid, int pid, char *file_path, int mode, int ret) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret == 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("MKDIR username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  result:%s  mode:%o  ret:%d\n",
		username,uid,commandname,pid,logtime,file_path, result, mode, ret);
    insert_mkdir(username,uid,commandname,pid,logtime,file_path, result, mode);
}

void LogFchmodat(char *commandname, int uid, int pid, char *file_path, int mod, int ret, int dirfd) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret == 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("FCHMODAT username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  result:%s  mod:%o  ret:%d  dirfd:%d\n",
		username,uid,commandname,pid,logtime,file_path, result, mod, ret, dirfd);
    insert_fchmodat(username,uid,commandname,pid,logtime,file_path, result, mod, dirfd);
}

void LogFchownat(char *commandname, int uid, int pid, char *file_path, int flags, int ret, int dirfd, int gid, int user_id) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret == 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("FCHOWNAT username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  result:%s  flags:%d  ret:%d  dirfd:%d  gid:%d  user_id:%d\n",
		username,uid,commandname,pid,logtime,file_path, result, flags, ret, dirfd, gid, user_id);
    insert_fchownat(username,uid,commandname,pid,logtime,file_path, result, flags, dirfd, gid, user_id);
}


void LogUnlinkat(char *commandname, int uid, int pid, char *file_path, int mod, int ret, int dirfd) {
	char logtime[64];
	char username[32];
	struct passwd *pwinfo;
	char result[10];

	if (ret == 0) strcpy(result,"success");
	else strcpy(result,"failed");

	time_t t=time(0);
	pwinfo = getpwuid(uid);
	strcpy(username,pwinfo->pw_name);
	strftime(logtime, sizeof(logtime), TM_FMT, localtime(&t) );

	printf("UNLINKAT username(uid):%s(%d)  command(pid):%s(%d)  logtime:%s  filepath:\"%s\"  result:%s  mod:%o  ret:%d  dirfd:%d\n",
		username,uid,commandname,pid,logtime,file_path, result, mod, ret, dirfd);
    insert_unlinkat(username,uid,commandname,pid,logtime,file_path, result, mod, dirfd);
}


void sendpid(unsigned int pid)
{
	//Send message to initialize
	memset(&msg, 0, sizeof(msg));
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = pid;  //self pid
	src_addr.nl_groups = 0;  //not in mcast groups
	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;   //For Linux Kernel
	dest_addr.nl_groups = 0; //unicast

	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = pid;  /* self pid */
	nlh->nlmsg_flags = 0;
	/* Fill in the netlink message payload */
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	//printf(" Sending message. ...\n");
	sendmsg(sock_fd, &msg, 0);
}

void killdeal_func()
{
	printf("The process is killed! \n");
	close(sock_fd);
	if (nlh != NULL)
	 	free(nlh);
	exit(0);
}

int main(int argc, char *argv[]){
	char buff[110];
	//void killdeal_func();
	char logpath[32];
	if (argc == 1) strcpy(logpath,"./log");
	else if (argc == 2) strncpy(logpath, argv[1],32);
	else {
		printf("commandline parameters error! please check and try it! \n");
		exit(1);
	}

	signal(SIGTERM,killdeal_func);
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    sendpid(getpid());


    char *filename = "test.db";
    create_table(filename);

    // int count = 0;
	// Loop to get message
	while(1) {	//Read message from kernel
		// if (count > 2) break;
        // count++;
        unsigned int uid, pid,flags,ret;
		int flag = -1;
		char * file_path;
		char * commandname;
		char * fd_name;
		recvmsg(sock_fd, &msg, 0);
		flag = *( (unsigned int *)NLMSG_DATA(nlh) );		
		// printf("%s\n", syscall_name[atoi(flag)]);

		if (strcmp(syscall_name[flag], "open") == 0) {
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (int *)NLMSG_DATA(nlh)  );
			flags = *( 3 + (int *)NLMSG_DATA(nlh)  );
			ret = *( 4 + (int *)NLMSG_DATA(nlh)  );
			commandname = (char *)( 5 + (int *)NLMSG_DATA(nlh));
			file_path = (char *)( 5 + TASK_COMM_LEN/4 + (int *)NLMSG_DATA(nlh));
			LogOpen(commandname, uid, pid, file_path, flags, ret);
		} 
		else if (strcmp(syscall_name[flag], "read") == 0) {
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (int *)NLMSG_DATA(nlh)  );
			flags = *( 3 + (int *)NLMSG_DATA(nlh)  );
			ret = *( 4 + (int *)NLMSG_DATA(nlh)  );
			commandname = (char *)( 5 + (int *)NLMSG_DATA(nlh));
			file_path = (char *)( 5 + TASK_COMM_LEN/4 + (int *)NLMSG_DATA(nlh));
			fd_name = (char *)( 5 + TASK_COMM_LEN/4 + 512/4 + (int *)NLMSG_DATA(nlh));
			LogRead(commandname, uid, pid, file_path, fd_name, ret);
		} 
		else if (strcmp(syscall_name[flag], "write") == 0) {
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (int *)NLMSG_DATA(nlh)  );
			flags = *( 3 + (int *)NLMSG_DATA(nlh)  );
			ret = *( 4 + (int *)NLMSG_DATA(nlh)  );
			commandname = (char *)( 5 + (int *)NLMSG_DATA(nlh));
			file_path = (char *)( 5 + TASK_COMM_LEN/4 + (int *)NLMSG_DATA(nlh));
			fd_name = (char *)( 5 + TASK_COMM_LEN/4 + 512/4 + (int *)NLMSG_DATA(nlh));
			LogWrite(commandname, uid, pid, file_path, fd_name, ret);
		}
		else if (strcmp(syscall_name[flag], "close") == 0) {
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (unsigned int *)NLMSG_DATA(nlh)  );
			flags = *( 3 + (unsigned int *)NLMSG_DATA(nlh)  );   // 文件描述字
			ret = *( 4 + (unsigned int *)NLMSG_DATA(nlh)  );
			commandname = (char *)( 5 + (unsigned int *)NLMSG_DATA(nlh));
			file_path = (char *)( 5 + TASK_COMM_LEN/4 + (unsigned int *)NLMSG_DATA(nlh));
			LogClose(commandname, uid, pid, file_path, flags, ret);
			// printf("flag:%s pid:%d flags:%d commandname:%s file_path:%s\n", flag, pid, flags, commandname, file_path);
		}
		else if (strcmp(syscall_name[flag], "kill") == 0) {
			int gid, sig, pid_;
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (unsigned int *)NLMSG_DATA(nlh) );
			gid = *( 3 + (unsigned int *)NLMSG_DATA(nlh));
			sig = *( 4 + (unsigned int *)NLMSG_DATA(nlh));
			pid_ = *( 5 + (unsigned int *)NLMSG_DATA(nlh));
			ret = *( 6 + (unsigned int *)NLMSG_DATA(nlh));
			commandname = (char *)( 7 + (unsigned int *)NLMSG_DATA(nlh));
			file_path = (char *)( 7 + TASK_COMM_LEN/4 + (unsigned int *)NLMSG_DATA(nlh));
			LogKill(commandname, uid, pid, file_path, ret, gid, sig, pid_);
		}
		else if (strcmp(syscall_name[flag], "mkdir") == 0) {
			int mode;
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (unsigned int *)NLMSG_DATA(nlh)  );
			mode = *( 3 + (unsigned int *)NLMSG_DATA(nlh)  );
			ret = *( 4 + (unsigned int *)NLMSG_DATA(nlh)  );
			commandname = (char *)( 5 + (unsigned int *)NLMSG_DATA(nlh));
			file_path = (char *)( 5 + TASK_COMM_LEN/4 + (unsigned int *)NLMSG_DATA(nlh));
			LogMkdir(commandname, uid, pid, file_path, mode, ret);
		}
		else if (strcmp(syscall_name[flag], "fchmodat") == 0) {
			int mod, dirfd;
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (unsigned int *)NLMSG_DATA(nlh) );
			mod = *( 3 + (unsigned int *)NLMSG_DATA(nlh) );
			ret = *( 4 + (unsigned int *)NLMSG_DATA(nlh) );
			dirfd = *( 5 + (unsigned int *)NLMSG_DATA(nlh) );  //dirfd，是否为相对路径
			commandname = (char *)( 6 + (unsigned int *)NLMSG_DATA(nlh));
			file_path = (char *)( 6 + TASK_COMM_LEN/4 + (unsigned int *)NLMSG_DATA(nlh));
			LogFchmodat(commandname, uid, pid, file_path, mod, ret, dirfd);
		}
		else if (strcmp(syscall_name[flag], "fchownat") == 0) {
			int dirfd, gid, user_id;
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (unsigned int *)NLMSG_DATA(nlh) );
			dirfd = *( 3 + (unsigned int *)NLMSG_DATA(nlh) );
			flags = *( 4 + (unsigned int *)NLMSG_DATA(nlh)  );
			gid = *( 5 + (unsigned int *)NLMSG_DATA(nlh));
			user_id = *( 6 + (unsigned int *)NLMSG_DATA(nlh));
			ret = *( 7 + (unsigned int *)NLMSG_DATA(nlh)  );
			commandname = (char *)( 8 + (unsigned int *)NLMSG_DATA(nlh));
			file_path = (char *)( 8 + TASK_COMM_LEN/4 + (unsigned int *)NLMSG_DATA(nlh));
			LogFchownat(commandname, uid, pid, file_path, flags, ret, dirfd, gid, user_id);
		}
		else if (strcmp(syscall_name[flag], "unlinkat") == 0) {
			int mod, dirfd;
			uid = *( 1 + (unsigned int *)NLMSG_DATA(nlh) );
			pid = *( 2 + (unsigned int *)NLMSG_DATA(nlh) );
			mod = *( 3 + (unsigned int *)NLMSG_DATA(nlh) );
			ret = *( 4 + (unsigned int *)NLMSG_DATA(nlh) );
			dirfd = *( 5 + (unsigned int *)NLMSG_DATA(nlh) );  //dirfd，是否为相对路径
			commandname = (char *)( 6 + (unsigned int *)NLMSG_DATA(nlh));
			file_path = (char *)( 6 + TASK_COMM_LEN/4 + (unsigned int *)NLMSG_DATA(nlh));
			LogUnlinkat(commandname, uid, pid, file_path, mod, ret, dirfd);
		}
		
	}
	close(sock_fd);
	free(nlh);
    close_table();
	return 0;
}

