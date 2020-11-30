#include <linux/string.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/limits.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/pid.h>
#include <linux/fs.h>           /*struct file*/


#define TASK_COMM_LEN 16
#define NETLINK_TEST 29
#define AUDITPATH "/home/test/Desktop/TestAudit"
#define MAX_LENGTH 256

static u32 pid=0;
static struct sock *nl_sk = NULL;

//发送netlink消息message
int netlink_sendmsg(const void *buffer, unsigned int size)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int len = NLMSG_SPACE(1200);
	if((!buffer) || (!nl_sk) || (pid == 0)) 	return 1;
	skb = alloc_skb(len, GFP_ATOMIC); 	//分配一个新的sk_buffer
	if (!skb){
		printk(KERN_ERR "net_link: allocat_skb failed.\n");
		return 1;
	}
	nlh = nlmsg_put(skb,0,0,0,1200,0);
	NETLINK_CB(skb).creds.pid = 0;      /* from kernel */
	//下面必须手动设置字符串结束标志\0，否则用户程序可能出现接收乱码
	memcpy(NLMSG_DATA(nlh), buffer, size);
	//使用netlink单播函数发送消息
	if( netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT) < 0){
	//如果发送失败，则打印警告并退出函数
		printk(KERN_ERR "net_link: can not unicast skb \n");
		return 1;
	}
	return 0;
}


void get_fullname(const char *pathname,char *fullname)
{
	struct dentry *parent_dentry = current->fs->pwd.dentry;
    char buf[MAX_LENGTH];


        // pathname could be a fullname
	if (*(parent_dentry->d_name.name)=='/'){
	    strcpy(fullname,pathname);
	    return;
	}

	// pathname is not a fullname
	for(;;){
	    if (strcmp(parent_dentry->d_name.name,"/")==0)
            buf[0]='\0';//reach the root dentry.
	    else
	        strcpy(buf,parent_dentry->d_name.name);
        strcat(buf,"/");
        strcat(buf,fullname);
        strcpy(fullname,buf);

        if ((parent_dentry == NULL) || (*(parent_dentry->d_name.name)=='/'))
            break;

        parent_dentry = parent_dentry->d_parent;
	}

	strcat(fullname,pathname);

	return;
}

// PATH_MAX=4096
int AuditOpenat(struct pt_regs *regs, char *pathname, int ret)
{
    int flag = 0;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    // printk("pathmax: %ld", PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);

    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0) return 1;

    printk("openat, Info: fullname is  %s \t; Auditpath is  %s \n", fullname, AUDITPATH);

    strncpy(commandname,current->comm,TASK_COMM_LEN);

    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1 + 4;
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->dx; // regs->dx: mode for open file
    *((int*)buffer + 4) = ret;
    strcpy( (char*)( 5 + (int*)buffer ), commandname);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);

    // printk("flag: %d", *( (int*)buffer ));
    // printk("commandname: %s", (char*)( 5 + (int*)buffer ));
    // printk("fullname: %s", (char*)( 5 + TASK_COMM_LEN/4 +(int*)buffer ));

    netlink_sendmsg(buffer, size);
    return 0;
}


int AuditRead(struct pt_regs *regs, char *pathname, int ret)
{
    int flag = 1;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    char fd_name[512];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);

    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0) return 1;

    printk("read, Info: fullname is  %s \t; Auditpath is  %s \n", fullname, AUDITPATH);

    strncpy(commandname,current->comm,TASK_COMM_LEN);
    char ac_Buf[512];
    struct file * pst_File = NULL;
    //取出FD对应struct file并检验
    pst_File = fget(regs->di);
    if (NULL != pst_File)
    {
        //取出FD对应文件路径及文件名并检验
        strcpy(fd_name, d_path(&(pst_File->f_path), ac_Buf, sizeof(ac_Buf)));

        // if (NULL != fd_name)
        //     printk("\tfd %d is %s, addr is 0x%p", regs->di, fd_name, pst_File);
        // else
        //     printk("\tfd %d name is NULL, addr is 0x%p", regs->di, pst_File);
        // // fget(),fput()成对
        fput(pst_File);
    }
    if(NULL == fd_name)
    {
        strcpy(fd_name, "fd_name not found");
    }

    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1 + 4 + 512;
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->dx; // regs->dx: count for read
    *((int*)buffer + 4) = ret;
    strcpy( (char*)( 5 + (int*)buffer ), commandname);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 + (int*)buffer ), fd_name);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 + 512/4 + (int*)buffer ), fullname);
    printk("fd_name: %s, fullname: %s", fd_name, fullname);

    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditWrite(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 2;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    char fd_name[512];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);

    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0) return 1;

    printk("write, Info: fullname is  %s \t; Auditpath is  %s \n", fullname, AUDITPATH);

    strncpy(commandname,current->comm,TASK_COMM_LEN);
    char ac_Buf[512];
    struct file * pst_File = NULL;
    //取出FD对应struct file并检验
    pst_File = fget(regs->di);
    if (NULL != pst_File)
    {
        //取出FD对应文件路径及文件名并检验
        strcpy(fd_name, d_path(&(pst_File->f_path), ac_Buf, sizeof(ac_Buf)));

        // if (NULL != fd_name)
        //     printk("\tfd %d is %s, addr is 0x%p", regs->di, fd_name, pst_File);
        // else
        //     printk("\tfd %d name is NULL, addr is 0x%p", regs->di, pst_File);
        // // fget(),fput()成对
        fput(pst_File);
    }
    if(NULL == fd_name)
    {
        strcpy(fd_name, "fd_name not found");
    }

    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1 + 4 + 512;
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->dx; // regs->dx: count for write
    *((int*)buffer + 4) = ret;
    strcpy( (char*)( 5 + (int*)buffer ), commandname);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 + (int*)buffer ), fd_name);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 + 512/4 + (int*)buffer ), fullname);
    printk("fd_name: %s, fullname: %s", fd_name, fullname);

    netlink_sendmsg(buffer, size);
    return 0;
}


int AuditClose(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 3;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("close, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1 + 4;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val; ;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->di; //文件描述字
    *((int*)buffer + 4) = ret; //close结果
    strcpy( (char*)( 5 + (int*)buffer ), commandname);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);
    
    // printk((char*)( 5 + (int*)buffer ));
    // printk((char*)( 5 + TASK_COMM_LEN/4 +(int*)buffer));
    
    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditKill(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 4;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("kill, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 32 + TASK_COMM_LEN + 1 + 4;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val; ;  //uid
    *((int*)buffer + 2) = current->pid;  //当前的pid
    *((int*)buffer + 3) = task_pgrp(current)->numbers->nr; //当前的进程组id
    *((int*)buffer + 4) = regs->si; //sig号
    *((int*)buffer + 5) = regs->di; //pid号
    *((int*)buffer + 6) = ret; //kill结果
    strcpy( (char*)( 7 + (int*)buffer ), commandname);
    strcpy( (char*)( 7 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);

    printk((char*)( 7 + (int*)buffer ));
    printk( (char*)( 7 + TASK_COMM_LEN/4 +(int*)buffer ));
        
    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditMkdir(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 5;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    char *makedir_pathname;
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);
    
    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("mkdir, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val; ;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->si; //mkdir的mode
    *((int*)buffer + 4) = ret; //mkdir结果
    // printk("%o", *((int*)buffer + 2));
    strcpy( (char*)( 5 + (int*)buffer ), commandname);
    strcpy( (char*)( 5 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);  //mkdir的目录

    printk((char*)( 5 + (int*)buffer));
    printk((char*)( 5 + TASK_COMM_LEN/4 +(int*)buffer));
    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditFchmodat(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 6;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    if(pathname == NULL)
    {
        printk("Null");
    }else
    {
        printk("pathname is %s", pathname);
    }
    
    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("fchmodat, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 20 + TASK_COMM_LEN + 1 + 4;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val; ;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->dx; //mod
    *((int*)buffer + 4) = ret; //fchmodat结果
    *((int*)buffer + 5) = regs->di; //dirfd，是否为相对路径
    strcpy( (char*)( 6 + (int*)buffer ), commandname);
    strcpy( (char*)( 6 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);
    

    printk("mod: %o, dirfd: %d", *((int*)buffer + 3), *((int*)buffer + 5));
    printk("fullname: %s,  commandname: %s", (char*)( 6 + TASK_COMM_LEN/4 +(int*)buffer), (char*)( 6 + (int*)buffer ));

    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditFchownat(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 7;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("fchownat, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 28 + TASK_COMM_LEN + 1 + 4;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val; ;  //uid  %zu
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->di; //dirfd
    *((int*)buffer + 4) = regs->r8; //int flag
    *((int*)buffer + 5) = regs->r10; //gid_t group  %zu
    *((int*)buffer + 6) = regs->dx; //user id
    *((int*)buffer + 7) = ret; //fchownat结果
    strcpy( (char*)( 8 + (int*)buffer ), commandname);
    strcpy( (char*)( 8 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);
    
    printk("dirfd：%d，flag: %d, groupid: %d， user： %d， commandname：%s,  fullname: %s", *((int*)buffer + 3), *((int*)buffer + 4), *((int*)buffer + 5), *((int*)buffer + 6), (char*)( 8 + (int*)buffer ), (char*)( 8 + TASK_COMM_LEN/4 +(int*)buffer));
    printk((char*)( 8 + (int*)buffer ));
    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditUnlinkat(struct pt_regs *regs, char * pathname, int ret)
{
    int flag = 8;
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("unlinkat, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 20 + TASK_COMM_LEN + 1 + 4;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = flag;
    *((int*)buffer + 1) = cred->uid.val; ;  //uid
    *((int*)buffer + 2) = current->pid;
    *((int*)buffer + 3) = regs->dx; //flag
    *((int*)buffer + 4) = ret; //unlinkat结果
    *((int*)buffer + 5) = regs->di; //dirfd，是否为相对路径
    strcpy( (char*)( 6 + (int*)buffer ), commandname);
    strcpy( (char*)( 6 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);
    
    printk("mod: %o, dirfd: %d", *((int*)buffer + 3), *((int*)buffer + 5));
    printk("fullname: %s,  commandname: %s", (char*)( 6 + TASK_COMM_LEN/4 +(int*)buffer), (char*)( 6 + (int*)buffer ));

    netlink_sendmsg(buffer, size);
    return 0;
}



void nl_data_ready(struct sk_buff *__skb)
 {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    skb = skb_get (__skb);

    if (skb->len >= NLMSG_SPACE(0)) {
	nlh = nlmsg_hdr(skb);
//	if( pid != 0 ) printk("Pid != 0 \n ");
	pid = nlh->nlmsg_pid; /*pid of sending process */
	//printk("net_link: pid is %d, data %s:\n", pid, (char *)NLMSG_DATA(nlh));
	printk("net_link: pid is %d\n", pid);
	kfree_skb(skb);
    }
    return;
}



void netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_data_ready,
    };

    nl_sk=netlink_kernel_create(&init_net,NETLINK_TEST, &cfg);

    if (!nl_sk)
    {
		printk(KERN_ERR "net_link: Cannot create netlink socket.\n");
		if (nl_sk != NULL)
    		sock_release(nl_sk->sk_socket);
    }
    else  printk("net_link: create socket ok.\n");
}


void netlink_release(void) {
    if (nl_sk != NULL)
 		sock_release(nl_sk->sk_socket);
}
