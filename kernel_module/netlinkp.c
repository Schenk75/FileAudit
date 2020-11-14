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
#include <linux/fs.h>           /*struct file*/


#define TASK_COMM_LEN 16
#define NETLINK_TEST 29
#define AUDITPATH "/home/TestAudit"
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


int AuditOpenat(struct pt_regs *regs, char *pathname, int ret)
{
    char *flag = "00";
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

    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0) return 1;

    printk("openat, Info: fullname is  %s \t; Auditpath is  %s \n", fullname, AUDITPATH);


    strncpy(commandname,current->comm,TASK_COMM_LEN);

    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1 + strlen(flag);  // strlen(flag) == 2
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = cred->uid.val; ;  //uid
    *((int*)buffer + 1) = current->pid;
    *((int*)buffer + 2) = regs->dx; // regs->dx: mode for open file
    *((int*)buffer + 3) = ret;
    strcpy( (char*)( 4 + (int*)buffer ), flag);
    strcpy( (char*)( 6 + (int*)buffer ), commandname);
    strcpy( (char*)( 6 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);

    printk((char*)( 4 + (int*)buffer ));
    printk((char*)( 6 + (int*)buffer ));

    netlink_sendmsg(buffer, size);
    return 0;
}


int AuditRead(struct pt_regs *regs, char *pathname, int ret)
{
    char *flag = "01";
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    char *fd_name = NULL;
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("read, Info: fullname is  %s \t; Auditpath is  %s ; fd is %d", fullname, AUDITPATH, regs->di);

    char ac_Buf[128];
    struct file * pst_File = NULL;
    //取出FD对应struct file并检验
    pst_File = fget(regs->di);
    if (NULL != pst_File)
    {
        //取出FD对应文件路径及文件名并检验
        fd_name = d_path(&(pst_File->f_path), ac_Buf, sizeof(ac_Buf));

        // if (NULL != fd_name)
        // {
        //     printk("\tfd %d is %s, addr is 0x%p", regs->di, fd_name, pst_File);
        // }
        // else
        // {
        //     printk("\tfd %d name is NULL, addr is 0x%p", regs->di, pst_File);
        // }
        // fget(),fput()成对
        fput(pst_File);
    }

    strncpy(commandname,current->comm,TASK_COMM_LEN);

    size = strlen(fd_name) + 16 + TASK_COMM_LEN + 1 + PATH_MAX + strlen(flag);
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = cred->uid.val; ;  //uid
    *((int*)buffer + 1) = current->pid;
    *((int*)buffer + 2) = regs->dx; // regs->dx: read buf size
    *((int*)buffer + 3) = ret;
    strcpy( (char*)( 4 + (int*)buffer ), flag);
    strcpy( (char*)( 6 + (int*)buffer ), commandname);
    strcpy( (char*)( 6 + TASK_COMM_LEN/4 + (int*)buffer ), fullname);
    strcpy( (char*)( 6 + TASK_COMM_LEN/4 + MAX_LENGTH/4 + (int*)buffer ), fd_name); //不确定是否可以

    printk((char*)( 4 + (int*)buffer ));
    printk( (char*)( 6 + TASK_COMM_LEN/4 + (int*)buffer ));
    printk((char*)( 6 + TASK_COMM_LEN/4 + MAX_LENGTH/4 + (int*)buffer ));

    netlink_sendmsg(buffer, size);
    return 0;
}

int AuditWrite(struct pt_regs *regs, char * pathname, int ret)
{
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    char *fd_name = NULL;
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("write, Info: fullname is  %s \t; Auditpath is  %s ; fd is %d", fullname, AUDITPATH, regs->di);

    char ac_Buf[128];
    struct file * pst_File = NULL;
    //取出FD对应struct file并检验
    pst_File = fget(regs->di);
    int file_size = pst_File->f_inode->i_size; //文件大小
    if (NULL != pst_File)
    {
        //取出FD对应文件路径及文件名并检验
        fd_name = d_path(&(pst_File->f_path), ac_Buf, sizeof(ac_Buf));
        //fget(),fput()成对
        fput(pst_File);
    }

    strncpy(commandname,current->comm,TASK_COMM_LEN);

    size = strlen(fd_name) + 16 + TASK_COMM_LEN + 1 + PATH_MAX;
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    //int类型占用四个字节
    *((int*)buffer) = cred->uid.val; ;  //uid
    *((int*)buffer + 1) = current->pid;
    *((int*)buffer + 2) = regs->dx; // regs->dx: write buf size
    *((int*)buffer + 3) = ret;
    strcpy( (char*)( 4 + (int*)buffer ), commandname);
    strcpy( (char*)( 4 + TASK_COMM_LEN/4 + (int*)buffer ), fullname);
    strcpy( (char*)( 4 + TASK_COMM_LEN/4 + MAX_LENGTH/4 + (int*)buffer ), fd_name); //不确定是否可以

    printk((char*)( 4 + (int*)buffer ));
    printk((char*)( 4 + TASK_COMM_LEN/4 + (int*)buffer ));
    printk((char*)( 4 + TASK_COMM_LEN/4 + MAX_LENGTH/4 + (int*)buffer ));

    netlink_sendmsg(buffer, size);
    return 0;
}


int AuditClose(struct pt_regs *regs, char * pathname, int ret)
{
    char commandname[TASK_COMM_LEN];
    char fullname[PATH_MAX];
    unsigned int size;   // = strlen(pathname) + 32 + TASK_COMM_LEN;
    void *buffer; // = kmalloc(size, 0);
    char auditpath[PATH_MAX];
    char *fd_name = NULL;
    const struct cred *cred;

    memset(fullname, 0, PATH_MAX);
    memset(auditpath, 0, PATH_MAX);

    get_fullname(pathname, fullname);
    strcpy(auditpath, AUDITPATH);
    if (strncmp(fullname, auditpath, strlen(auditpath)) != 0)  
        return 1;
    printk("close, Info: fullname is  %s \t; Auditpath is  %s", fullname, AUDITPATH);
    
    strncpy(commandname,current->comm,TASK_COMM_LEN);
    size = strlen(fullname) + 16 + TASK_COMM_LEN + 1;
    
    buffer = kmalloc(size, 0);
    memset(buffer, 0, size);

    cred = current_cred();
    *((int*)buffer) = cred->uid.val; ;  //uid
    *((int*)buffer + 1) = current->pid;
    *((int*)buffer + 2) = regs->di; //文件描述字
    *((int*)buffer + 3) = ret;
    strcpy( (char*)( 4 + (int*)buffer ), commandname);
    strcpy( (char*)( 4 + TASK_COMM_LEN/4 +(int*)buffer ), fullname);
    
    printk((char*)( 4 + (int*)buffer ));
    printk((char*)( 4 + TASK_COMM_LEN/4 +(int*)buffer));
    
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
