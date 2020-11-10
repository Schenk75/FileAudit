#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>

/*
** module macros
*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("infosec-sjtu");
MODULE_DESCRIPTION("hook sys_call_table");


typedef void (* demo_sys_call_ptr_t)(void);
//原始的open
typedef asmlinkage long (*orig_openat_t)(struct pt_regs *regs);
//原始的read
typedef asmlinkage long (*orig_read_t)(struct pt_regs *regs);
//原始的close
typedef asmlinkage long (*orig_close_t)(struct pt_regs *regs);
//原始的write
typedef asmlinkage long (*orig_write_t)(struct pt_regs *regs);
//原始的kill
typedef asmlinkage long (*orig_kill_t)(struct pt_regs *regs);
//原始的chmod
typedef asmlinkage long (*orig_chmod_t)(struct pt_regs *regs);
//原始的mkdir
typedef asmlinkage long (*orig_mkdir_t)(struct pt_regs *regs);

demo_sys_call_ptr_t *get_sys_call_table(void);

//重载open
int AuditOpenat(struct pt_regs *, char * pathname, int ret);
//重载read
int AuditRead(struct pt_regs *, char * pathname, int ret);
//重载close
int AuditClose(struct pt_regs *, char * pathname, int ret);
//重载write
int AuditWrite(struct pt_regs *, char * pathname, int ret);
//重载kill
int AuditKill(struct pt_regs *, char * pathname, int ret);



void netlink_release(void);
void netlink_init(void);

demo_sys_call_ptr_t * sys_call_table = NULL;
//原始open地址
orig_openat_t orig_openat = NULL;
//原始read地址
orig_read_t orig_read = NULL;
//原始close地址
orig_close_t orig_close = NULL;
//原始write地址
orig_write_t orig_write = NULL;


unsigned int level;
pte_t *pte;

//挂载open
asmlinkage long hacked_openat(struct pt_regs *regs)
{
	long ret;
	char buffer[PATH_MAX];
    long nbytes;

  	nbytes = strncpy_from_user(buffer, (char*)regs->bx, PATH_MAX);

   	//printk("Info:   hooked sys_openat(), file name:%s(%ld bytes)",buffer,nbytes);

	ret = orig_openat(regs);

	AuditOpenat(regs,buffer,ret);

  	return ret;
}
//挂载read
asmlinkage long hacked_read(struct pt_regs *regs)
{
	long ret;
	char buffer[PATH_MAX];
    long nbytes;

  	nbytes = strncpy_from_user(buffer, (char*)regs->bx, PATH_MAX);
	ret = orig_read(regs);
	AuditRead(regs,buffer,ret);

  	return ret;
}
//挂载write
asmlinkage long hacked_write(struct pt_regs *regs)
{
	long ret;
	char buffer[PATH_MAX];
    long nbytes;

  	nbytes = strncpy_from_user(buffer, (char*)regs->bx, PATH_MAX);
	ret = orig_write(regs);
	AuditWrite(regs,buffer,ret);

  	return ret;
}
//挂载close
asmlinkage long hacked_close(struct pt_regs *regs)
{
	long ret;
	char buffer[PATH_MAX];
    long nbytes;

  	nbytes = strncpy_from_user(buffer, (char*)regs->bx, PATH_MAX);
	ret = orig_close(regs);
	AuditClose(regs,buffer,ret);
	return ret;
}

static int __init audit_init(void)
{
	sys_call_table = get_sys_call_table();
	printk("Info: sys_call_table found at %lx\n",(unsigned long)sys_call_table) ;

    //Hook Sys Call Openat
	//orig_openat = (orig_openat_t) sys_call_table[__NR_openat];
	//printk("Info:  orginal openat:%lx\n",(long)orig_openat);
	//Hook Sys Call Read
	//orig_read = (orig_read_t) sys_call_table[__NR_read];
	// //Hook Sys Call Close
	orig_close = (orig_close_t) sys_call_table[__NR_close];
	printk("Info:  orginal close:%lx\n",(long)orig_close);
	// orig_write = (orig_close_t) sys_call_table[__NR_write];
	// printk("Info:  orginal write:%lx\n",(long)orig_write);

	pte = lookup_address((unsigned long) sys_call_table, &level);
	// Change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));
	printk("Info: Disable write-protection of page with sys_call_table\n");

	// sys_call_table[__NR_openat] = (demo_sys_call_ptr_t) hacked_openat;
	// sys_call_table[__NR_read] = (demo_sys_call_ptr_t) hacked_read;
	sys_call_table[__NR_close] = (demo_sys_call_ptr_t) hacked_close;
	// sys_call_table[__NR_write] = (demo_sys_call_ptr_t) hacked_write;

	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
	printk("Info: sys_call_table hooked!\n");

	netlink_init();
	return 0;
}


static void __exit audit_exit(void)
{
    pte = lookup_address((unsigned long) sys_call_table, &level);
    set_pte_atomic(pte, pte_mkwrite(*pte));
	// sys_call_table[__NR_openat] = (demo_sys_call_ptr_t)orig_openat;
	// sys_call_table[__NR_read] = (demo_sys_call_ptr_t)orig_read;
	sys_call_table[__NR_close] = (demo_sys_call_ptr_t)orig_close;
	// sys_call_table[__NR_write] = (demo_sys_call_ptr_t)orig_write;
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    netlink_release();
}

module_init(audit_init);
module_exit(audit_exit);
