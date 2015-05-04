#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/task_work.h>
#include <linux/tick.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/proc_fs.h>
#include <linux/cpu.h>
#include <linux/uio.h>

#include <linux/list.h>

#include <asm/desc.h>
#include <asm/uaccess.h>

#include "kmod.h"

#define KMOD_USERBUFLEN 1024

struct kmod_user_info {
	char buf[KMOD_USERBUFLEN];
	int len;
	int pid;
	int cpu;
};

static struct task_struct *kmod_task;
static struct kmod_user_list *nuser_list;
static struct kmod_proc_fs *kmod_proc;
unsigned int debug_couner;

ssize_t kmod_proc_write(struct file *filp, const char __user *buff, size_t size, loff_t *data)
{
	int len;
	mutex_lock(&kmod_proc->mtx);
	len = min((int) size, KMOD_PROC_BUFLEN);
	if (copy_from_user(kmod_proc->buf, buff, len)) {
		mutex_unlock(&kmod_proc->mtx);
		return -EFAULT;
	}
	kmod_proc->buf_len = len;
	kmod_proc->buf_tmp = kmod_proc->buf_len;
	mutex_unlock(&kmod_proc->mtx);
	return size;
}

ssize_t kmod_proc_read(struct file *filp, char __user *buff, size_t size, loff_t *data)
{
	int len;
	mutex_lock(&kmod_proc->mtx);
	len = min((int) size, kmod_proc->buf_len);
	if ((int) len > kmod_proc->buf_tmp) {
		len = kmod_proc->buf_tmp;
	}
	if (copy_to_user(buff, kmod_proc->buf, len)) {
		mutex_unlock(&kmod_proc->mtx);
		return -EFAULT;
	}
	if (len == 0) {
		kmod_proc->buf_tmp = kmod_proc->buf_len;
	} else {
		kmod_proc->buf_tmp -= len;
	}
	mutex_unlock(&kmod_proc->mtx);
	return len;
}

static const struct file_operations kmod_proc_fops = {
	.write = kmod_proc_write,
	.read = kmod_proc_read,
};

static ssize_t __kmod_write_proc_buf(char *buf, size_t size)
{
	int len;
	mutex_lock(&kmod_proc->mtx);
	len = min((int) size, KMOD_PROC_BUFLEN);
	memcpy(kmod_proc->buf, buf, len);
	kmod_proc->buf_len = len;
	kmod_proc->buf_tmp = kmod_proc->buf_len;
	mutex_unlock(&kmod_proc->mtx);
	return len;
}

int __kmod_proc_setup(void)
{
	kmod_proc = kmalloc(sizeof(struct kmod_proc_fs), GFP_KERNEL);
	if (!kmod_proc) {
		return -ENOMEM;
	}
	kmod_proc->buf_len = 0;
	kmod_proc->buf_tmp = kmod_proc->buf_len;
	mutex_init(&kmod_proc->mtx);
	kmod_proc->entry = proc_create("kmod", 0644, NULL, &kmod_proc_fops);
	if (kmod_proc->entry == NULL) {
		return -ENOMEM;
	}
	return 0;
}

void __kmod_proc_exit(void)
{
	if (kmod_proc && kmod_proc->entry) {
		proc_remove(kmod_proc->entry);
	}
	if (kmod_proc) {
		kfree(kmod_proc);
	}
}

static void kmod_main(void)
{
	struct kmod_user *user;
	struct list_head *pos, *next;
	list_for_each_safe(pos, next, &nuser_list->head) {
		user = (struct kmod_user *) container_of(pos, struct kmod_user, entity);
	}
}

static int kmod_thread(void *data)
{
	size_t len;
	char buf[1024];
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ*5);
		len = snprintf(buf, 1024, "%d\n", debug_couner++);
		len = __kmod_write_proc_buf(buf, len);
		kmod_main();
	}
	return 0;
}

static int kmod_open(struct inode *inode, struct file *file)
{
	KMODD("open");
	return 0;
}

static struct kmod_user *__kmod_register(void *mem, struct file *filp)
{
	struct kmod_user *user;
	user =  kmalloc(sizeof(struct kmod_user), GFP_KERNEL);
	if (user && filp) {
		list_add_tail(&user->entity, &nuser_list->head);
		user->mem = mem;
		filp->private_data = user;
	}
	return user;
}

static void __kmod_disregister(struct file *filp)
{
	struct kmod_user *user;
	user = filp->private_data;
	if (user) {
		free_pages((unsigned long) user->mem, KMOD_FIELD_ORDER);
		list_del(&user->entity);
		kfree(user);
	}
}

static int kmod_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int error;
	unsigned long off, va;
	u64 pa;
	struct kmod_user *user;
	int kmod_cpu = 1;
	void *field;
	field = (void *) __get_free_pages(GFP_ATOMIC | __GFP_ZERO, KMOD_FIELD_ORDER);
	if (!field) {
		KMODD("__get_free_pages failed");
		return -EINVAL;
	}
	if ((vma->vm_start & ~PAGE_MASK) || (vma->vm_end & ~PAGE_MASK)) {
		KMODD("vm_start = %lx vm_end = %lx", vma->vm_start, vma->vm_end);
		return -EINVAL;
	}

	for (va = vma->vm_start, off = vma->vm_pgoff;
	     va < vma->vm_end;
	     va += PAGE_SIZE, off++) {
		pa = virt_to_phys(field);
		error = remap_pfn_range(vma, va, pa >> PAGE_SHIFT, PAGE_SIZE, vma->vm_page_prot);
		if (error) {
			KMODD("remap_pfn_range error");
			return error;
		}
	}
	user = __kmod_register(field, filp);
	user->cpu = kmod_cpu;
	return 0;
}

long kmod_ioctl(struct file *filp, u_int cmd, u_long data)
{
	KMODD("%s", __func__);
	return 0;
}

static u_int kmod_poll(struct file * filp, struct poll_table_struct *pwait)
{
	KMODD("%s", __func__);
	return POLLIN | POLLOUT | POLLERR;
}

static int kmod_release(struct inode *inode, struct file *filp)
{
	if (filp) {
		__kmod_disregister(filp);
	}
	KMODD("release");
	return 0;
}

static struct file_operations kmod_fops = {
	.owner = THIS_MODULE,
	.open = kmod_open,
	.mmap = kmod_mmap,
	.unlocked_ioctl = kmod_ioctl,
	.poll = kmod_poll,
	.release = kmod_release,
};

struct miscdevice kmod_cdevsw = {
	MISC_DYNAMIC_MINOR,
	"kmod",
	&kmod_fops,
};

void __kmod_info_setup(void)
{
	nuser_list = kmalloc(sizeof(struct kmod_user_list), GFP_KERNEL);
	INIT_LIST_HEAD(&nuser_list->head);
}

void __kmod_info_exit(void)
{
	struct kmod_user *user;
	struct list_head *pos, *next;
	list_for_each_safe(pos, next, &nuser_list->head) {
		user = (struct kmod_user *) container_of(pos, struct kmod_user, entity);
		free_pages((unsigned long) user->mem, KMOD_FIELD_ORDER);
		kfree(user);
	}
	kfree(nuser_list);
}

void __kmod_start(void)
{
	debug_couner = 0;
	kmod_task = kthread_create(kmod_thread, NULL, "%s", "kmod");
	if (IS_ERR(kmod_task)) {
		KMODD("task error");
		return;
	}
	wake_up_process(kmod_task);
}

void __kmod_stop(void)
{
	kthread_stop(kmod_task);
}

void kmod_init(void)
{
	misc_register(&kmod_cdevsw);
	__kmod_proc_setup();
	__kmod_info_setup();
	__kmod_start();
}

void kmod_exit(void)
{
	__kmod_stop();
	__kmod_info_exit();
	__kmod_proc_exit();
	misc_deregister(&kmod_cdevsw);
}

struct task_struct *__get_task_by_pid(pid_t pid_int)
{
	struct task_struct *tsk;
	struct pid *pid;
	pid = find_get_pid(pid_int);
	if (!pid) {
		KMODD("No pid");
		return NULL;
	}
	tsk = get_pid_task(pid, PIDTYPE_PID);
	if (!tsk) {
		KMODD("No task");
		return NULL;
	}
	return tsk;
}

static int __init kmod_module_init(void)
{
	KMODD("KMOD Loaded");
	kmod_init();
	return 0;
}

static void __exit kmod_module_exit(void)
{
	kmod_exit();
	KMODD("KMOD Unloaded");
	return;
}
/* -------------------------------------------------------------------- */

module_init(kmod_module_init);
module_exit(kmod_module_exit);

MODULE_AUTHOR("Kenichi Yasukata");
MODULE_DESCRIPTION("Kernel Module Template");
MODULE_LICENSE("Dual BSD/GPL");
