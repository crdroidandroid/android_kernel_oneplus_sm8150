#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <linux/types.h>

#include "runtime/ksud.h"

#include <linux/jump_label.h>

extern struct static_key_true ksu_su_compat_enabled;

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

// Handler functions exported for hook_manager
int ksu_handle_faccessat_sucompat(int *dfd, const char __user **filename_user,
				int *mode, int *__unused_flags);
int ksu_handle_stat_sucompat(int *dfd, const char __user **filename_user, int *flags);
long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, const struct pt_regs *regs);
long ksu_handle_execveat_sucompat_user(const char __user **filename_user, int orig_nr, const struct pt_regs *regs);
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *argv_user, void *envp_user, int *flags);
#ifdef CONFIG_KSU_SUSFS
int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,
			 int *__unused_flags);
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);
int ksu_handle_execveat_init(struct filename *filename,
			     struct user_arg_ptr *argv_user,
			     struct user_arg_ptr *envp_user);
int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr,
				      void *argv_user, void *envp_user,
				      int *flags, int *retval);
#endif

#endif