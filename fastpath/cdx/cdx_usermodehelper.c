/*
 * cdx_usermodehelper.c — Run userspace programs from kernel context
 *
 * FreeBSD equivalent of Linux's call_usermodehelper(UMH_WAIT_PROC).
 * Creates a new process via fork1(), execs the binary via kern_execve(),
 * and waits synchronously for it to exit via kern_wait().
 *
 * Pattern derived from FreeBSD sys/kern/init_main.c (create_init +
 * start_init), adapted for use from loadable kernel modules.
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/unistd.h>
#include <sys/imgact.h>
#include <sys/sched.h>
#include <sys/ucred.h>
#include <sys/wait.h>
#include <sys/syscallsubr.h>

/* Prototype (called from cdx_main_freebsd.c) */
int	cdx_call_usermodehelper(const char *path, char *const argv[],
	    char *const envp[], int *statusp);

/*
 * Arguments passed from cdx_call_usermodehelper() to cdx_umh_entry()
 * via cpu_fork_kthread_handler().  Lives on the caller's stack, which
 * remains valid because the caller blocks in kern_wait() while the
 * child reads these fields.
 */
struct umh_args {
	const char	*path;
	char *const	*argv;
	char *const	*envp;
	int		 argc;
	int		 envc;
};

/*
 * Child process entry point.  Runs in a new process created by fork1().
 * Builds exec arguments and calls kern_execve() to transition from
 * kernel to userspace.  On success (EJUSTRETURN), the thread returns
 * to userspace as the target binary.  On failure, the process exits.
 */
static void
cdx_umh_entry(void *arg)
{
	struct umh_args *ua = arg;
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct image_args args;
	struct vmspace *oldvmspace;
	int error, i;

	memset(&args, 0, sizeof(args));
	error = exec_alloc_args(&args);
	if (error != 0) {
		printf("cdx: umh: exec_alloc_args: %d\n", error);
		goto fail;
	}

	error = exec_args_add_fname(&args, ua->path, UIO_SYSSPACE);
	if (error != 0) {
		printf("cdx: umh: exec_args_add_fname: %d\n", error);
		exec_free_args(&args);
		goto fail;
	}

	for (i = 0; i < ua->argc; i++) {
		error = exec_args_add_arg(&args, ua->argv[i], UIO_SYSSPACE);
		if (error != 0) {
			printf("cdx: umh: exec_args_add_arg[%d]: %d\n",
			    i, error);
			exec_free_args(&args);
			goto fail;
		}
	}

	for (i = 0; i < ua->envc; i++) {
		error = exec_args_add_env(&args, ua->envp[i], UIO_SYSSPACE);
		if (error != 0) {
			printf("cdx: umh: exec_args_add_env[%d]: %d\n",
			    i, error);
			exec_free_args(&args);
			goto fail;
		}
	}

	/*
	 * Transition from kernel to userspace.  kern_execve() replaces
	 * this process's address space with the target binary.  On
	 * success it returns EJUSTRETURN — the thread resumes in
	 * userspace via fork_trampoline.
	 */
	memset(td->td_frame, 0, sizeof(*td->td_frame));
	oldvmspace = p->p_vmspace;
	error = kern_execve(td, &args, NULL, oldvmspace);

	if (error == EJUSTRETURN) {
		exec_cleanup(td, oldvmspace);
		return;		/* returns to userspace */
	}

	printf("cdx: umh: kern_execve %s: error %d\n", ua->path, error);

fail:
	kproc_exit(error != 0 ? error : EIO);
	/* NOTREACHED */
}

/*
 * cdx_call_usermodehelper — Run a userspace program synchronously.
 *
 * Creates a new process, execs the given binary, and blocks until
 * it exits.  Returns 0 on success (child ran and exited cleanly),
 * or errno on failure.
 *
 * This is the FreeBSD equivalent of Linux's
 * call_usermodehelper(path, argv, envp, UMH_WAIT_PROC).
 *
 * MUST NOT be called from interrupt context or with locks held.
 */
int
cdx_call_usermodehelper(const char *path, char *const argv[],
    char *const envp[], int *statusp)
{
	struct umh_args ua;
	struct fork_req fr;
	struct proc *newproc;
	struct thread *td2;
	int error, status, i;
	pid_t pid;

	/* Count argc and envc */
	ua.path = path;
	ua.argv = argv;
	ua.envp = envp;
	ua.argc = 0;
	ua.envc = 0;
	if (argv != NULL)
		for (i = 0; argv[i] != NULL; i++)
			ua.argc++;
	if (envp != NULL)
		for (i = 0; envp[i] != NULL; i++)
			ua.envc++;

	/*
	 * Create a new process via fork1(), matching the create_init()
	 * pattern from init_main.c.  RFFDG gives the child its own
	 * file descriptor table.  RFSTOPPED creates it stopped so we
	 * can set the entry point before it runs.  We omit RFMEM
	 * (unlike kproc_create) because kern_execve will replace the
	 * vmspace entirely.
	 */
	newproc = NULL;
	bzero(&fr, sizeof(fr));
	fr.fr_flags = RFFDG | RFPROC | RFSTOPPED;
	fr.fr_procp = &newproc;

	error = fork1(curthread, &fr);
	if (error != 0) {
		printf("cdx: umh: fork1 failed: %d\n", error);
		return (error);
	}

	pid = newproc->p_pid;

	/*
	 * Set the child's entry point to cdx_umh_entry, which will
	 * call kern_execve() to become the userspace binary.
	 */
	td2 = FIRST_THREAD_IN_PROC(newproc);
	cpu_fork_kthread_handler(td2, cdx_umh_entry, &ua);

	/* Make the child runnable */
	thread_lock(td2);
	TD_SET_CAN_RUN(td2);
	sched_add(td2, SRQ_BORING);

	/*
	 * Wait for the child to exit.  This blocks the current thread
	 * (the kldload caller) until dpa_app completes — equivalent
	 * to Linux's UMH_WAIT_PROC.
	 */
	error = kern_wait(curthread, pid, &status, 0, NULL);
	if (error != 0) {
		printf("cdx: umh: kern_wait (pid %d) failed: %d\n",
		    pid, error);
		return (error);
	}

	if (statusp != NULL)
		*statusp = status;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			printf("cdx: umh: %s exited with status %d\n",
			    path, WEXITSTATUS(status));
			return (EIO);
		}
		return (0);
	}

	if (WIFSIGNALED(status)) {
		printf("cdx: umh: %s killed by signal %d\n",
		    path, WTERMSIG(status));
		return (EIO);
	}

	printf("cdx: umh: %s: unexpected wait status 0x%x\n",
	    path, status);
	return (EIO);
}
