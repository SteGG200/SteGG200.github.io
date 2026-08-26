---
title: Linux Kernel Hacking Basics
tags:
  - Kernel Exploit
  - Guide
createdAt: 2026-08-14
---

# Goals

## Get root privilege

- payload:

```c
commit_creds(prepare_kernel_cred(0))
```

## Escape SECCOMP

- payload:

```c
current->thread_info.flags &= ~(1 << TIF_SECCOMP)
```

## Run single command

- payload:

```c
run_cmd("/path/to/command")
```

# Background

## Kernel Space & User Space

- Linux memory divides into 2 separated areas: **Kernel Space** and **User Space**
- User needs to ask the kernel for help by sending requests which is called **System Calls**
- On **x86-64** arch, after calling `syscall`, the CPU enters **kernel mode** and calls the `entry_SYSCALL_64()` function. It will then search and execute requested system call from `sys_call_table`

## Task

- Linux kernel doesn't distinguish between **Processes** and **Threads**, it defines them all as **Tasks** by calling `copy_process()` function

- When **tasks** are created, they are allocated a `task_struct` structure, one for each task

```c
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info              thread_info;
#endif
	unsigned int                    __state;
	/* saved state for "spinlock sleepers" */
	unsigned int                    saved_state;
	/*
	 * This begins the randomizable portion of task_struct. Only
	 * scheduling-critical items should be added above here.
	 */
	randomized_struct_fields_start
	void                            *stack;
	refcount_t                      usage;
	/* Per task flags (PF_*), defined further below: */
	unsigned int                    flags;
	unsigned int                    ptrace;
#ifdef CONFIG_SMP
	int                             on_cpu;
	struct __call_single_node       wake_entry;
	unsigned int                    wakee_flips;
	unsigned long                   wakee_flip_decay_ts;
	struct task_struct              *last_wakee;
	...
}
```

- `task_struct` stores most essential metadata and state information for a **task**
  - `pid_t pid` is the process ID
  - `pid_t tgid` is the thread group ID. All threads generated within a same parent process share identical **TGID** values.
  - `char comm[TASK_COMM_LEN]`: An array of characters that stores the executable binary of the task. Used to identify the task.
  - `struct list_head tasks`: A doubly linked-list of active tasks in the kernel.
  - `struct task_struct __rcu *parent`: Points to the task's parent task.
  - `struct list_head children`: A linked-list of all child tasks.
  - `struct mm_struct *mm`: Pointer to a struct **mm_struct** for the task's memory management.
  - `struct files_struct *files`: Pointer to **files_struct**, a struct that manages the files that the task `open()` has opened. This member manages the list of files that the task is opening and the state of each file.
  - `struct signal_struct *signal`: A pointer to a **signal_struct**, a struct containing information for handling signals. This handles the incomming signals.

- The `current` macro is a pointer to the `task_struct` struct of the task currently running on CPU.

## Memory Architecture

- Looking at the structure of `mm_struct`, it looks like this:

```c
struct mm_struct {
	struct {
		...
		unsigned long start_code, end_code, start_data, end_data;
		unsigned long start_brk, brk, start_stack;
		unsigned long arg_start, arg_end, env_start, env_end;
		...
	} __randomize_layout;
	/*
	 * The mm_cpumask needs to be at the end of mm_struct, because it
	 * is dynamically sized based on nr_cpu_ids.
	 */
	unsigned long cpu_bitmap[];
};
```

- `start_code` and `end_code` are about **code segment**
- `start_data` and `end_data` are about **data segment**
- `start_brk` and `brk` are about **heap segment**. `brk` can be incremented
- `start_stack` is the start address of the **stack segment**

- All above are belongs to user space. The main memory structures in the kernel are summarized below:
  - `0x0000000000000000 ~ 0x00007fffffffffff`: The virtual address of user space. Each process has its own independent area
  - `0xffff888000000000 ~ 0xffffc87fffffffff`: Direct mapping of all physical memory region
  - `0xffffc90000000000 ~ 0xffffe8ffffffffff`: `vmalloc` area. It is virtually contiguous (physicaly non-contiguous) allocations
  - `0xffffffff80000000 ~ 0xffffffff9fffffff`: The area where the kernel code is located.
  - `0xffffffffa0000000 ~ 0xfffffffffeffffff`: The area where the kernel modules are located.

- Other areas are **Vmemmap Region** and **KASAN Shadow Region**

- The above memory map corresponds to **4-level Page Tables** on **x86-64** arch, and its structure may vary depending on whenther or not the kernel has the `CONFIG_X86_5LEVEL` (5-level page tables)

# Reference

- https://santaclz.github.io/2023/11/03/Linux-Kernel-Exploitation-Getting-started-and-BOF.html
