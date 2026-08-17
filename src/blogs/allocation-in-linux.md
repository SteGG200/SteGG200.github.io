---
title: Allocator In Linux Kernel
tags:
  - Kernel Exploit
  - Guide
createdAt: 2026-08-14
---

# Buddy Allocator

- Buddy Allocator is a memory management allowing kernel to allocate physically contiguous memory block (page frame)
- Its strategy is to divide memory block into smaller blocks with power-of-two size.
- When a allocation request comes in, for example allocate 30, it recursively splits into 2 same smaller chunks, each one is called **buddy** of the other. It keeps doing that until it gets 32-size chunk, which is the smallest chunk but greater or equal to the requested size. This likes a full binary tree.
- When a chunk is released, it will merge with its buddy and release the parent chunk, except these cases:
  - The released chunk is the biggest size block. It has no more buddy
  - Its buddy chunk is still being used
  - Its buddy chunk is partially used - it has some in-used children chunks
- The Buddy Allocator keeps track of free areas via an array of `struct free_area`:

```c
struct free_area {
	struct list_head free_list[MIGRATE_TYPES];
	unsigned long nr_free;
};
```

- Page frames are allocated and released in kernel using the following functions:

```c

// "linux/gfp.h"
static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order);

// "linux/page_alloc.c"
void free_pages(unsigned long addr, unsigned int order);
```

- There are 4 types of Buddy System:
  - Binary Buddy System
  - Fibonacci Buddy System
  - Weighted Buddy System
  - Tertiary Buddy System
- The Buddy Allocator usually operates in minimum sizes of page frames (4 KB)

# Slab Allocator

- Slab Allocator is designed for fast allocation and release of small memory chunk via functions `kmalloc()` and `kfree()`. It sits directly on top of the **Buddy Allocator** to allocate memory efficiently.
- There are 3 kind of slab allocators:
  - **SLOB Allocator**: was the original slab allocator. It is optimized for low-memory embedded devices based on **first-fit** allocation algorithm. It was removed from Linux v6.4
  - **SLAB Allocator**: An improved version of SLOB allocator, aims to be "cache-friendly". It was removed from Linux v6.8
  - **SLUB Allocator**: A streamlined redesign that reduces complex queues and simplifies metadata. Therefore, it improves performance on modern multi-core systems
- These are main components of **Slab Allocator**:
  - **Object**: A individual memory chunk.
  - **Page Frame**: A contiguous block of physical page (4-KB size) received from **Buddy Allocator**.
  - **Slab**: A block of memory made of one or more physically contiguous pages. It contains equal-size Slab objects.
  - **Cache**: A set of Slab pages reserved for objects of a uniform size of specific type.

## Caches

- The slab allocator has 2 type of caches:
  - **Dedicated**: Created in kernel for commonly used objects (`mm_struct`, `vm_area_struct`). It allocates memory chunks with exact size of requested object corresponding to C `struct`
  - **Generic**: Used for general purpose caches, which are of power-of-two sizes
    ```sh
    $ sudo cat /proc/slabinfo
    slabinfo - version: 2.1
    # name      <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
    kmalloc-8k      208          224       8192       4             8 : tunables 0 0 0 : slabdata 56 56 0
    kmalloc-4k      623          656       4096       8             8 : tunables 0 0 0 : slabdata 82 82 0
    kmalloc-2k      1824         1920      2048       16            8 : tunables 0 0 0 : slabdata 120 120 0
    kmalloc-1k      2664         3040      1024       32            8 : tunables 0 0 0 : slabdata 95 95 0
    kmalloc-512     5339         5344      512        32            4 : tunables 0 0 0 : slabdata 167 167 0
    kmalloc-256     6815         6832      256        32            2 : tunables 0 0 0 : slabdata 214 214 0
    kmalloc-128     3064         3072      128        32            1 : tunables 0 0 0 : slabdata 96 96 0
    kmalloc-64      13961        15296     64         64            1 : tunables 0 0 0 : slabdata 239 239 0
    kmalloc-32      19020        19584     32         128           1 : tunables 0 0 0 : slabdata 153 153 0
    kmalloc-16      19920        22016     16         256           1 : tunables 0 0 0 : slabdata 86 86 0
    kmalloc-8       8940         9216      8          512           1 : tunables 0 0 0 : slabdata 18 18 0
    radix_tree_node 40068        46312     584        28            4 : tunables 0 0 0 : slabdata 1654 1654 0
    task_group      224          230       704        23            4 : tunables 0 0 0 : slabdata 10 10 0
    maple_node      4629         5440      256        32            2 : tunables 0 0 0 : slabdata 170 170 0
    mm_struct       240          252       1792       18            8 : tunables 0 0 0 : slabdata 14 14 0
    vmap_area       34269        38024     72         56            1 : tunables 0 0 0 : slabdata 679 679 0
    ```

- Here are function to allocate and release generic slab objects through slab allocator:

```c
// "include/linux/slab.h"
static __always_inline void *kmalloc(size_t size, gfp_t flags);
//allocates memory through slab allocator.

static inline void *kzalloc(size_t size, gfp_t flags);
//allocates memory (and zeroes it out like calloc() in libc) through the slab allocator.

void * __must_check krealloc(const void *, size_t, gfp_t);
//resize existing allocation.

void kfree(const void *);
//frees memory previously allocated.

void kzfree(const void *);
```

- To create an object from dedicated cache, it is required initializing a slab cache (`struct kmem_cache`)

## Local CPU and NUMA Node

- A **Local CPU** refers to the specific CPU core (or a logical thread) currently executing code. Its data is private for outside so no spinlocks required. Therefore, its latency is also low

- A **NUMA Node** is a hardware grouping of multiple CPU cores attached to dedicated physical RAM. Its data is shared among all CPU cores residing in that NUMA socket so it needs spinlock.

## SLAB Cache Management

- These are 3 main structure used by **SLAB Allocator** to manage caches:
  - `struct kmem_cache`
  - `struct kmem_cache_node`
  - `struct array_cache`

- Here is some fields of `struct kmem_cache` in source code of [Linux v6.7](https://elixir.bootlin.com/linux/v6.7/source/include/linux/slab_def.h#L12):

```c
struct kmem_cache {
	/* A local per-CPU cache using LIFO ordering.
	 * Its member `void *entry[]` holds an array of recently freed object pointers.
	 * It can contains freed object from multiple page frames.
	 * Handing out these pointer takes advantage of "warm cache"
	 * because they reside in the CPU's hardware cache
	 */
	struct array_cache __percpu *cpu_cache;
	...
	unsigned int gfporder; // Defines the order of pages per slab (2^n)
	gfp_t allocflags;

	size_t colour; // Cache colouring range
	unsigned int colour_off; // Colour offset
	unsigned int freelist_size;

	void (*ctor)(void *obj); // Constructor function for object

	const char *name;
	struct list_head list;
	int refcount;
	int object_size; // Byte size of objects stored in this cache
	int align;
	...
	/* Manage slabs per NUMA memory node by keeping 3 doubly linked-lists:
	 * - `struct list_head slabs_partial` contains pages frame that has both allocated and freed objects
	 * - `struct list_head slabs_full`: all objects inside each page frame are currently in used
	 * - `struct list_head slabs_free`: all objects inside each page frame are freed
	 */
	struct kmem_cache_node *node[MAX_NUMNODES];
};
```

- Note: Allocator always prioritize `array_cache` (Fast Path) over `kmem_cache_node` (Slow Path) when allocating or freeing an object.

## SLUB Cache Management

- **SLUB Allocator** simplified SLAB Management by removing complex per-CPU queues and full/free list queues. SLUB only manages a linked-list of objects in each slab page.
- Here is some fields of `struct kmem_cache` in source code of [Linux v7.1](https://elixir.bootlin.com/linux/v7.1/source/mm/slab.h#L198)

```c
struct kmem_cache {
	/* A per-CPU pointer to `struct slub_percpu_sheaves`,
	 * used by SLUB's sheaves fast-path allocation
	 */
	struct slub_percpu_sheaves __percpu *cpu_sheaves;

	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;  // Object size including metadata
	unsigned int object_size;  // Object size without metadata
	struct reciprocal_value reciprocal_size;
	unsigned int offset;  // Next pointer in free-list offset
	unsigned int sheaf_capacity; // Defines capacity held within a `slab_sheaf` array
	struct kmem_cache_order_objects oo;
	...
	/* Each element in this array holds a pointer to `struct kmem_cache_per_node` (per-node partial-slab list)
	 * and a `struct node_barn` holding freed sheaves/objecs for every NUMA node
	 */
	struct kmem_cache_per_node_ptrs per_node[MAX_NUMNODES];
};
```

- Here is `struct slub_percpu_sheaves`:

```c
struct slab_sheaf {
	union {
		struct rcu_head rcu_head;
		struct list_head barn_list;
		/* only used for prefilled sheafs */
		struct {
			unsigned int capacity;
			bool pfmemalloc;
		};
	};
	struct kmem_cache *cache;
	unsigned int size;
	int node; /* only used for rcu_sheaf */
	void *objects[];
};

struct slub_percpu_sheaves {
	local_trylock_t lock;
	/* Point to the primary active `slab_sheaf` containing a array of object pointers.
	 * Allocator pop from the top of this array without locks.
	 */
	struct slab_sheaf *main;
	/* A secondary `slab_sheaf`. When main become full or empty,
	 * it is swapped with main before enter `kmem_cache_per_node_ptrs`.
	 */
	struct slab_sheaf *spare;
	/* Collect object freed via `kfree_rcu()` in batches */
	struct slab_sheaf *rcu_free;
};
```

- Here is `struct kmem_cache_per_node_ptrs`:

```c
struct kmem_cache_per_node_ptrs {
	/* A shared pool holding full and empty slab_sheaf instances for that NUMA node.
	 * Allocator checks this (Medium Path) before check partial list of kmem_cache_node (Slow Path).
	 */
	struct node_barn *barn;
	/* This structure only holds a linkedlist tracking partial slabs */
	struct kmem_cache_node *node;
};
```

- The checking order of **SLUB Allocator** when allocating or releasing is:
  - `struct slub_percpu_sheaves -> main`
  - `struct slub_percpu_sheaves -> spare`
  - `struct node_barn`
  - `struct kmem_cache_node`

## About Slabs

- **SLAB/SLUB Allocator** manages the slabs using an internal metadata descriptor, `struct slab`. It is defined as an overlay on top of `struct page` which is associated with every physical page frame in the system.
- Here is `struct slab` in source code of [Linux v7.1](https://elixir.bootlin.com/linux/v7.1/source/mm/slab.h#L74):

```c
struct slab {
	memdesc_flags_t flags;

	/* Point back to `struct kmem_cache` that owns this slab */
	struct kmem_cache *slab_cache;
	union {
		struct {
			/* Links the slab into per-node partial list managed by cache*/
			struct list_head slab_list;
			/* Double-word boundary */
			/* An embedded struct tracks slab's internal allocation state
			 * which holds the `freelist` pointer
			 * with packed counter (`inuse`, `objects`, `frozen`).
			 * Therefore, they can be updated automatically
			 * via `cmpxchg`, avoiding ABA races
			 */
			struct freelist_counters;
		};
		/* Shared memory, used when a slab need to be freed via RCU */
		struct rcu_head rcu_head;
	};

	unsigned int __page_type;
	atomic_t __page_refcount;
#ifdef CONFIG_SLAB_OBJ_EXT
	unsigned long obj_exts;
#endif
};
```

# Reference

- https://www.geeksforgeeks.org/operating-systems/operating-system-allocating-kernel-memory-buddy-system-slab-system/
- https://hammertux.github.io/slab-allocator
