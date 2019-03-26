# Zerotask - Pwn (132 points, 73 solves)

Writeup by poortho

## Problem Description

`nc 111.186.63.201 10001`

[zerotask](./zerotask)
[libc](./libc-2.27.so)
[libcrypto](./libcrypto.so.1.0.0)

## Analysis

Looking at the binary, we are presented with 3 options:
```
1. Add a task
2. Delete a task
3. Run a task
```

Essentially, each task is a struct with data, data length, a task id, a pointer to the next task in the linked list, and a bunch of crypto stuff (key, iv, a pointer to a libcrypto struct).

When adding a struct, we can enter whatever data we want and choose to set the task to "encrypt" or "decrypt" as well as give the key and iv.

When deleting a task, the program correctly frees all components of the struct and removes it from the linked list.

However, the run task function is where we find our vulnerability - it turns out this is multi-threaded! On top of that, they nicely give us a `sleep(2)` between when we call run task and when the task actually runs.

Thus, our vulnerability is a race condition - in between when we call run task and when the task runs, we must modify the memory the task was called on to do everything.

But how exactly do we exploit this?

Initially, I tried simply freeing the task. This way, we could obtain a leak (as the program would try to encrypt a pointer on the free list). However, this fails, as `EVP_CIPHER_CTX_free` (the function used to free a libcrypto EVP struct) actually zeroes out the memory of the chunks, hence making our encrypt call invalid.

Then, I tried freeing and then reallocating the chunk, but this time setting our `data` to be a different size, thus the task would still use our freed chunk from before.

However, this also failed, as the thread reads our struct directly, meaning that it correctly accessed the updated data field from our reallocation.

The same thing applied to when I tried to allocate very small amounts of data in hopes of the program would encrypt past my data and into some pointers. This also failed as it uses `task->data_length` right before it performs the encryption/decryption.

And now, here's how I finally figured out how to properly exploit this:

If we look carefully, we see that the wrapper for `read` that they use is as follows:

```c
__int64 __fastcall read_wrapper(__int64 a1, unsigned int a2)
{
  __int64 result; // rax@6
  __int64 v3; // rcx@6
  char buf; // [sp+1Fh] [bp-11h]@2
  int i; // [sp+20h] [bp-10h]@1
  int v6; // [sp+24h] [bp-Ch]@2
  __int64 v7; // [sp+28h] [bp-8h]@1

  v7 = *MK_FP(__FS__, 40LL);
  for ( i = 0; i < (signed int)a2; ++i )
  {
    v6 = read(0, &buf, 1uLL);
    if ( !v6 )
      exit(1);
    *(_BYTE *)(a1 + i) = buf;
  }
  result = (unsigned int)i;
  v3 = *MK_FP(__FS__, 40LL) ^ v7;
  return result;
}
```

It actually reads our input character by character! We can use this to update `data_length` without updating `data` fully! (Actually, now that I'm making this writeup, this doesn't even matter - we could just not give any input at all. Oops.)

Thus, our plan is as follows:
1. Create a task
2. Run the task
3. Before the task runs, free the task
4. Reallocate the task again, with the same size field, but pause before giving the actual data.

By doing this, the code will encrypt past our written data. If we perform this with tcache, we can obtain a heap leak. If we perform this with large bins (size > 0x410), we can obtain a libc leak.

But now, how do we get control of the program?

For this, we need to look into a little how the libcrypto struct works.

Looking at our memory, we have
```asm
0x555555758270:	0x0000000000000000	0x0000000000000081 <- task struct that we created
0x555555758280:	0x00005555557584c0	0x0000000000000010 <- pointer to data and length of data
0x555555758290:	0x0000000000000001	0x0000000000000000 <- check if task is to encrypt or decrypt
0x5555557582a0:	0x0000000000000000	0x0000000000000000 <- key and iv (set to 0 here)
0x5555557582b0:	0x0000000000000000	0x0000000000000000
0x5555557582c0:	0x0000000000000000	0x0000000000000000
0x5555557582d0:	0x0000000000000000	0x0000555555758300 <- pointer to libcrypto stuff
0x5555557582e0:	0x0000000000000002	0x00005555557588e0 <- next task 
0x5555557582f0:	0x0000000000000000	0x00000000000000b1 <- libcrypto stuff
0x555555758300:	0x00007ffff7b98620	0x0000000000000000
0x555555758310:	0x0000000000000001	0x0000000000000000
0x555555758320:	0x0000000000000000	0x5c76b51fb5e3e1d0
0x555555758330:	0x1a8aebd57a0e788b	0x1010101010101010
0x555555758340:	0x1010101010101010	0x0000000000000000
0x555555758350:	0x0000000000000000	0x0000000000000000
0x555555758360:	0x0000000000000000	0x0000000000000020
0x555555758370:	0x0000000000000000	0x00005555557583b0 <- pointer to more libcrypto stuff
0x555555758380:	0x0000000f00000000	0x0000000000000000
0x555555758390:	0x0000000000000000	0x0000000000000000
0x5555557583a0:	0x0000000000000000	0x0000000000000111 <- more libcrypto stuff
0x5555557583b0:	0x0000000000000000	0x0000000000000000
0x5555557583c0:	0x0000000000000000	0x0000000000000000
0x5555557583d0:	0x6363636263636362	0x6363636263636362
0x5555557583e0:	0xfbfbfbaafbfbfbaa	0xfbfbfbaafbfbfbaa
0x5555557583f0:	0xac0f0f0dcf6c6c6f	0xac0f0f0dcf6c6c6f
0x555555758400:	0x917676d76a8d8d7d	0x917676d76a8d8d7d
0x555555758410:	0x6de25b5ec1ed5453	0x0e81383ca28e3731
0x555555758420:	0x50f7fc41c1818a96	0xab0c07eb3a7a713c
0x555555758430:	0x456df1c0288faa9e	0xe962fecde7e3c6f1
0x555555758440:	0x8fdccd6adf2b312b	0x1eaabbbdb5a6bc56
0x555555758450:	0x1790f7a452fd0664	0x1911cf98f0733155
0x555555758460:	0x847576070ba9bb6d	0x2f7971ec31d3ca51
0x555555758470:	0x8b7847439ce8b0e7	0x621ab98e7b0b7616
0x555555758480:	0x257e9b73a10bed74	0x3bd420ce14ad5122
0x555555758490:	0x9c72bf53170af810	0x856370cbe779c945
0x5555557584a0:	0x000000000000000d	0x00007ffff780ff00
0x5555557584b0:	0x00007ffff78126c0	0x0000000000000021 <- our data chunk
0x5555557584c0:	0x0000000000000000	0x0000000000000000
```

So, I was too lazy to really read up on how the libcrypto structs worked, so instead, I snooped around on their data structures.

Specifically, I looked at pointers to see if any of them pointed to functions.
```asm
gef➤  x/30i 0x00007ffff780ff00
   0x7ffff780ff00:	movups xmm2,XMMWORD PTR [rdi]
   0x7ffff780ff03:	mov    eax,DWORD PTR [rdx+0xf0]
   0x7ffff780ff09:	movups xmm0,XMMWORD PTR [rdx]
   0x7ffff780ff0c:	movups xmm1,XMMWORD PTR [rdx+0x10]
   0x7ffff780ff10:	lea    rdx,[rdx+0x20]
   0x7ffff780ff14:	xorps  xmm2,xmm0
   0x7ffff780ff17:	aesenc xmm2,xmm1
   0x7ffff780ff1c:	dec    eax
   0x7ffff780ff1e:	movups xmm1,XMMWORD PTR [rdx]
   0x7ffff780ff21:	lea    rdx,[rdx+0x10]
   0x7ffff780ff25:	jne    0x7ffff780ff17
   0x7ffff780ff27:	aesenclast xmm2,xmm1
   0x7ffff780ff2c:	pxor   xmm0,xmm0
   0x7ffff780ff30:	pxor   xmm1,xmm1
   0x7ffff780ff34:	movups XMMWORD PTR [rsi],xmm2
   0x7ffff780ff37:	pxor   xmm2,xmm2
   0x7ffff780ff3b:	repz ret 
   0x7ffff780ff3d:	nop    DWORD PTR [rax]
   0x7ffff780ff40:	movups xmm2,XMMWORD PTR [rdi]
   0x7ffff780ff43:	mov    eax,DWORD PTR [rdx+0xf0]
   0x7ffff780ff49:	movups xmm0,XMMWORD PTR [rdx]
   0x7ffff780ff4c:	movups xmm1,XMMWORD PTR [rdx+0x10]
   0x7ffff780ff50:	lea    rdx,[rdx+0x20]
   0x7ffff780ff54:	xorps  xmm2,xmm0
   0x7ffff780ff57:	aesdec xmm2,xmm1
   0x7ffff780ff5c:	dec    eax
   0x7ffff780ff5e:	movups xmm1,XMMWORD PTR [rdx]
   0x7ffff780ff61:	lea    rdx,[rdx+0x10]
   0x7ffff780ff65:	jne    0x7ffff780ff57
   0x7ffff780ff67:	aesdeclast xmm2,xmm1
gef➤  x/30i 0x00007ffff78126c0
   0x7ffff78126c0:	test   rdx,rdx
   0x7ffff78126c3:	je     0x7ffff7812ffe
   0x7ffff78126c9:	mov    r10d,DWORD PTR [rcx+0xf0]
   0x7ffff78126d0:	mov    r11,rcx
   0x7ffff78126d3:	test   r9d,r9d
   0x7ffff78126d6:	je     0x7ffff7812780
   0x7ffff78126dc:	movups xmm2,XMMWORD PTR [r8]
   0x7ffff78126e0:	mov    eax,r10d
   0x7ffff78126e3:	cmp    rdx,0x10
   0x7ffff78126e7:	jb     0x7ffff781274f
   0x7ffff78126e9:	sub    rdx,0x10
   0x7ffff78126ed:	jmp    0x7ffff78126f0
   0x7ffff78126ef:	nop
   0x7ffff78126f0:	movups xmm3,XMMWORD PTR [rdi]
   0x7ffff78126f3:	lea    rdi,[rdi+0x10]
   0x7ffff78126f7:	movups xmm0,XMMWORD PTR [rcx]
   0x7ffff78126fa:	movups xmm1,XMMWORD PTR [rcx+0x10]
   0x7ffff78126fe:	xorps  xmm3,xmm0
   0x7ffff7812701:	lea    rcx,[rcx+0x20]
   0x7ffff7812705:	xorps  xmm2,xmm3
   0x7ffff7812708:	aesenc xmm2,xmm1
   0x7ffff781270d:	dec    eax
   0x7ffff781270f:	movups xmm1,XMMWORD PTR [rcx]
   0x7ffff7812712:	lea    rcx,[rcx+0x10]
   0x7ffff7812716:	jne    0x7ffff7812708
   0x7ffff7812718:	aesenclast xmm2,xmm1
   0x7ffff781271d:	mov    eax,r10d
   0x7ffff7812720:	mov    rcx,r11
   0x7ffff7812723:	movups XMMWORD PTR [rsi],xmm2
   0x7ffff7812726:	lea    rsi,[rsi+0x10]
gef➤  x/30i 0x00007ffff7b98620
   0x7ffff7b98620:	stos   DWORD PTR es:[rdi],eax
   0x7ffff7b98621:	add    DWORD PTR [rax],eax
   0x7ffff7b98623:	add    BYTE PTR [rax],dl
   0x7ffff7b98625:	add    BYTE PTR [rax],al
   0x7ffff7b98627:	add    BYTE PTR [rax],ah
   0x7ffff7b98629:	add    BYTE PTR [rax],al
   0x7ffff7b9862b:	add    BYTE PTR [rax],dl
   0x7ffff7b9862d:	add    BYTE PTR [rax],al
   0x7ffff7b9862f:	add    BYTE PTR [rdx],al
   0x7ffff7b98631:	adc    BYTE PTR [rax],al
   0x7ffff7b98633:	add    BYTE PTR [rax],al
   0x7ffff7b98635:	add    BYTE PTR [rax],al
   0x7ffff7b98637:	add    al,ah
   0x7ffff7b98639:	outs   dx,BYTE PTR ds:[rsi]
   0x7ffff7b9863a:	mov    edi,esi
   0x7ffff7b9863c:	(bad)  
   0x7ffff7b9863d:	jg     0x7ffff7b9863f
   0x7ffff7b9863f:	add    BYTE PTR [rax-0x87692],dh
   0x7ffff7b98645:	jg     0x7ffff7b98647
   0x7ffff7b98647:	add    BYTE PTR [rax],al
   0x7ffff7b98649:	add    BYTE PTR [rax],al
   0x7ffff7b9864b:	add    BYTE PTR [rax],al
   0x7ffff7b9864d:	add    BYTE PTR [rax],al
   0x7ffff7b9864f:	add    BYTE PTR [rax],cl
   0x7ffff7b98651:	add    DWORD PTR [rax],eax
   0x7ffff7b98653:	add    BYTE PTR [rax],al
   0x7ffff7b98655:	add    BYTE PTR [rax],al
   0x7ffff7b98657:	add    BYTE PTR [rax],al
   0x7ffff7b98659:	add    BYTE PTR [rax],al
   0x7ffff7b9865b:	add    BYTE PTR [rax],al
```

Unfortunately, none of these really look like proper function calls.

However, if we instead look at the hex data of the last address, we see:
```asm
gef➤  x/10gx 0x00007ffff7b98620
0x7ffff7b98620:	0x00000010000001ab	0x0000001000000020
0x7ffff7b98630:	0x0000000000001002	0x00007ffff7896ee0
0x7ffff7b98640:	0x00007ffff7896eb0	0x0000000000000000
0x7ffff7b98650:	0x0000000000000108	0x0000000000000000
0x7ffff7b98660:	0x0000000000000000	0x0000000000000000
```

And if we view _these_ pointers, we get:
```asm
gef➤  x/10i 0x00007ffff7896ee0
   0x7ffff7896ee0:	push   rbp
   0x7ffff7896ee1:	push   rbx
   0x7ffff7896ee2:	mov    rax,rsi
   0x7ffff7896ee5:	sub    rsp,0x8
   0x7ffff7896ee9:	mov    rdx,QWORD PTR [rdi]
   0x7ffff7896eec:	mov    esi,DWORD PTR [rdi+0x68]
   0x7ffff7896eef:	mov    rbp,QWORD PTR [rdi+0x78]
   0x7ffff7896ef3:	mov    rdi,rax
   0x7ffff7896ef6:	mov    rbx,QWORD PTR [rdx+0x10]
   0x7ffff7896efa:	shl    esi,0x3
gef➤  x/10i 0x00007ffff7896eb0
   0x7ffff7896eb0:	sub    rsp,0x8
   0x7ffff7896eb4:	mov    rax,rdx
   0x7ffff7896eb7:	mov    r9d,DWORD PTR [rdi+0x10]
   0x7ffff7896ebb:	mov    rdx,rcx
   0x7ffff7896ebe:	mov    rcx,QWORD PTR [rdi+0x78]
   0x7ffff7896ec2:	lea    r8,[rdi+0x28]
   0x7ffff7896ec6:	mov    rdi,rax
   0x7ffff7896ec9:	call   0x7ffff78126c0
   0x7ffff7896ece:	mov    eax,0x1
   0x7ffff7896ed3:	add    rsp,0x8
```

These look alot more promising - in fact, the first one is basically exactly what the beginning of a function looks like!

So it looks like the libcrypto chunk of size `0xb1` has a pointer to a vtable of some sort, which has poiners to functions we can modify.

So now, we want to forge this `0xb1` struct to our own data struct. We do this as follows:

1. Create task 1 with the data being the forged vtable (basically, copy everything exactly but change the function pointer to `one_gadget`)
2. Create task 2
3. Create task 3
4. Run task 2
5. Delete task 2
6. Delete task 3
7. Add task 4 (this will be where task 3 was) but set the size of your data to be 0xb1, and forge the libcrypto struct (simply set the pointer to the vtable to be your forged vtable from task 1)

When the task runs, it should jump to one_gadget and we have a shell!

And thus, we have our flag: `flag{pl4y_w1th_u4F_ev3ryDay_63a9d2a26f275685665dc02b886b530e}`

Full solve script [here](./zerotask.py).