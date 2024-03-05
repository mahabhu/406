#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// 665 1689 1065

int bof(char *str)
{
    int arr[10];
    arr[5] = 7;
    char buffer[665];

    /* The following statement has a buffer overflow problem */ 
    strcpy(buffer, str);
    // printf("%s",buffer);
    return 1;
}

int foo(char *str)
{
    int arr[1689];
    arr[120] = 23;
    bof(str);
    return 1;
}

int secret()
{
    printf("Inside a Secret function\n");
}


int main(int argc, char **argv)
{
    char str[1065];
    FILE *badfile;
	
    bof("Normal Execution\n");
    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 1065, badfile);
    foo(str);

    printf("Try Again\n");
    return 1;
}

//0xffffd198 0xffffb708