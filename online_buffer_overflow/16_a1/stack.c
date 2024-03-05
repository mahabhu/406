
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// 26 699 831

int foo(char *str)
{
    int arr[26];
    char buffer[703];

    /* The following statement has a buffer overflow problem */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char str[831];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 831, badfile);
    foo(str);

    printf("Try Again\n");
    return 1;
}

