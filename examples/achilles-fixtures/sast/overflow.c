#include <stdio.h>
#include <string.h>

void copy_user(char *in) {
    char buf[16];
    gets(buf);
    strcpy(buf, in);
    sprintf(buf, "%s", in);
}
