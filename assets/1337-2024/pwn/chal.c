// gcc chal.c -o chal
#include <stdio.h>

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);

    // the flag length is the same on the server
    char flag[48] = "maple{REDACTED_REDACTED_REDACTED_REDACTED_REDAC}";
    char buf[8];

    while(1) {
        printf("\nEnter something: ");
        scanf("%7s", buf);
        printf(buf);
    }
}
