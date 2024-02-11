#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define FLAG_LEN 15

long current_balance = 10000;
char flag[20];

void win(){
    printf("How is this possible?!?!?!?!\n");
    puts(flag);
}

long get_amount(){
    long amount;
    int success = scanf("%ld%*c", &amount);

    if(!success || amount < 0){
        printf("You need to provide a positive integer!\n");
        return -1;
    }
    return amount;
}

void withdraw(){
    long amount = get_amount();
    if(amount<0){
        puts("Withdraw failed!");
        return;
    }
    if(current_balance - amount < 0){
        puts("Hey, you can't have negative money!");
    } else {
        current_balance -= amount;
    }
}

void deposit(){
    long amount = get_amount();
    if(amount<0){
        puts("Deposit failed!");
        return;
    }
    current_balance += amount;
}

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    int fd = open("flag.txt", O_RDONLY);
    
    char option[2];
    flag[19] = 0;

    if(fd < 0){
        printf("Couldn't open flag file. Please contact admins\n");
        return 0;
    }

    long bytes_read = read(fd, flag, FLAG_LEN);
    if(bytes_read < 0){
        printf("Couldn't read flag. Please contact admins\n");
        return 0;
    }

    printf("Welcome to the most secure bank in the world!\n");
    while(1){
        printf("\n\nYour current balance is $%ld\n[1] Deposit Money\n[2] Withdraw Money\n[3] Quit\n\n", current_balance);

        if(current_balance < 0)
            win();

        //!
        gets(option);

        switch (option[0])
        {
        case '1':
            puts("Amount(positive integer):");
            deposit();
            break;
        case '2':
            puts("Amount(positive integer):");
            withdraw();
            break;
        case '3':
            printf("Bye!\n");
            return 0;
            break;
        default:
            printf("That not a valid option!\n");
            break;
        }
    }

    return 0;
}
