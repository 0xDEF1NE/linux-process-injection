#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


int main() {
    pid_t PID = getpid();
    unsigned long long i = 1;
    while (i > 0) {
        printf("[%d] I'm the slave process :c (PID %d)\n", i, PID);
	sleep(1);
        i++;
    }
    
    return 0;
}
