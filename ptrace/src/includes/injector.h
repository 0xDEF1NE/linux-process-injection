#ifndef __INJECTOR_DEF1NE__
#define __INJECTOR_DEF1NE__

#define _GNU_SOURCE 

#define PID_BUFFER_LENGTH 0x40 // 64
#define DEFAULT_PID_MAX 0x8000 /* 32768 - fallback value */

#define PROC_SYS_KERNEL_PID_MAX_PATH "/proc/sys/kernel/pid_max"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "utils.h"

/* Contains the permissions and address of the section with r-xp permissions */
typedef struct proc_pid_maps
{
    uint8_t permissions;
    long address;
} proc_maps_t;


int ptrace_setregs(pid_t pid, struct user_regs_struct *regs);

/**
 * ptrace_getregs - Get the register values of a process using PTRACE_GETREGS
 * @pid: Process ID of the target process
 * This function retrieves the register values of the specified process identified by @pid
 * using the PTRACE_GETREGS command. It allocates memory for the register structure and returns
 * a pointer to the structure containing the register values.
 * Return: Pointer to the struct user_regs_struct containing the register values,
 */
struct user_regs_struct *ptrace_getregs(pid_t pid);

/**
 * ptrace_attach - Attach to a process using PTRACE_ATTACH
 * @pid: Process ID of the target process to attach to
 * This function attaches to the specified process identified by @pid using the PTRACE_ATTACH command.
 * It waits for the process to receive a SIGTRAP signal indicating successful attachment.
 * Return: 0 on success, exits with failure status on error
 */
int ptrace_attach(pid_t pid);

/**
 * get_mem_perms - Get memory section with r-xp permissions
 * @line: The line of text containing memory permissions.
 * This function extracts the memory permissions from a line of text and returns them as a uint8_t value.
 * The line is expected to contain a specific format where the permissions are represented by specific characters.
 * The function checks the characters at specific offsets and calculates the corresponding permission value.
 * The resulting permission value is then returned.
 * Return: The memory permissions as a uint8_t value.
 */
uint8_t get_mem_perms(char *line);

/**
 * get_mem_addr - Retrieve memory address from a buffer.
 * @buffer: The input buffer containing the memory address.
 * This function extracts the memory address from the provided buffer.
 * It searches for the first occurrence of a hyphen ('-') character and copies the preceding characters into a separate buffer.
 * The extracted string is then converted to a long integer using the base 16 (hexadecimal) representation.
 * Return: The memory address as a long integer.
 */
long get_mem_addr(char *buffer);

/**
 * retrieve_maxPID_value - Retrieves the maximum PID value from the system.
 * This function reads the maximum PID value from the file /proc/sys/kernel/pid_max and returns it as an unsigned integer.
 * If the file cannot be opened or read, or if the value cannot be parsed, it returns a default maximum PID value.
 * Return: The maximum PID value if successfully retrieved, otherwise a default value.
 */
unsigned int retrieve_maxPID_value();

/**
 * proc_mappings - Retrieve process memory mappings.
 * @pid: The process ID of the target process.
 * This function retrieves the memory mappings of a process identified by @pid.
 * It reads the contents of the "/proc/<pid>/maps" file, extracts the relevant information,
 * and stores it in a proc_maps_t structure.
 * The function iterates over each line in the file, determines the memory permissions,
 * and checks if the permissions match a specific value.
 * If a match is found, it retrieves the memory address and returns the corresponding proc_maps_t structure.
 * Return: A proc_maps_t structure containing the memory mapping information, or NULL if an error occurs.
 */
proc_maps_t *proc_mappings(pid_t pid);

/**
 * ptrace_poketext - Write a buffer of data to the memory of a process using PTRACE_POKETEXT
 * @pid: Process ID of the target process
 * @address: Memory address where the data will be written
 * @payload: Pointer to the buffer containing the data to be written
 * @len_buffer: Length of the buffer in bytes
 * This function writes a buffer of data to the memory of a specific process indicated by the process ID (@pid)
 * using the PTRACE_POKETEXT command. The data is written in blocks of 8 bytes, starting from the memory address (@address).
 * The buffer containing the data is pointed to by @payload, and the length of the buffer is specified by @len_buffer.
 * Return: 0 on success, exits with failure status on error
 */
int ptrace_poketext(pid_t pid, long address, unsigned long *buffer, size_t len_buffer);

/**
 * file2buf - Read a file and store its content in a buffer
 * @fpath: The path of the file to be read
 * @buffer: Pointer to the buffer where the file content will be stored
 * @buffer_len: Pointer to the variable to store the length of the buffer
 * This function reads the content of a file specified by @fpath and stores it in a buffer pointed
 * to by @buffer. The length of the buffer is stored in the variable pointed to by @buffer_len.
 * Return: 0 in success
 */
int file2buf(const char* fpath, unsigned char** buffer, size_t* buffer_len);

#endif
