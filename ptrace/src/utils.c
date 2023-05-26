#include "utils.h"

int _atoi(const char *s)
{
    int n = 0, is_neg = 0;
    while (u_isspace(*s))
        s++;
    switch (*s)
    {
    case '-':
        is_neg = 1;
    case '+':
        s++;
    }

	while (u_isdigit(*s))
        // (52 - 48) = 4
        n = 10 * n + (*s++ - '0');
    return is_neg ? -n : n;
}
size_t _strlen(const char *str)
{
	const char *s;
	for (s = str; *s; ++s);
	return (s - str);
}
char *vasprintfEx(const char *fmt, va_list args)
{
    char *p;

    if (vasprintf(&p, fmt, args) < 0)
        p = NULL;

    return p;
}

void _memcpy(void *destaddr, const void *srcaddr, int len)
{
  char *src_addr = (char *)srcaddr; 
  char *dest = (char *)destaddr;

  while (len-- > 0)
    *dest++ = *src_addr++;

}

char *asprintfEx(const char *fmt, ...)
{
    va_list args;
    char *p;

    va_start(args, fmt);
    p = vasprintfEx(fmt, args);
    va_end(args);

    return p;
}

void freestr_(char **p)
{
    free(*p);
    *p = NULL;
}

void printShellcode(const unsigned char* shellcode, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\n");
}


inline int u_isspace(char c) { return (c == ' ' || c == '\t' || c == '\n' || c == '\12'); }

inline int u_isdigit(char c) { return (c >= '0' && c <= '9'); }

inline int u_isupper(char c) { return (c >= 'A' && c <= 'Z'); }

inline int u_isalpha(char c) { return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')); }
