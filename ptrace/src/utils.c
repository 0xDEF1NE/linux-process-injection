#include "utils.h"

/**
 * Converte um ponteiro para char em um inteiro
 * Retorna o inteiro convertido.
 */
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
    /* Compute n as a negative number to avoid overflow on INT_MIN */
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

    // Se vasprintf() falhar GARANTE que retornará NULL.
    if (vasprintf(&p, fmt, args) < 0)
        p = NULL;

    return p;
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

/**
 * Verifica se o caracter é um ' ', '\t', '\n' ou '\12'
 * retorna 1 caso seja falso
 */
inline int u_isspace(char c) { return (c == ' ' || c == '\t' || c == '\n' || c == '\12'); }

/**
 * Verifica se o numero é maior que 0 e menor que 9
 * retorna 1 caso seja falso
 */
inline int u_isdigit(char c) { return (c >= '0' && c <= '9'); }

/**
 * Verifica se o caractere é uppercase
 * retorna 1 caso seja falso
 */
inline int u_isupper(char c) { return (c >= 'A' && c <= 'Z'); }

/**
 * Verifica se o caractere é uppercase ou normal
 * retorna 1 caso seja falso
 */
inline int u_isalpha(char c) { return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')); }
