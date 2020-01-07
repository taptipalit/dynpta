#include <stdbool.h>
#include <string.h>


typedef _Bool uint1_t;

typedef unsigned long size_t;

void internal_memset(void *s, char c, size_t n, uint1_t isVolatile) __attribute__((used));
int internal_memcmp(const void *s1, const void *s2, size_t n) __attribute__((used));
void internal_memcpy(void *dest, const void *src, size_t n, uint1_t isVolatile) __attribute__((used));
int internal_strlen(const char *s) __attribute__((used));
char* internal_strcat(char* destination, const char* source) __attribute__((used));
char* internal_strcpy(char* destination, const char* source) __attribute__((used));
int internal_strcmp(const char *X, const char *Y) __attribute__((used));
char* internal_strstr(const char *str, const char *substr) __attribute__((used));


void internal_memset(void *s, char c, size_t n, uint1_t isVolatile) {
    while (n > 0) {
        *(char *) s = c;
        s++;
        n--;
    }
}

int internal_memcmp(const void *s1, const void *s2, size_t n) {
    if(!n) {
        return 0;
    }
    while(--n && (*(char *)s1 == *(char *)s2)) {
        s1 = (char *)s1 + 1;
        s2 = (char *)s2 + 1;
    }
    return ( *((unsigned char *)s1) - *((unsigned char *)s2));
}

void internal_memcpy(void *dest, const void *src, size_t n, uint1_t isVolatile) {
    while (n > 0) {
        *(char*) dest = *(char *) src;
        dest++;
        src++;
        n--;
    }
}

int internal_strlen(const char *s) {
    int len = 0;
    while (*s != '\0') {
        len++;
        s++;
    }
    return len;
}

char* internal_strcat(char* destination, const char* source) {
	// make ptr point to the end of destination string
	char* ptr = destination + internal_strlen(destination);

	// Appends characters of source to the destination string
	while (*source != '\0')
		*ptr++ = *source++;

	// null terminate destination string
	*ptr = '\0';

	// destination is returned by standard strcat()
	return destination;
}


char* internal_strcpy(char* destination, const char* source)
{
	// return if no memory is allocated to the destination
	if (destination == NULL)
		return NULL;

	// take a pointer pointing to the beginning of destination string
	char *ptr = destination;
	
	// copy the C-string pointed by source into the array
	// pointed by destination
	while (*source != '\0')
	{
		*destination = *source;
		destination++;
		source++;
	}

	// include the terminating null character
	*destination = '\0';

	// destination is returned by standard strcpy()
	return ptr;
}

// Function to implement strcmp function
int internal_strcmp(const char *X, const char *Y)
{
	while(*X)
	{
		// if characters differ or end of second string is reached
		if (*X != *Y)
			break;

		// move to next pair of characters
		X++;
		Y++;
	}

	// return the ASCII difference after converting char* to unsigned char*
	return *(const unsigned char*)X - *(const unsigned char*)Y;
}


char* internal_strstr(const char *str, const char *substr)
{
	  while (*str) 
	  {
		    char *Begin = str;
		    char *pattern = substr;
		    
		    // If first character of sub string match, check for whole string
		    while (*str && *pattern && *str == *pattern) 
			{
			      str++;
			      pattern++;
		    }
		    // If complete sub string match, return starting address 
		    if (!*pattern)
		    	  return Begin;
		    	  
		    str = Begin + 1;	// Increament main string 
	  }
	  return NULL;
}

