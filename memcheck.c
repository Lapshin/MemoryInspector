/*
 * arm-none-linux-gnueabi-gcc -mapcs -mno-sched-prolog -fno-omit-frame-pointer  -D_GNU_SOURCE -fPIC -c memcheck.c -g;arm-none-linux-gnueabi-gcc -mapcs -mno-sched-prolog -fno-omit-frame-pointer  -D_GNU_SOURCE -shared -Wl,-soname,libmemcheck.so  -rdynamic -o libmemcheck.so memcheck.o -lc -nostartfiles; cp libmemcheck.so /tftpboot/
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <pthread.h>

static void *(*_malloc)(size_t n) = NULL;
static void *(*_calloc)(size_t num, size_t size) = NULL;
static void *(*_realloc)(void *ptr, size_t size) = NULL;
static void (*_free)(void *ptr) = NULL;
static char *(*_strdup)(const char *ptr) = NULL;
//static int (*_scandir)(const char *dirp, struct dirent ***namelist,int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **));)
//static void (*_syslog) (int __pri, const char *__fmt, ...) = NULL;




/*
 * !!!!!!!!!!!!!!!! USE code below and CFLAG -finstrument-functions for compile !!!!!!!!!!!!!!
 *
 * Then attach with GDB to your fuckin process and it will be stop on your condition.
 * Remember, the signal you sending has a little delay.
 *
 */

/*

#include <unistd.h>
#include <signal.h>
void __cyg_profile_func_enter (void *, void *) __attribute__((no_instrument_function));
void __cyg_profile_func_exit (void *, void *) __attribute__((no_instrument_function));
void __cyg_profile_func_enter(void *fn, void *caller){
	unsigned char *ptr__;
	int i;
	if( access( "/tmp/flag", F_OK ) != -1)
	{
		if(YOUR CONDITION)
		{
			raise(SIGSTOP);
		}
	}
}
void __cyg_profile_func_exit(void *fn, void *caller){
	unsigned char *ptr__;
	int i;
	if( access( "/tmp/flag", F_OK ) != -1)
	{
		if(ptr__[0] == 0x38 && ptr__[1] == 0x0E &&  ptr__[2] == 0xAA && ptr__[3] == 0xAA)
		{
			raise(SIGSTOP);
		}
	}
}
*/

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#define u8 unsigned char

static unsigned char start[] = {
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa
};

static unsigned char end[] = {
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa
};

#define BT_BUF_SIZE 100
void *buffer[BT_BUF_SIZE];
int size;
char **strings;

struct meminfo_s
{
	u8 *pointer;
	size_t size;
	unsigned lr;
	unsigned pc;
	u8 checked;
};

#define ARRAY_SIZE 50
static struct meminfo_s meminfo[ARRAY_SIZE] = {{0}};

#define LAST_FREE_ARRAY_SIZE 200
static int last_free_index = 0;
static struct meminfo_s last_free[LAST_FREE_ARRAY_SIZE] = {{0}};

//static void *(*old_realloc_hook) (void *ptr, size_t size);


void dump_all(void)
{
	int i;
	for(i = 0; i < ARRAY_SIZE; i++)
	{
		if(meminfo[i].pointer == NULL)
		{
			continue;
		}
		printf("pointer %p size %d lr 0x%X pc 0x%X\n", meminfo[i].pointer, meminfo[i].size, meminfo[i].lr, meminfo[i].pc);
	}

	printf("Last free pointers:\n");
	for(i = (last_free_index - 1); last_free[i].pointer != NULL ; i--)
	{
		if(i < 0)
		{
			i = LAST_FREE_ARRAY_SIZE - 1;
			if(last_free[i].pointer == NULL)
			{
				break;
			}
		}
		printf("pointer %p size %d lr 0x%X pc 0x%X\n", last_free[i].pointer, last_free[i].size, last_free[i].lr, last_free[i].pc);
	}
}

int set_to_list(void *ptr, void *ptr_in, unsigned lr, unsigned pc, size_t size, int request)
{
	int i, k;
	int found = 0;
	pthread_mutex_lock(&mutex);
	for(i = 0; i < ARRAY_SIZE; i++)
	{
		if(request != 0 && size == 0)
		{
			printf("*****************ptr_in %p ptr %p lr 0x%X pc 0x%X size %d\n", ptr_in, ptr, lr, pc, size);
		}


		/*ALLOCATE MEMORY*/
		if(found == 0 && (request == 1 && meminfo[i].pointer == NULL))
		{
			meminfo[i].pointer = ptr;
			meminfo[i].lr = lr;
			meminfo[i].pc = pc;
			meminfo[i].size = size;
			found = 1;
		}


		/*CHECK MEMORY*/
		if(meminfo[i].pointer != NULL)
		{
			if(meminfo[i].checked == 0 && (memcmp(meminfo[i].pointer, start, sizeof(start)) ||
					memcmp(meminfo[i].pointer + sizeof(start) + meminfo[i].size, end, sizeof(end))))
			{
				printf("!!!!!corrupted %p size %d!!!!\n", meminfo[i].pointer, meminfo[i].size);
				printf("\tlr 0x%X pc 0x%X", meminfo[i].lr, meminfo[i].pc);
				for(k = 0; k <  meminfo[i].size + sizeof(end) + sizeof(start); k++)
				{
					if(k % 40 == 0 || (k == sizeof(start)) || (k == (meminfo[i].size + sizeof(start))))
					{
						printf("\n");
					}
					printf("%02X ", meminfo[i].pointer[k]);
				}
				printf("\n");
				dump_all();
				meminfo[i].checked = 1;
			}
		}

		/*FREE MEMORY*/
		if(found == 0 && request == 0 && meminfo[i].pointer == ptr)
		{
			memcpy(&last_free[last_free_index], &meminfo[i], sizeof(struct meminfo_s));
			last_free_index++;
			if(last_free_index >= LAST_FREE_ARRAY_SIZE)
			{
				last_free_index = 0;
			}
			memset(&last_free[last_free_index], 0, sizeof(struct meminfo_s));
			memset(&meminfo[i], 0, sizeof(struct meminfo_s));
			found = 1;
		}

	}
	if(found == 0)
	{
		printf("ptr %p lr 0x%X pc 0x%X ARRAY_SIZE! request %d ptr_in %p %d size %d\n", ptr, lr, pc, request, ptr_in, ptr - ptr_in, size);
		dump_all();
		pthread_mutex_unlock(&mutex);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}
#define STACK_OCTETS 5
void *malloc(size_t n)
{
	unsigned stack;
	unsigned lr = *(&stack + STACK_OCTETS + 2);
	unsigned pc = *(&stack + STACK_OCTETS + 1);
	unsigned i;

	u8 *ptr;
	if (_malloc == NULL)
	{
		_malloc = (void *(*)(size_t n))dlsym(RTLD_NEXT, "malloc");
	}


	if( access( "/tmp/flag", F_OK ) != -1)
	{
		ptr = _malloc(n + sizeof(start) + sizeof(end));

		memcpy(ptr, start, sizeof(start));

		memcpy(ptr + n + sizeof(start), end, sizeof(end));
		set_to_list(ptr, NULL, lr, pc, n, 1);
		return ptr + sizeof(start);
	}
	else
	{
		ptr = _malloc(n);
//		printf("m %p %d 0x%X 0x%X\n", ptr, n, lr, pc);
	}

	return ptr;
}

void *realloc(void *ptr_in, size_t n)
{
	unsigned stack;
	unsigned lr = *(&stack + STACK_OCTETS + 2);
	unsigned pc = *(&stack + STACK_OCTETS + 1);
	unsigned i;

	u8 *ptr;

	if( access( "/tmp/flag", F_OK ) != -1 )
	{
		if (_malloc == NULL)
		{
			_malloc = (void *(*)(size_t n))dlsym(RTLD_NEXT, "malloc");
		}

		if (_free == NULL)
		{
			_free = (void (*)(void *ptr))dlsym(RTLD_NEXT, "free");
		}
		if(n != 0)
		{
			ptr = _malloc(n + sizeof(start) + sizeof(end));

			memcpy(ptr, start, sizeof(start));
			if(ptr_in != NULL)
			{
				memcpy(ptr + sizeof(start), ptr_in, n);
			}
			memcpy(ptr + n + sizeof(start), end, sizeof(end));
			set_to_list(ptr, NULL, lr, pc, n, 1);
		}


		if(ptr_in != NULL)
		{
			i = set_to_list(ptr_in - sizeof(start), ptr_in, lr, pc, n, 0);
			if(i == 0)
			{
				_free(ptr_in - sizeof(start));
			}
			else
			{
				_free(ptr_in);
			}
		}

		return ptr + sizeof(start);
	}
	else
	{
		if (_realloc == NULL)
		{
			_realloc = (void *(*)(void *ptr, size_t size))dlsym(RTLD_NEXT, "realloc");
		}
		ptr = _realloc(ptr_in, n);
//		printf("r %p %d 0x%X 0x%X\n", ptr, n, lr, pc);
	}
	return ptr;
}

void free(void *ptr)
{
	unsigned stack;
	unsigned lr = *(&stack + STACK_OCTETS + 2);
	unsigned pc = *(&stack + STACK_OCTETS + 1);
	unsigned i = 1;
//	printf("1\n");
	u8 *ptrRR = ptr;
	if(ptrRR != NULL)
	{
		if( access( "/tmp/flag", F_OK ) != -1 )
		{
			ptrRR = ptrRR - sizeof(start);

			i = set_to_list(ptrRR, NULL, lr, pc, 0, 0);
		}
	}

	if (_free == NULL)
	{
		_free = (void (*)(void *ptr))dlsym(RTLD_NEXT, "free");
//		old_realloc_hook = __realloc_hook;
//		__realloc_hook = my_realloc_hook;
	}
	if(i == 0)
	{
		_free(ptrRR);
	}
	else
	{
//		printf("f %p %d 0x%X 0x%X\n", ptr, 0, lr, pc);
		_free(ptr);
	}
	return;
}



char *strdup(const char *s)
{
	unsigned stack;
	unsigned lr = *(&stack + STACK_OCTETS + 2);
	unsigned pc = *(&stack + STACK_OCTETS + 1);
	unsigned i= 1;

	u8 *ptrRR;


	if (_strdup == NULL)
	{
		_strdup = (char *(*)(const char *ptr))dlsym(RTLD_NEXT, "strdup");
	}
	ptrRR = _strdup(s);
	printf("STRDUP %p %s 0x%X 0x%X\n", ptrRR, s, lr, pc);

	return ptrRR;
}


/*void syslog (int __pri, const char *__fmt, ...)
{
	unsigned stack;
	unsigned lr = *(&stack + STACK_OCTETS + 2);
	unsigned pc = *(&stack + STACK_OCTETS + 1);
	unsigned i= 1;

	u8 *ptrRR;
	va_list ap;

	if (_syslog == NULL)
	{
		_syslog = (void(*)(int __pri, const char *__fmt, ...))dlsym(RTLD_NEXT, "syslog");
	}

	va_start(ap, __fmt);
//	printf("syslog %d %s", __pri, __fmt);
//	printf("\t");
	printf( __fmt, ap);
	printf("\n");
//	__vsyslog_chk(__pri, -1, __fmt, ap);
	va_end(ap);
	return;
}*/



