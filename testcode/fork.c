#include <stdio.h>
#include <unistd.h>

void child_proc(pid_t pid)
{
	printf("Child: %d\n", pid);
}

void parent_proc(pid_t pid)
{
	printf("Parent: child_proc = %d\n", pid);
}

int main(void)
{
	pid_t pid;
	if ((pid = fork()) == 0) {
		child_proc(pid);
	} else if (pid == -1) {
		return -1;
	} else {
		parent_proc(pid);
	}
	return 0;
}
