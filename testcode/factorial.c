#include <stdio.h>
#include <stdlib.h>

int factorial(int i)
{
	if (i == 0) {
		return 1;
	} else {
		return i * factorial(i - 1);
	}
}

int main(int argc, char **argv)
{
	if (argc == 1) {
		printf("%d\n", factorial(5));
	} else {
		printf("%d\n", factorial(atoi(argv[1])));
	}
	return 0;
}
