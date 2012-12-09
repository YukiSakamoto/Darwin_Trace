#include <stdio.h>

int fibonacci(int i) {
	if (i == 0 || i == 1) {
		return 1;
	} else {
		return fibonacci(i - 1) + fibonacci(i - 2);
	}
}

int main(void)
{
	printf("%d\n", fibonacci(3));
	return 0;
}
