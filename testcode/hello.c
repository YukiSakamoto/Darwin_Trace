#include <stdio.h>

void say_goodnight(void) {
	printf("good night!\n");
}

void say_hello(void)
{
	int i;
	for(i = 0; i < 5; i++) {
		printf("hello world\n");
	}
	say_goodnight();
}

int main(void)
{
	say_hello();
	say_hello();
	say_hello();
	return 0;
}
