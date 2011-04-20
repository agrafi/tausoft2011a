all: authenticat create_authenticat

clean:
	-rm create_authentication/*.o authenticate/*.o 

authenticat: authenticate/authenticate.o
	gcc -ansi -pedantic-errors -g -lm  authenticate/authenticate.o -o authenticat

create_authenticat: create_authentication/create_authentication.o
	gcc -ansi -pedantic-errors -g -lm  create_authentication/create_authentication.o -o create_authenticat

authenticate/authenticate.o: src/authenticate.c
	gcc -ansi -pedantic-errors -c -Wall -g -DAUTHETICATE src/authenticate.c -o authenticate/authenticate.o

create_authentication/create_authentication.o: create_authentication/create_authentication.c
	gcc -ansi -pedantic-errors -c -Wall -g create_authentication/create_authentication.c -o create_authentication/create_authentication.o 

