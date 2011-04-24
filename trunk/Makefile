# Makefile for Tau Project 2011.
# Make sure to run make prepare before running other targets
OBJDIR=objs
PARTDIRS=Part1 Part2 Part3

# change on nova
P1SRCDIR=src
P2SRCDIR=src
P3SRCDIR=src
SHAREDSRCDIR=src

SHARED_PALL=$(OBJDIR)/misc.o $(OBJDIR)/sha1.o $(OBJDIR)/md5.o $(OBJDIR)/helpers.o
SHARED_P2_P3=$(OBJDIR)/rules.o $(OBJDIR)/DEHT.o

all: prepare part1 part2 part3

$(OBJDIR):
	mkdir $(OBJDIR)

prepare: $(OBJDIR)
	-mkdir $(PARTDIRS)
	
clean:
	-rm $(OBJDIR)/*.o
	-rm Part1/create_authentication Part1/authenticate
	-rm Part2/exhaustive_table_generator Part2/exhaustive_query
	-rm Part3/create_rainbow_table Part3/crack_using_rainbow_table

#part 1
part1: authenticat create_authenticat

create_authenticat: $(OBJDIR)/create_authentication.o $(SHARED_PALL)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/create_authentication.o $(SHARED_PALL) -o Part1/create_authentication

authenticat: $(OBJDIR)/authenticate.o $(SHARED_PALL)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/authenticate.o $(SHARED_PALL) -o Part1/authenticate

$(OBJDIR)/create_authentication.o: $(P1SRCDIR)/create_authentication.c
	gcc -ansi -pedantic-errors -c -Wall -g -DCREATE_AUTHENTICATION $(P1SRCDIR)/create_authentication.c -o $(OBJDIR)/create_authentication.o 

$(OBJDIR)/authenticate.o: $(P1SRCDIR)/authenticate.c
	gcc -ansi -pedantic-errors -c -Wall -g -DAUTHENTICATE $(P1SRCDIR)/authenticate.c -o $(OBJDIR)/authenticate.o

#part 2
part2: exhaustive_table_generator exhaustive_query

exhaustive_table_generator: $(OBJDIR)/exhaustive_table_generator.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/exhaustive_table_generator.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part2/exhaustive_table_generator

exhaustive_query: $(OBJDIR)/exhaustive_query.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/exhaustive_query.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part2/exhaustive_query

$(OBJDIR)/exhaustive_table_generator.o: $(P2SRCDIR)/exhaustive_table_generator.c
	gcc -ansi -pedantic-errors -c -Wall -g -DEXHAUSTIVE_TABLE_GENERATOR $(P2SRCDIR)/exhaustive_table_generator.c -o $(OBJDIR)/exhaustive_table_generator.o

$(OBJDIR)/exhaustive_query.o: $(P2SRCDIR)/exhaustive_query.c
	gcc -ansi -pedantic-errors -c -Wall -g -DEXHAUSTIVE_QUERY $(P2SRCDIR)/exhaustive_query.c -o $(OBJDIR)/exhaustive_query.o 

#part 3
part3: create_rainbow_table crack_using_rainbow_table

create_rainbow_table: $(OBJDIR)/create_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/create_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part3/create_rainbow_table

crack_using_rainbow_table: $(OBJDIR)/crack_using_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/crack_using_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part3/crack_using_rainbow_table

$(OBJDIR)/create_rainbow_table.o: $(P3SRCDIR)/create_rainbow_table.c
	gcc -ansi -pedantic-errors -c -Wall -g -DCREATE_RAINBOW_TABLE $(P3SRCDIR)/create_rainbow_table.c -o $(OBJDIR)/create_rainbow_table.o

$(OBJDIR)/crack_using_rainbow_table.o: $(P3SRCDIR)/crack_using_rainbow_table.c
	gcc -ansi -pedantic-errors -c -Wall -g -DCRACK_USING_RAINBOW_TABLE $(P3SRCDIR)/crack_using_rainbow_table.c -o $(OBJDIR)/crack_using_rainbow_table.o 


#shared
$(OBJDIR)/misc.o: $(SHAREDSRCDIR)/misc.c
	gcc -ansi -pedantic-errors -c -Wall -g $(SHAREDSRCDIR)/misc.c -o $(OBJDIR)/misc.o

$(OBJDIR)/sha1.o: $(SHAREDSRCDIR)/sha1.c
	gcc -ansi -pedantic-errors -c -Wall -g $(SHAREDSRCDIR)/sha1.c -o $(OBJDIR)/sha1.o

$(OBJDIR)/md5.o: $(SHAREDSRCDIR)/md5.c
	gcc -ansi -pedantic-errors -c -Wall -g $(SHAREDSRCDIR)/md5.c -o $(OBJDIR)/md5.o

$(OBJDIR)/helpers.o: $(SHAREDSRCDIR)/helpers.c
	gcc -ansi -pedantic-errors -c -Wall -g $(SHAREDSRCDIR)/helpers.c -o $(OBJDIR)/helpers.o

$(OBJDIR)/rules.o: $(SHAREDSRCDIR)/rules.c
	gcc -ansi -pedantic-errors -c -Wall -g $(SHAREDSRCDIR)/rules.c -o $(OBJDIR)/rules.o

$(OBJDIR)/DEHT.o: $(SHAREDSRCDIR)/DEHT.c
	gcc -ansi -pedantic-errors -c -Wall -g $(SHAREDSRCDIR)/DEHT.c -o $(OBJDIR)/DEHT.o
