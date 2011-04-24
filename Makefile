# Makefile for Tau Project 2011.
# Make sure to run make prepare before running other targets
OBJDIR=objs
PARTDIRS=Part1 Part2 Part3

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

$(OBJDIR)/create_authentication.o: src/create_authentication.c
	gcc -ansi -pedantic-errors -c -Wall -g -DCREATE_AUTHENTICATION src/create_authentication.c -o $(OBJDIR)/create_authentication.o 

$(OBJDIR)/authenticate.o: src/authenticate.c
	gcc -ansi -pedantic-errors -c -Wall -g -DAUTHENTICATE src/authenticate.c -o $(OBJDIR)/authenticate.o

#part 2
part2: exhaustive_table_generator exhaustive_query

exhaustive_table_generator: $(OBJDIR)/exhaustive_table_generator.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/exhaustive_table_generator.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part2/exhaustive_table_generator

exhaustive_query: $(OBJDIR)/exhaustive_query.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/exhaustive_query.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part2/exhaustive_query

$(OBJDIR)/exhaustive_table_generator.o: src/exhaustive_table_generator.c
	gcc -ansi -pedantic-errors -c -Wall -g -DEXHAUSTIVE_TABLE_GENERATOR src/exhaustive_table_generator.c -o $(OBJDIR)/exhaustive_table_generator.o

$(OBJDIR)/exhaustive_query.o: src/exhaustive_query.c
	gcc -ansi -pedantic-errors -c -Wall -g -DEXHAUSTIVE_QUERY src/exhaustive_query.c -o $(OBJDIR)/exhaustive_query.o 

#part 3
part3: create_rainbow_table crack_using_rainbow_table

create_rainbow_table: $(OBJDIR)/create_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/create_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part3/create_rainbow_table

crack_using_rainbow_table: $(OBJDIR)/crack_using_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3)
	gcc -ansi -pedantic-errors -g -lm $(OBJDIR)/crack_using_rainbow_table.o $(SHARED_PALL) $(SHARED_P2_P3) -o Part3/crack_using_rainbow_table

$(OBJDIR)/create_rainbow_table.o: src/create_rainbow_table.c
	gcc -ansi -pedantic-errors -c -Wall -g -DCREATE_RAINBOW_TABLE src/create_rainbow_table.c -o $(OBJDIR)/create_rainbow_table.o

$(OBJDIR)/crack_using_rainbow_table.o: src/crack_using_rainbow_table.c
	gcc -ansi -pedantic-errors -c -Wall -g -DCRACK_USING_RAINBOW_TABLE src/crack_using_rainbow_table.c -o $(OBJDIR)/crack_using_rainbow_table.o 


#shared
$(OBJDIR)/misc.o: src/misc.c
	gcc -ansi -pedantic-errors -c -Wall -g src/misc.c -o $(OBJDIR)/misc.o

$(OBJDIR)/sha1.o: src/sha1.c
	gcc -ansi -pedantic-errors -c -Wall -g src/sha1.c -o $(OBJDIR)/sha1.o

$(OBJDIR)/md5.o: src/md5.c
	gcc -ansi -pedantic-errors -c -Wall -g src/md5.c -o $(OBJDIR)/md5.o

$(OBJDIR)/helpers.o: src/helpers.c
	gcc -ansi -pedantic-errors -c -Wall -g src/helpers.c -o $(OBJDIR)/helpers.o

$(OBJDIR)/rules.o: src/rules.c
	gcc -ansi -pedantic-errors -c -Wall -g src/rules.c -o $(OBJDIR)/rules.o

$(OBJDIR)/DEHT.o: src/DEHT.c
	gcc -ansi -pedantic-errors -c -Wall -g src/DEHT.c -o $(OBJDIR)/DEHT.o
