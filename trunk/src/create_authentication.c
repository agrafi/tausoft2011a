/*
 * This file simulates the creation of users where each user enters a password
 * and outputs a file with hashed passwords.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include "sha1.h"
#include "md5.h"
#include "misc.h"
#include "helpers.h"

/*
 * This function prints the record into the file
 */
void writeRecordToFile(FILE* file, record* r)
{
	fprintf(file, "%s\t", r->username);
	printHash(r, file);
	fprintf(file, "\n");
}


#ifdef CREATE_AUTHENTICATION

/*
 * Main reads a line from the user, verifies it and writes it to a file.
 */
int main(int argc, char** argv) {
	enum Hashfunc hashfunc;
	BasicHashFunctionPtr hashptr;
	char* filename = NULL;
	FILE* filename_handle = NULL;
	record* newuser = NULL;
	char quit = 1;
	int hashed_password_len = 0;

	if (argc != 3)
	{
		fprintf(stderr, "Error: Usage create_authentication <hash function name> <filename to create>\n");
		return 1;
	}

	if(strcmp("SHA1",argv[1])==0)
	{
		hashfunc = SHA1;
		hashptr = SHA1BasicHash;
		hashed_password_len = SHA1_OUTPUT_LENGTH_IN_BYTES;
	}
	else if(strcmp("MD5",argv[1])==0)
	{
		hashfunc = MD5;
		hashptr = MD5BasicHash;
		hashed_password_len = MD5_OUTPUT_LENGTH_IN_BYTES;
	}
	else
	{
		fprintf(stderr, "Error: Hash \"%s\" is not supported\n", argv[1]);
		return 1;
	}

	filename = argv[2];
	if (fileexists(filename))
	{
		fprintf(stderr, "Error: File \"%s\" already exist\n", filename);
		return 1;
	}

	if ((filename_handle = fopen(filename, "wt")) == NULL)
	{
		perror(filename);
		return 1;
	}
	fprintf(filename_handle, "%s\n", argv[1]);

	while(quit)
	{
			newuser = (record*)calloc(1, sizeof(record));
			if (!newuser)
				break;

			newuser->hashptr = hashptr;
			newuser->hash = hashfunc;
			newuser->hashed_password_len = hashed_password_len;
			quit = readLineFromUser(newuser);
			if (quit != CMD_VALID)
			{
				free(newuser);
				if (quit == CMD_QUIT)
					break;
				continue;
			}
			writeRecordToFile(filename_handle, newuser);
			free(newuser);
	}

	fclose(filename_handle);
	return EXIT_SUCCESS;
}
#endif
