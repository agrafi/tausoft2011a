/*
 ============================================================================
 Name        : create_authentication.c
 Author      : Aviv Graffi and Asaf Bruner
 Version     :
 Copyright   :
 Description : create authentication, first part of the project.
 ============================================================================
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

void writeRecordToFile(FILE* file, record* r)
{
	fprintf(file, "%s\t", r->username);
	printHash(r, file);
	fprintf(file, "\n");
}

int readLineFromUser(record* newuser)
{
	char* buffer = NULL;
	char* position = NULL;

	buffer = (char*)calloc(1, MAX_INPUT*sizeof(char));
	if(!buffer)
		return CMD_QUIT;


	memset(buffer, 0, MAX_INPUT*sizeof(char));
	printf(">>");
	if (buffer != fgets(buffer, MAX_INPUT, stdin))
	{
		free(buffer);
		return CMD_QUIT;
	}
	if (strncmp("quit\n", buffer, 6) == 0)
	{
		/* quit detected, TODO: free everything */
		free(buffer);
		return CMD_QUIT;
	}
	else if (strncmp("\n", buffer, 1) == 0)
	{
		free(buffer);
		return CMD_CONTINUE;
	}
	else
	{
		/* find first tab */
		if ((position = strchr(buffer, '\t')) == NULL)
		{
			fprintf(stderr, "Error: Commands are either “quit” or <user name>tab<password>.\n");
			free(buffer);
			return CMD_CONTINUE;
		}
		*position = '\0';
		strncpy((char*)&(newuser->username), buffer, position - buffer);
		strncpy((char*)&(newuser->password), position+1, strlen(position+1)-1);

#ifdef DEBUG
		printf("user: %s pass: %s\n", newuser->username, (char*)&(newuser->password));
#endif
		memset((void*)&(newuser->hashed_password), 0, sizeof(newuser->hashed_password));
		newuser->hashptr((unsigned char*)&(newuser->password), strlen(newuser->password), (unsigned char*) &(newuser->hashed_password));
#ifdef DEBUG
		printHash(newuser, stdout); printf("\n");
#endif
		free(buffer);
	}
	return CMD_VALID;
}

#ifdef CREATE_AUTHENTICATION
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
