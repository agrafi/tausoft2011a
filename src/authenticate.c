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

int readLineFromFile(FILE* file, record* newuser)
{
	char* buffer = NULL;
	char* position = NULL;

	buffer = (char*)calloc(1, MAX_INPUT*sizeof(char));
	if (!buffer)
		return CMD_QUIT;


	memset(buffer, 0, MAX_INPUT*sizeof(char));
	fgets(buffer, MAX_INPUT, file);
	/* find first tab */
	if ((position = strchr(buffer, '\t')) == NULL)
	{
		free(buffer);
		return CMD_QUIT;
	}
	*position = '\0';
	strncpy((char*)&(newuser->username), buffer, position - buffer);
	memset((void*)&(newuser->hashed_password), 0, sizeof(newuser->hashed_password));
	hexa2binary(position+1, (unsigned char*)&(newuser->hashed_password), MIN(newuser->hashed_password_len, sizeof(newuser->hashed_password)));
	free(buffer);
	return CMD_VALID;
}

#ifdef AUTHENTICATE
int main(int argc, char** argv) {
	enum Hashfunc hashfunc;
	BasicHashFunctionPtr hashptr;
	char* filename = NULL;
	FILE* filename_handle = NULL;
	char buffer[MAX_FIELD] = {0};
	int i = 0;
	int dblen = 0;
	record* newuser = NULL;
	record* newrecord = NULL;
	record* db = NULL;
	char quit = CMD_CONTINUE;
	char approved = 0;
	int hashed_password_len = 0;

	if (argc != 2)
	{
		fprintf(stderr, "Error: Usage authenticate <authentication table text file>\n");
		return 1;
	}

	filename = argv[1];
	if (!fileexists(filename))
	{
		fprintf(stderr, "Error: File \"%s\" does not exists\n", filename);
		return 1;
	}

	if ((filename_handle = fopen(filename, "rt")) == NULL)
	{
		perror(filename);
		return 1;
	}
	fgets(buffer, MAX_INPUT, filename_handle);
	/* drop newline trail */
	if (buffer[strlen(buffer)-1] == '\n')
		buffer[strlen(buffer)-1] = '\0';

	if(strcmp("SHA1",buffer)==0)
	{
		hashfunc = SHA1;
		hashptr = SHA1BasicHash;
		hashed_password_len = SHA1_OUTPUT_LENGTH_IN_BYTES;
	}
	else if(strcmp("MD5",buffer)==0)
	{
		hashfunc = MD5;
		hashptr = MD5BasicHash;
		hashed_password_len = MD5_OUTPUT_LENGTH_IN_BYTES;
	}
	else
	{
		fprintf(stderr, "Error: Hash \"%s\" is not supported\n", buffer);
		return 1;
	}
	dblen = numOfLines(filename);
	db = (record*)calloc(1, sizeof(record)*dblen);
	if (!db)
		return 1;

	i = 0;
	while(1)
	{
		newrecord = (record*)calloc(1, sizeof(record));
		if(!newrecord)
		{
			free(db);
			break;
		}
		newrecord->hashed_password_len = hashed_password_len;
		quit = readLineFromFile(filename_handle, newrecord);
		if (quit == CMD_QUIT)
		{
			free(newrecord);
			break;
		}
		memcpy(&db[i], newrecord, sizeof(record));
		free(newrecord);
		i++;
	}

	quit = CMD_CONTINUE;
	while(quit != CMD_QUIT)
	{
			approved = 0;
			newuser = (record*)calloc(1, sizeof(record));
			if(!newuser)
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

			for (i=0; i<dblen && !approved; i++)
			{

#ifdef DEBUG
		printf("user: %s pass: %s\n", newuser->username,(char*) &(newuser->password));
		printHash(newuser, stdout); printf("\n");
#endif

				if (!memcmp(newuser->username, db[i].username, sizeof(newuser->username)) &&
						!memcmp((char*)&(newuser->hashed_password), (char*)&(db[i].hashed_password), sizeof(newuser->hashed_password)))
					approved = 1;
			}
			if (approved)
				printf("Approved.\n");
			else
				printf("Denied.\n");
			free(newuser);
	}
	/* release db */
	free(db);

	fclose(filename_handle);
	return EXIT_SUCCESS;
}
#endif
