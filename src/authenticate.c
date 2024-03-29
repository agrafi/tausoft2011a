/*
 * This file receives a user-hashed password table, and simulates a "login" authentication process.
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
 * This function takes a file and a record and returns CMD_VALID after updating
 * the record structure or CMD_QUIT if it fails.
 */
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

/*
 * Main reads the file, reads input from user and tries to authenticate it against the file.
 */
int main(int argc, char** argv) {
	enum Hashfunc hashfunc;
	BasicHashFunctionPtr hashptr;
	char* filename = NULL;
	FILE* filename_handle = NULL;
	char buffer[MAX_FIELD] = {0};
	int i = 0;
	int dblen = 0;
	record newuser;
	record newrecord;
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

	/* Acquire number of lines in file and allocate table */
	dblen = numOfLines(filename);
	db = (record*)calloc(1, sizeof(record)*dblen);
	if (!db)
		return 1;

	i = 0;
	/* read db and store in memory */
	while(1)
	{
		memset(&newrecord, 0, sizeof(record));

		newrecord.hashed_password_len = hashed_password_len;
		quit = readLineFromFile(filename_handle, &newrecord);

		if (quit == CMD_QUIT)
		{
			break;
		}

		memcpy(&db[i], &newrecord, sizeof(record));
		i++;
	}

	/* read creds using console prompt and check against db */
	quit = CMD_CONTINUE;
	while(quit != CMD_QUIT)
	{
			approved = 0;
			memset(&newuser, 0, sizeof(record));

			newuser.hashptr = hashptr;
			newuser.hash = hashfunc;
			newuser.hashed_password_len = hashed_password_len;
			quit = readLineFromUser(&newuser);

			if (quit != CMD_VALID)
			{
				if (quit == CMD_QUIT)
					break;
				continue;
			}

			/* iterate over db */
			for (i=0; i<dblen && !approved; i++)
			{
				if (!memcmp(newuser.username, db[i].username, sizeof(newuser.username)) &&
						!memcmp((char*)&(newuser.hashed_password), (char*)&(db[i].hashed_password), sizeof(newuser.hashed_password)))
					approved = 1;
			}

			if (approved)
				printf("Approved.\n");
			else
				printf("Denied.\n");

	}
	/* release db */
	free(db);

	fclose(filename_handle);
	return EXIT_SUCCESS;
}
#endif
