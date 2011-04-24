/*
 * This file gathers a few functions which we use across the project
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "sha1.h"
#include "md5.h"
#include "misc.h"
#include "helpers.h"

/*
 * This function takes a record and a file and prints the hashed password into the file
 */
void printHash(record* r, FILE* file)
{
	int i = 0;
	if (r->hash == SHA1)
	{
		for (i=0; i<20; i++)
			fprintf(file, "%02x", r->hashed_password.sha1[i]);
	}
	else if (r->hash == MD5)
	{
		for (i=0; i<16; i++)
			fprintf(file, "%02x", r->hashed_password.md5[i]);
	}
}

/*
 * This function takes a file name and returns 1 if exists, 0 otherwise
 */
int fileexists(char* filename)
{
	FILE *fp = fopen(filename,"r");
	if (fp)
	{
		fclose(fp);
		return 1;
	}
	else
	{
		return 0;
	}
}


/*
 * This function reads a line from the user
 */
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

/*
 * This function takes a file name and returns the number of lines in it
 */
int numOfLines(char* filename)
{
	FILE *f;
	char c;
	int lines = 0;

	f = fopen(filename, "r");

	if(f == NULL)
		return 0;

	while((c = fgetc(f)) != EOF)
		if(c == '\n')
			lines++;

	fclose(f);

	if(c != '\n')
		lines++;

	return lines;
}

/*
 * This function takes a buffer and two char* variables parameterName, parameterValue.
 * The function parses the buffer and updates the char* variables with the parameter and value.
 */
int extractParameterNameValue(char* buffer, char* parameterName, char* parameterValue)
{
	int retValue = PARAM_INVALID;
	char* currentPtr = buffer;
	char* paramPtr = parameterName;

	/* skip white spaces */
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	/* copy from buffer to parameter name until first non alpha char */
	while(*currentPtr && isalpha(*currentPtr))
		*paramPtr++ = *currentPtr++;

	/* terminate parameter name */
	*paramPtr = '\0';

	/* skip white spaces */
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	/* check for '=' */
	if (*currentPtr++ != '=')
		return PARAM_INVALID;

	/* skip white spaces */
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	if (*currentPtr == '\0')
		return PARAM_INVALID;

	paramPtr = parameterValue;

	/* copy from buffer to parameter name until first blank char */
	while(*currentPtr && !isblank(*currentPtr))
		*paramPtr++ = *currentPtr++;

	/* terminate parameter name */
	*paramPtr = '\0';

	/* skip white spaces */
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	if (*currentPtr != '\0')
		return PARAM_INVALID;

	/* deciding which retValue to return according to the parameter parsed */
	retValue = (strcmp("LexiconName", parameterName) 		? retValue : PARAM_LEXNAME);
	retValue = (strcmp("ChainLength", parameterName) 		? retValue : PARAM_CHAIN_LENGTH);
	retValue = (strcmp("NumOfHashEntries", parameterName) 	? retValue : PARAM_NUM_OF_HASH_ENTRIES);
	retValue = (strcmp("ElementsInBucket", parameterName) 	? retValue : PARAM_ELEMS_IN_BUCKET);
	retValue = (strcmp("Rule", parameterName) 				? retValue : PARAM_RULE);
	retValue = (strcmp("MainRandSeed", parameterName) 		? retValue : PARAM_MAIN_RAND_SEED);
	retValue = (strcmp("HashFunction", parameterName) 		? retValue : PARAM_HASH_FUNCTION);
	retValue = (strcmp("OutputFilePrefix", parameterName) 	? retValue : PARAM_OUTPUT_FILE_PREFIX);

	return retValue;
}

/*
 * This function gets a rainbow_setting struct and a path to an ini file.
 * The function parses the ini file and updates the rainbow_setting struct.
 */
int parseSettings(rainbow_settings* settings, char* inipath)
{
	FILE* inihandle = NULL;
	char buffer [MAX_INPUT + 1];
	char parameterName[MAX_INPUT + 1];
	char parameterValue[MAX_INPUT + 1];

	if ((inihandle = fopen(inipath, "r")) == NULL)
	{
		sprintf(buffer, "Could not open ini file at %s", inipath);
		perror(buffer);
		return 0;
	}

	memset(buffer, 0, MAX_INPUT + 1);
	while (fgets(buffer, MAX_INPUT, inihandle))
	{
		char parameterCode = PARAM_INVALID;
		memset(parameterName, 0, MAX_INPUT + 1);
		memset(parameterValue, 0, MAX_INPUT + 1);

		if (buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';

		/* if empty line, continue */
		if (strlen(buffer) == 0)
			continue;

		if (PARAM_INVALID == (parameterCode = extractParameterNameValue(buffer, parameterName, parameterValue)))
		{
			fprintf(stderr, "Unknown parameter %s. aborting.", parameterName);
			fclose(inihandle);
			return 0;
		}

		/* handling each parameter individually */
		switch (parameterCode)
		{
		case PARAM_LEXNAME:
			snprintf(settings->LexiconName, MAX_INPUT, "%s", parameterValue);
			break;
		case PARAM_CHAIN_LENGTH:
			settings->ChainLength = atoi(parameterValue);
			break;
		case PARAM_NUM_OF_HASH_ENTRIES:
			settings->NumOfHashEnries = atoi(parameterValue);
			break;
		case PARAM_ELEMS_IN_BUCKET:
			settings->ElementsInBucket = atoi(parameterValue);
			break;
		case PARAM_RULE:
			snprintf(settings->Rule, MAX_INPUT, "%s", parameterValue);
			break;
		case PARAM_MAIN_RAND_SEED:
			snprintf(settings->MainRandSeed, MAX_INPUT, "%s", parameterValue);
			break;
		case PARAM_HASH_FUNCTION:
			if(strcmp("SHA1",parameterValue)==0)
			{
				settings->hashptr = SHA1BasicHash;
				settings->hashed_password_len = SHA1_OUTPUT_LENGTH_IN_BYTES;
			}
			else if(strcmp("MD5",parameterValue)==0)
			{
				settings->hashptr = MD5BasicHash;
				settings->hashed_password_len = MD5_OUTPUT_LENGTH_IN_BYTES;
			}
			else
			{
				fprintf(stderr, "Error: Hash \"%s\" is not supported\n", parameterValue);
				fclose(inihandle);
				return 0;
			}
			snprintf(settings->HashFunction, MAX_INPUT, "%s", parameterValue);
			break;
		case PARAM_OUTPUT_FILE_PREFIX:
			snprintf(settings->OutputFilePrefix, MAX_INPUT, "%s", parameterValue);
			break;
		default:
			fprintf(stderr, "Unknown parameter code %d. aborting.", parameterCode);
		}
	}

	return 1;
}

