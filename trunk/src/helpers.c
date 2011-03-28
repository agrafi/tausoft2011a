#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include "sha1.h"
#include "md5.h"
#include "misc.h"
#include "helpers.h"

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


int extractParameterNameValue(char* buffer, char* parameterName, char* parameterValue)
{
	int retValue = PARAM_INVALID;
	char* currentPtr = buffer;
	char* paramPtr = parameterName;
	int bufferlen = strlen(buffer);

	// skip white spaces
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	// copy from buffer to parameter name until first non alpha char
	while(*currentPtr && isalpha(*currentPtr))
		*paramPtr++ = *currentPtr++;

	// terminate parameter name
	*paramPtr = '\0';

	// skip white spaces
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	// check for '='
	if (*currentPtr++ != '=')
		return PARAM_INVALID;

	// skip white spaces
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	if (*currentPtr == '\0')
		return PARAM_INVALID;

	paramPtr = parameterValue;

	// copy from buffer to parameter name until first blank char
	while(*currentPtr && !isblank(*currentPtr))
		*paramPtr++ = *currentPtr++;

	// terminate parameter name
	*paramPtr = '\0';

	// skip white spaces
	while (*currentPtr && isblank(*currentPtr))
		currentPtr++;

	if (*currentPtr != '\0')
		return PARAM_INVALID;

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

		// if empty line, continue
		if (strlen(buffer) == 0)
			continue;

		if (PARAM_INVALID == (parameterCode = extractParameterNameValue(buffer, parameterName, parameterValue)))
		{
			fprintf(stderr, "Unknown parameter %s. aborting.", parameterName);
			fclose(inihandle);
			return 0;
		}

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
			fprintf(stderr, "Unknown parameter code %s. aborting.", parameterCode);
		}
	}

	return 1;
}

