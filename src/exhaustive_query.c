/*
 * This file gets a DEHT prefix and checks if the input from the user is in it.
 */
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"
#include "DEHT.h"
#include "rules.h"
#include "assert.h"

/*
 * Main loads deht from files, reads hash from user, queries deht and locks deht files.
 */
#ifdef EXHAUSTIVE_QUERY
int main(int argc, char** argv)
{
	DEHT* deht = NULL;
	char* prefix = argv[1];
	int quit = 0, cmd = CMD_CONTINUE;
	unsigned long keylen;
	int hashed_password_len = 0;

	char keybuf[SHA1_OUTPUT_LENGTH_IN_BYTES];
	char hashbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];
	char databuf[MAX_INPUT];

	if (argc != 2)
	{
		fprintf(stderr, "Error: Usage exhaustive_query <DEHT prefix>\n");
		return 1;
	}

	deht = load_DEHT_from_files(prefix, hashfun, validfun);

	if (!deht)
		return 1;



	if(strcmp("SHA1",deht->header.sHashName)==0)
	{
		hashed_password_len = SHA1_OUTPUT_LENGTH_IN_BYTES;
	}
	else if(strcmp("MD5",deht->header.sHashName)==0)
	{
		hashed_password_len = MD5_OUTPUT_LENGTH_IN_BYTES;
	}
	else
	{
		fprintf(stderr, "Error: Hash \"%s\" is not supported\n", argv[1]);
		lock_DEHT_files(deht);
		return 1;
	}

	while (!quit)
	{
		memset(&hashbuf, 0, sizeof(hashbuf));
		memset(&databuf, 0, sizeof(databuf));
		cmd = readHashFromUser(hashbuf);
		switch(cmd)
		{
		case CMD_QUIT:
			quit = 1;
			break;
		case CMD_CONTINUE:
			break;
		case CMD_VALID:
			/* key buf holds the hashed password string */
			/* verify provided hash string length */
			if (strlen(hashbuf) != hashed_password_len * 2)
			{
				fprintf(stderr, "Error: Wrong hash size \n");
				break;
			}

			keylen = hexa2binary(hashbuf,(unsigned char*)keybuf, sizeof(keybuf));
			/* query user provided hash */
			if (query_DEHT(deht,(unsigned char*)keybuf, keylen,(unsigned char*)databuf, sizeof(databuf)))
				printf("Try to login with password \"%s\"\n", databuf);
			else
				printf("Sorry but this hash doesn't appear in pre-processing\n");
			break;
		}
	}

	lock_DEHT_files(deht);
	return EXIT_SUCCESS;
}
#endif
