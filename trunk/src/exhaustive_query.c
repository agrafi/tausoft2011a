/*
 * exhaustive_query.c
 *
 *  Created on: Mar 12, 2011
 *      Author: a
 */

#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"
#include "DEHT.h"
#include "rules.h"
#include "assert.h"

int readHashFromUser(char* hashedpass)
{
	char* buffer = NULL;

	buffer = (char*)calloc(1, MAX_INPUT*sizeof(char));
	assert(buffer != NULL);


	memset(buffer, 0, MAX_INPUT*sizeof(char));
	printf(">>");
	fgets(buffer, MAX_INPUT, stdin);
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
		// drop trailing newline
		if (buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';
		strncpy(hashedpass, buffer, strlen(buffer)+1);
		free(buffer);
	}
	return CMD_VALID;
}


#ifdef EXHAUSTIVE_QUERY
int main(int argc, char** argv)
{
	DEHT* deht = NULL;
	char* prefix = argv[1];
	/*unsigned int passgensize = 0;*/
	/*unsigned long k = 0;*/
	/*unsigned long numOfPasswords = 0;*/
	/*char* pass = NULL;*/
	/*unsigned long i = 0; */
	int quit = 0, cmd = CMD_CONTINUE;
	unsigned long keylen;
	/*unsigned long datalen;*/
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
			// key buf holds the hashed password string
			if (strlen(hashbuf) != hashed_password_len * 2)
			{
				fprintf(stderr, "Error: Wrong hash size \n");
				break;
			}

			keylen = hexa2binary(hashbuf,(unsigned char*)keybuf, sizeof(keybuf));
			if (query_DEHT(deht,(unsigned char*)keybuf, keylen,(unsigned char*)databuf, sizeof(databuf)))
				printf("Try to login with password \"%s\"\n", databuf);
			else
				printf("Sorry but this hash doesn't appear in pre-processing\n");
			break;
		}
	}





	lock_DEHT_files(deht);
	//free(keybuf);
	//free(databuf);
	return 0;


	/*
	int i = 0, len = 0, datalen = 0, keylen = 0;
	DEHT* deht = create_empty_DEHT("deht", hashfun, validfun, "SHA1", 65536, ELEMENTS_PER_NODE, 8);
	char* keybuf = calloc(1, 20);
	char* databuf = calloc(1, 30);
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	add_DEHT(deht, keybuf, keylen, databuf, datalen);

	for (i=0; i<11; i++)
	{
		datalen = hexa2binary("65432100", databuf, 30);
		keylen = hexa2binary("dd5fef9c1c1da1394d6d34b248c51be2ad740840", keybuf, 20);
		add_DEHT(deht, keybuf, keylen, databuf, datalen);
	}
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	memset(databuf, 0, 30);
	len = query_DEHT(deht, keybuf, 20, databuf, 30);
	memset(keybuf, 0 , 20);
	binary2hexa(databuf, len, keybuf, 20);
	printf("data is %s\n", keybuf);
	lock_DEHT_files(deht);

	deht = load_DEHT_from_files("deht", hashfun, validfun);
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	memset(databuf, 0, 30);
	len = query_DEHT(deht, keybuf, 20, databuf, 30);
	memset(keybuf, 0 , 20);
	binary2hexa(databuf, len, keybuf, 20);
	printf("data is %s\n", keybuf);
	*/

	return EXIT_SUCCESS;
}
#endif