/*
 * crack_using_rainbow_table.c
 *
 *  Created on: Mar 26, 2011
 *      Author: a
 */
#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"
#include "DEHT.h"
#include "rules.h"
#include <assert.h>

#define MAX_MATCHED_PASSWORDS 10

#define NUM_PASS_TO_CHECK 1000

#ifdef CRACK_USING_RAINBOW_TABLE

char* queryRainbowTable(DEHT* deht, unsigned char* target, rainbow_settings* settings, unsigned long* seeds,
		passgencontext* passgenctx, lexicon* lex, char* pass)
{
	long j = 0;
	unsigned long i = 0, k = 0, n = 0, h = 0;
	char curHash[SHA1_OUTPUT_LENGTH_IN_BYTES];
	char tryThisPassword[MAX_MATCHED_PASSWORDS * MAX_FIELD];
	char* dataPointers[MAX_MATCHED_PASSWORDS + 1]; /* reserve extra slot */
	char curPass[MAX_FIELD + 1] = {0};

	/* Gamble that our password is in location "j" in some chain as follow: */
	for (j = settings->ChainLength - 1; j >= 0; j--)
	{
		/* set curHash to target */
		memset(curHash, 0, sizeof(curHash));
		memcpy(curHash, target, settings->hashed_password_len);

		/* go down the chain (chain_length-j ) steps (till curHash = end-point hash). */
		for (i = j; i < settings->ChainLength - 1; i++)
		{
			k = pseudo_random_function((const unsigned char*)curHash, settings->hashed_password_len, seeds[i]);
			generatePassword(passgenctx, lex, k, pass);
			settings->hashptr((const unsigned char*)pass, strlen(pass), (unsigned char*)curHash);
		}
		/* Multi-query in disk-embedded hash table with key: curHash.*/
		/* Get data (passwords set) to array: tryThisPassword[0..n]*/
		n = mult_query_DEHT(deht, (unsigned char*)curHash, settings->hashed_password_len,
				(unsigned char*)tryThisPassword, MAX_MATCHED_PASSWORDS * MAX_FIELD,
				(unsigned char**)dataPointers, MAX_MATCHED_PASSWORDS);

		/* if query failed, continue to next j. */
		if (n == DEHT_STATUS_FAIL)
			continue;

		/* if n=0 (no password is found), we guessed wrong j, continue loop other j. */
		if (n == 0)
			continue;

		for(h = 0; h < n; h++)
		{
			/* set curPass to tryThisPassword[h] */
			memset(curPass, 0, MAX_FIELD);
			memcpy(curPass, dataPointers[h], dataPointers[h+1] - dataPointers[h]);
			settings->hashptr((unsigned char*)curPass, strlen(curPass), (unsigned char*)curHash);
			for (i = 0; i < j; i++)
			{
				k = pseudo_random_function((unsigned char*)curHash, settings->hashed_password_len, seeds[i]);
				generatePassword(passgenctx, lex, k, pass);
				settings->hashptr((unsigned char*)pass, strlen(pass), (unsigned char*)curHash);
			}
			/* TODO handle j = 0 case (ugly) */
			if (j == 0) strncpy(pass, curPass, MAX_FIELD);

			if (!memcmp(curHash, target, settings->hashed_password_len))
				return pass;
		}

	}
	pass[0] = '\0';
	return NULL;
}

int main(int argc, char** argv)
{
	rainbow_settings settings;
	lexicon* lex = NULL;
	DEHT* deht = NULL;
	passgencontext* passgenctx = NULL;
	unsigned int passgensize = 0;
	unsigned long keylen;
	unsigned long* seeds = NULL;
	char cmd = CMD_CONTINUE;
	char quit = 0;

#ifdef DEBUG_TEST
	/*unsigned long i=1, succeeded=0, z=0;
	char hashbuf2[MAX_FIELD+1];*/
#endif
	/*unsigned char keybuf[SHA1_OUTPUT_LENGTH_IN_BYTES];*/
	unsigned char *keybuf = calloc(1,SHA1_OUTPUT_LENGTH_IN_BYTES);
	/*char hashbuf[MAX_FIELD+1];*/
	char *hashbuf = calloc(1,MAX_FIELD+1);
	/*char pass[MAX_FIELD+1] = {0};*/
	char *pass = calloc(1,MAX_FIELD+1);
	/*char *hexbuf[MAX_FIELD+1];*/
	char *hexbuf = calloc(1,MAX_FIELD+1);
	/*char databuf[MAX_INPUT];*/
	char *databuf = calloc(1,MAX_INPUT);

	memset(&hexbuf, 0, sizeof(hexbuf));

	if (argc != 2)
	{
		fprintf(stderr, "Error: Usage crack_using_rainbow_table <ini filename>\n");
		return 1;
	}

	if (!parseSettings(&settings, argv[1]))
		return 2;

	deht = load_DEHT_from_files(settings.OutputFilePrefix, hashfun, validfun);

	if (!deht)
		return 1;

	lex = preprocessLexicon(settings.LexiconName);
	if (!lex)
	{
		lock_DEHT_files(deht);
		return 1;
	}
	passgenctx = createrule(settings.Rule, lex, &passgensize);
	if (!passgenctx)
	{
		freelex(lex);
		lock_DEHT_files(deht);
		return 1;
	}

	/* Read seeds */
	seeds = calloc(settings.ChainLength - 1, sizeof(seeds));
	if (!seeds)
	{
		freelex(lex);
		freerule(passgenctx);
		lock_DEHT_files(deht);
		return 1;
	}
	if (DEHT_STATUS_SUCCESS != read_DEHT_Seed(deht, seeds, settings.ChainLength - 1))
	{
		freelex(lex);
		freerule(passgenctx);
		free(seeds);
		lock_DEHT_files(deht);
		return 1;
	}


	while (!quit)
	{
		memset(hashbuf, 0, MAX_FIELD);
		memset(&databuf, 0, MAX_INPUT);
		memset(&hexbuf, 0, MAX_FIELD);

#ifdef DEBUG_TEST
		/*memset(hashbuf2, 0, 2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1);
		cmd = CMD_VALID;
		if(i <= NUM_PASS_TO_CHECK)
		{
			z = rand() % passgenctx->numOfPasswords;
			memcpy(hashbuf2,"!",sizeof("!"));
			generatePassword(passgenctx, lex, z, hashbuf);
			strcat(hashbuf2,hashbuf);
			memcpy(hashbuf,hashbuf2,sizeof(hashbuf2));
			i++;
		}
		else
		{
			quit = 1;
			continue;
		}*/
#else
		/*cmd = readHashFromUser(hashbuf);*/
#endif

		switch(cmd)
		{
		case CMD_QUIT:
			quit = 1;
			break;
		case CMD_CONTINUE:
			break;
		case CMD_VALID:
			if (hashbuf[0] == '!')
			{
				memcpy(hexbuf, hashbuf+1, strlen(hashbuf)-1);
				settings.hashptr((unsigned char*)hexbuf, strlen(hexbuf), (unsigned char*)keybuf);
				binary2hexa((unsigned char*)keybuf, settings.hashed_password_len, hexbuf, sizeof(hexbuf));
				printf("In hexa password is%s\n", hexbuf); /* TODO: should it be with space? */
			}
			else
			{
				if (strlen(hashbuf) != settings.hashed_password_len * 2)
				{
					/* key buf holds the hashed password string */
					fprintf(stderr, "Error: Wrong hash size \n");
					break;
				}
				keylen = hexa2binary(hashbuf, (unsigned char*)keybuf, sizeof(keybuf));
			}

			queryRainbowTable(deht, (unsigned char*)keybuf, &settings, seeds, passgenctx, lex, pass);
			if (strlen(pass) != 0)
			{
				printf("Try to login with password \"%s\"\n", pass);
#ifdef DEBUG_TEST
				succeeded++;
#endif
			}
			else
				printf("Sorry but this hash doesn't appear in pre-processing\n");
			break;
		}
	}

#ifdef DEBUG_TEST
	printf("\nYou succeeded %lu passes out of %d which is %3.2f %%\n",succeeded,NUM_PASS_TO_CHECK,((float)succeeded/NUM_PASS_TO_CHECK)*100);
#endif

	freerule(passgenctx);
	freelex(lex);
	lock_DEHT_files(deht);
	free(seeds);


	free(keybuf);
	free(hashbuf);
	free(pass);
	free(hexbuf);
	free(databuf);

	return EXIT_SUCCESS;
}

#endif
