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

#ifdef CRACK_USING_RAINBOW_TABLE
/*
 * For j = chain_length to 1 do
	//Gamble that our password is in location "j" in some chain as follow:
	curHash=target
	// go down the chain (chain_length-j ) steps (till curHash = end-point hash).
	For i=j to chain_length do
		k = pseudo-random-function with seed seed[i] and input curHash;
		*
		NewPassword = get_kth_password (k,S)
		curHash = MD5(NewPassword);
	end // going down the chain.
	Multi-query in disk-embedded hash table with key: curHash.
	Get data (passwords set) to array: tryThisPassword[0..n]
	For k =0 to n-1 // if n=0 (no password is found), we guessed wrong j, continue loop other j.
		//assume tryThisPassword[k] is beginning of correct chain
		curPass = tryThisPassword[k]
		Go j-1 steps down // (till curPass is the password before the hash we are looking for).
		Check whether MD5(curPass)==target
		If so, return curPass
		Else, continue loop // false alarm.
	End // looping multiple query
End //main loop on j
If you arrived here, it means that the target does not exist in either 1 or 2 or 3 ... location of any-
chain, in other-words, not in our Rainbow-Table.
 *
 */

char* queryRainbowTable(DEHT* deht, unsigned char* target, rainbow_settings* settings, unsigned long* seeds,
		passgencontext* passgenctx, lexicon* lex, char* pass)
{
	long j = 0;
	unsigned long i = 0, k = 0, n = 0, h = 0;
	char curHash[SHA1_OUTPUT_LENGTH_IN_BYTES];
	char tryThisPassword[MAX_MATCHED_PASSWORDS * MAX_FIELD];
	char* dataPointers[MAX_MATCHED_PASSWORDS + 1]; // reserve extra slot
	char curPass[MAX_FIELD + 1] = {0};

	//Gamble that our password is in location "j" in some chain as follow:
	for (j = settings->ChainLength - 1; j >= 0; j--)
	{
		// set curHash to target
		memset(curHash, 0, sizeof(curHash));
		memcpy(curHash, target, settings->hashed_password_len);

		// go down the chain (chain_length-j ) steps (till curHash = end-point hash).
		for (i = j; i < settings->ChainLength - 1; i++)
		{
			k = pseudo_random_function((const unsigned char*)curHash, settings->hashed_password_len, seeds[i]);
			generatePassword(passgenctx, lex, k, pass);
			settings->hashptr((const unsigned char*)pass, strlen(pass), (unsigned char*)curHash);
		}
		// Multi-query in disk-embedded hash table with key: curHash.
		// Get data (passwords set) to array: tryThisPassword[0..n]
		n = mult_query_DEHT(deht, (unsigned char*)curHash, settings->hashed_password_len,
				(unsigned char*)tryThisPassword, MAX_MATCHED_PASSWORDS * MAX_FIELD,
				(unsigned char**)dataPointers, MAX_MATCHED_PASSWORDS);

		// if n=0 (no password is found), we guessed wrong j, continue loop other j.
		if (n == 0)
			continue;

		for(h = 0; h < n; h++)
		{
			// set curPass to tryThisPassword[h]
			memset(curPass, 0, MAX_FIELD);
			memcpy(curPass, dataPointers[h], dataPointers[h+1] - dataPointers[h]);
			settings->hashptr((unsigned char*)curPass, strlen(curPass), (unsigned char*)curHash);
			for (i = 0; i < j; i++)
			{
				k = pseudo_random_function((unsigned char*)curHash, settings->hashed_password_len, seeds[i]);
				generatePassword(passgenctx, lex, k, pass);
				settings->hashptr((unsigned char*)pass, strlen(pass), (unsigned char*)curHash);
				// TODO free pass
			}
			// TODO handle j = 0 case (ugly)
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
	char pass[MAX_FIELD+1] = {0};
	unsigned long keylen;
	unsigned long* seeds = NULL;;
	char cmd = CMD_CONTINUE;
	char quit = 0;

	unsigned char keybuf[SHA1_OUTPUT_LENGTH_IN_BYTES];
	char hashbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];
	char hexbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];
	char databuf[MAX_INPUT];

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
	passgenctx = createrule(settings.Rule, lex, &passgensize);

	// Read seeds
	seeds = calloc(settings.ChainLength - 1, sizeof(seeds));
	read_DEHT_Seed(deht, seeds, settings.ChainLength - 1);


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
			if (hashbuf[0] == '!')
			{
				memcpy(hexbuf, hashbuf+1, strlen(hashbuf)-1);
				settings.hashptr((unsigned char*)hexbuf, strlen(hexbuf), (unsigned char*)keybuf);
				binary2hexa((unsigned char*)keybuf, settings.hashed_password_len, hexbuf, sizeof(hexbuf));
				printf("In hexa password is%s\n", hexbuf);
			}
			else
			{
				if (strlen(hashbuf) != settings.hashed_password_len * 2)
				{
					// key buf holds the hashed password string
					fprintf(stderr, "Error: Wrong hash size \n");
					break;
				}
				keylen = hexa2binary(hashbuf, (unsigned char*)keybuf, sizeof(keybuf));
			}
			queryRainbowTable(deht, (unsigned char*)keybuf, &settings, seeds, passgenctx, lex, pass);
			if (strlen(pass) != 0)
				printf("Try to login with password \"%s\"\n", pass);
			else
				printf("Sorry but this hash doesn't appear in pre-processing\n");
			break;
		}
	}

	freerule(passgenctx);
	freelex(lex);
	lock_DEHT_files(deht);
	free(seeds);
	return EXIT_SUCCESS;
}

#endif
