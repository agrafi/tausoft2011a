/*
 * create_rainbow_table.c
 *
 *  Created on: Mar 25, 2011
 *      Author: aviv
 */

#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"
#include "DEHT.h"
#include "rules.h"

int parseSettings(rainbow_settings* settings, char* inipath)
{
	settings->ChainLength = 5;
	settings->ElementsInBucket = 8;
	settings->NumOfHashEnries = pow(2, 16);
	snprintf(settings->OutputFilePrefix, MAX_INPUT, "%s", "rainbow");
	snprintf(settings->LexiconName, MAX_INPUT, "%s", "/home/aviv/workspace/tausoft2011a/lexicon.txt");
	snprintf(settings->MainRandSeed, MAX_INPUT, "%s", "asaf");
	snprintf(settings->Rule, MAX_INPUT, "%s", "^2");
	snprintf(settings->HashFunction, MAX_INPUT, "%s", "MD5");
	settings->hashed_password_len = MD5_OUTPUT_LENGTH_IN_BYTES;
	settings->hashptr = MD5BasicHash;
	return 1;
}


#ifdef CREATE_RAINBOW_TABLE

int main(int argc, char** argv)
{
	rainbow_settings settings;
	lexicon* lex = NULL;
	DEHT* deht = NULL;
	passgencontext* passgenctx = NULL;
	unsigned int passgensize = 0;
	unsigned long k = 0;
	unsigned long numOfChains = 10;
	char* pass, *origpass = NULL;
	unsigned long i = 0, j = 0;
	unsigned long idx = 0;
	unsigned long datalen, keylen;
	unsigned long* seeds = NULL;;

	char keybuf[SHA1_OUTPUT_LENGTH_IN_BYTES];
	char hashbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];
	char hexbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];
	char databuf[MAX_INPUT];

	if (argc != 2)
	{
		fprintf(stderr, "Error: Usage create_rainbow_table <ini filename>\n");
		return 1;
	}

	if (!parseSettings(&settings, argv[1]))
		return 2;


	lex = preprocessLexicon(settings.LexiconName);
	passgenctx = createrule(settings.Rule, lex, &passgensize);

	deht = create_empty_DEHT(settings.OutputFilePrefix, hashfun, validfun,
			settings.HashFunction, settings.NumOfHashEnries, settings.ElementsInBucket, 8);
	if (!deht)
		return 1;

	/*
	To build the rainbow table we iterate many times (about 10 times size of S/chain length.)
		Generate a random password within S:(e.g. aadquy). Name it firstPass.
		Init curHash := MD5(firstPass)
		For j=1 to chain-length do
			k = pseudo-random-function with seed seed[j] and input curHash;
			*
			NewPassword = get_kth_password (k,S)
			curHash = MD5(NewPassword);
		end
		Reduction
		Insert into disk embedded hash table the following pair: key=curHash, data=firstPass
	end
	*/


	// Generate seeds
	seeds = calloc(settings.ChainLength, sizeof(seeds));
	/* initialize random generator */
	srandom(pseudo_random_function(settings.MainRandSeed, strlen(settings.MainRandSeed), 0));
	for(i = 0; i < settings.ChainLength; i++)
	{
		seeds[i] = random();
	}
	write_DEHT_Seed(deht, seeds, settings.ChainLength);

	// TODO Define numOfChains
	for(i = 0; i < numOfChains; i++)
	{
		idx = random() % (passgenctx->numOfPasswords - 1) + 1;
		origpass = pass = generatePassword(passgenctx, lex, idx);
		settings.hashptr(pass, strlen(pass), hashbuf);
		for (j = 0; j <settings.ChainLength; j++)
		{
			k = pseudo_random_function(hashbuf, settings.hashed_password_len, seeds[j]);
			pass = generatePassword(passgenctx, lex, k);
			settings.hashptr(pass, strlen(pass), hashbuf);
			// free(pass);
		}
#ifdef DEBUG
		binary2hexa(hashbuf, settings.hashed_password_len, hexbuf, sizeof(hexbuf));
		printf("The %d chain for %s is \t%s : \t%s\n", i, settings.Rule, origpass, hexbuf);
#endif
		add_DEHT(deht, hashbuf, settings.hashed_password_len, origpass, strlen(origpass));
	}

	lock_DEHT_files(deht);
	freerule(passgenctx);
	// TODO freelex
	return EXIT_SUCCESS;
}
#endif
