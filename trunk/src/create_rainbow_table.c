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

#ifdef CREATE_RAINBOW_TABLE

int main(int argc, char** argv)
{
	rainbow_settings settings;
	lexicon* lex = NULL;
	DEHT* deht = NULL;
	passgencontext* passgenctx = NULL;
	unsigned int passgensize = 0;
	unsigned long k = 0;
	unsigned long numOfChains = 50;
	char origpass[MAX_FIELD + 1] = {0};
	char pass[MAX_FIELD + 1] = {0};
	unsigned long i = 0, j = 0;
	unsigned long idx = 0;
	unsigned long* seeds = NULL;;

	char hashbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];
	char hexbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];

	if (argc != 2)
	{
		fprintf(stderr, "Error: Usage create_rainbow_table <ini filename>\n");
		return 1;
	}

	memset(&settings, 0, sizeof(settings));
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
	srandom((const unsigned int)pseudo_random_function((const unsigned char*)settings.MainRandSeed,
			strlen(settings.MainRandSeed), 0));
	for(i = 0; i < settings.ChainLength - 1; i++)
	{
		seeds[i] = random();
	}
	write_DEHT_Seed(deht, seeds, settings.ChainLength - 1);

	numOfChains = 10 * (passgenctx->numOfPasswords / settings.ChainLength);
	if (numOfChains == 0) numOfChains = 1;
	for(i = 0; i < numOfChains; i++)
	{
		idx = random() % (passgenctx->numOfPasswords - 1) + 1;
		generatePassword(passgenctx, lex, idx, pass);
		strncpy(origpass, pass, MAX_FIELD);
		settings.hashptr((const unsigned char*)pass, strlen(pass), (unsigned char*)hashbuf);
#ifdef DEBUG
			//binary2hexa(hashbuf, settings.hashed_password_len, hexbuf, sizeof(hexbuf));
			//printf("\t%s \t%s\n", pass, hexbuf);
#endif
		for (j = 0; j <settings.ChainLength - 1; j++)
		{
			k = pseudo_random_function((const unsigned char*)hashbuf, settings.hashed_password_len, seeds[j]);
			generatePassword(passgenctx, lex, k, pass);
			settings.hashptr((unsigned char*)pass, strlen(pass), (unsigned char*)hashbuf);
#ifdef DEBUG
			binary2hexa((unsigned char*)hashbuf, settings.hashed_password_len, hexbuf, sizeof(hexbuf));
			// printf("\t%s \t%s\n", pass, hexbuf);
#endif
		}
#ifdef DEBUG
		binary2hexa((unsigned char*)hashbuf, settings.hashed_password_len, hexbuf, sizeof(hexbuf));
		printf("%2.1f%%: The %lu/%lu chain for %s is \t%s : \t%s\n", 100*((float)i/(float)numOfChains),
				i, numOfChains,	settings.Rule, origpass, hexbuf);
#endif
		add_DEHT(deht, (unsigned char*)hashbuf, settings.hashed_password_len, (unsigned char*)origpass, strlen(origpass));
	}

	lock_DEHT_files(deht);
	freerule(passgenctx);
	freelex(lex);
	free(seeds);
	printf("Done.\n");
	return EXIT_SUCCESS;
}
#endif
