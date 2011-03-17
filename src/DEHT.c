/*
 * DEHT.c
 *
 *  Created on: Mar 12, 2011
 *      Author: a
 */

#include "DEHT.h"
#include "helpers.h"

/****************************************************************************/
/* type definition of hashKeyIntoTableFunctionPtr:                          */
/* Definition of what is a data-structre hash-function (not the cryptic one)*/
/* These function take a key and output an index in pointer table           */
/* Note that these function operates on the original key (not condensed one)*/
/* These function shall never fail (i.e. never return -1 or so)             */
/****************************************************************************/
/*Arguments are: */
/* const unsigned char *keyBuf, i.e. Binary buffer input*/
/* int keySizeof , i.e. in this project this is crypt output size, */
/*          but in real life this size may vary (e.g. string input)*/
/* int nTableSize, i.e. Output is 0 to (nTableSize-1) to fit table of pointers*/
int hashfun(const unsigned char *keyBuf, int keySizeof, int nTableSize)
{
	char* outbuf = calloc(1, MD5_OUTPUT_LENGTH_IN_BYTES);
	int retVal = 0;
	MD5BasicHash(keyBuf, keySizeof, outbuf);
	retVal = (*(int*)(outbuf)) & (nTableSize-1);
	return retVal;
}

/****************************************************************************/
/* type definition of hashKeyforEfficientComparisonFunctionPtr:             */
/* I is made to create a key signature (stored in DEHT) that distinguish    */
/* it from any other key in same bucket. Namely to correct false matches    */
/* caused by the hashKeyIntoTableFunctionPtr, thus must be independent of it*/
/* Note that these functions consider nBytesPerValidationKey as hard coded  */
/* E.g. stringTo32bit(very widely used) or cryptHashTo64bit(as in this proj)*/
/****************************************************************************/
/*Arguments are: */
/* const unsigned char *keyBuf, i.e. Binary buffer input*/
/* int keySizeof , i.e. in this project this is crypt output size, */
/*          but in real life this size may vary (e.g. string input)*/
/* unsigned char *validationKeyBuf, i.e. Output buffer, assuming allocated with nBytesPerValidationKey bytes*/
int validfun(const unsigned char *keyBuf, int keySizeof,
		unsigned char *validationKeyBuf)
{
	return (memcmp(keyBuf, validationKeyBuf, MIN(keySizeof, 8)) == 0);

}

DEHT *create_empty_DEHT(const char *prefix,/*add .key and .data to open two files return NULL if fail creation*/
                        hashKeyIntoTableFunctionPtr hashfun, hashKeyforEfficientComparisonFunctionPtr validfun,
                        const char *dictName,   /*e.g. MD5\0 */
                        int numEntriesInHashTable, int nPairsPerBlock, int nBytesPerKey) /*optimization preferences*/
{
	DEHT* d = calloc(1, sizeof(DEHT));
	sprintf(d->sKeyFileName, "%s.key", prefix);
	sprintf(d->sDataFileName, "%s.data", prefix);
	d->hashFunc = hashfun;
	d->comparisonHashFunc = validfun;
	snprintf(d->header.sHashName, sizeof(d->header.sHashName), "%s", dictName);
	d->header.nPairsPerBlock = nPairsPerBlock;
	d->header.numEntriesInHashTable = numEntriesInHashTable;
	d->header.nBytesPerValidationKey = nBytesPerKey;
	if ((d->dataFP = fopen(d->sDataFileName, "w+b")) == NULL)
	{
		perror("Could not open DEHT data file");
		return NULL;
	}
	if ((d->keyFP = fopen(d->sKeyFileName, "w+b")) == NULL)
	{
		perror("Could not open DEHT key file");
		return NULL;
	}

	//TODO: init inserts helpers
	d->anLastBlockSize = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR)); /*Tail offset*/
	d->hashPointersForLastBlockImageInMemory = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR)); /*Tail*/
	d->hashTableOfPointersImageInMemory = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR));

	int written = 0;
	if (sizeof(d->header) != (written = fwrite(&(d->header), 1, sizeof(d->header), d->keyFP)))
	{
		printf("%d\n", written);
		perror("Could not write DEHT header");
		return NULL;
	}

	if (d->header.numEntriesInHashTable != fwrite(d->hashTableOfPointersImageInMemory,
			sizeof(DEHT_DISK_PTR), d->header.numEntriesInHashTable, d->keyFP))
	{
		perror("Could not write DEHT pointers table");
		return NULL;
	}
#ifdef DEBUG
	fflush(d->keyFP);
#endif
	return d;
}

/********************************************************************************/
/* Function add_DEHT inserts an ellement,                                       */
/*    whenever exists or not                                                    */
/* Inputs: DEHT to insert into, key and data (as binary buffer with size)       */
/* Output: just status of action:                                               */
/* If successfully insert returns DEHT_STATUS_SUCCESS.                          */
/* If fail, returns DEHT_STATUS_FAIL                                            */
/* Notes:                                                                       */
/* if hashPointersForLastBlockImageInMemory!=NULL use it (save "fseek" commands)*/
/* if anLastBlockSize not null use it either.                                   */
/* if hashTableOfPointersImageInMemory use it (less efficient but stil helps)   */
/* if both null, do not load table of pointers into memory just make simple     */
/* insert using several fseek when necessary.                                   */
/********************************************************************************/
int add_DEHT ( DEHT *ht, const unsigned char *key, int keyLength,
				 const unsigned char *data, int dataLength)
{
	BLOCK_HEADER* bheader = calloc(1, sizeof(BLOCK_HEADER));;
	TRIPLE* block = calloc(ht->header.nPairsPerBlock, sizeof(TRIPLE));
	DEHT_DISK_PTR lastPtr = 0;
	DEHT_DISK_PTR lastDataPtr = 0;
	TRIPLE triple;

	if (0 != fseek(ht->keyFP, 0, SEEK_END))
	{
		free(block);
		perror("Could not seek to keyFP EOF");
		return DEHT_STATUS_FAIL;
	}
	lastPtr = ftell(ht->keyFP);

	int hashIndex = ht->hashFunc(key, keyLength, ht->header.numEntriesInHashTable);
	if (ht->hashTableOfPointersImageInMemory)
	{
		if (ht->hashPointersForLastBlockImageInMemory)
		{
			/* if needed, allocate new block */
			if ((ht->anLastBlockSize[hashIndex] == ht->header.nPairsPerBlock) ||
					(ht->hashPointersForLastBlockImageInMemory[hashIndex] == 0))
			{


				/* update memory pointers */
				/* first block for entry */
				if (ht->hashPointersForLastBlockImageInMemory[hashIndex] == 0)
				{
					ht->hashTableOfPointersImageInMemory[hashIndex] = lastPtr;
				}
				/* allocate new block for existing entry */
				else if (ht->anLastBlockSize[hashIndex] == ht->header.nPairsPerBlock)
				{
					/* go to last block for the desired key */
					fseek(ht->keyFP, ht->hashPointersForLastBlockImageInMemory[hashIndex], SEEK_SET);
					bheader->next = lastPtr;
					if (sizeof(BLOCK_HEADER) != fwrite(bheader,	1, sizeof(BLOCK_HEADER), ht->keyFP))
					{
						perror("Could not write DEHT new block header");
						return NULL;
					}
				}

				/* add new block the the end with empty header and fresh blocks */
				ht->hashPointersForLastBlockImageInMemory[hashIndex] = lastPtr;
				fseek(ht->keyFP, lastPtr, SEEK_SET);
				bheader->next = 0;
				if (sizeof(BLOCK_HEADER) != fwrite(bheader,	1, sizeof(BLOCK_HEADER), ht->keyFP))
				{
					perror("Could not write DEHT new block header");
					return NULL;
				}
#ifdef DEBUG
	fflush(ht->keyFP);
#endif
				if (ht->header.nPairsPerBlock != fwrite(block, sizeof(TRIPLE), ht->header.nPairsPerBlock, ht->keyFP))
				{
					perror("Could not write DEHT new block");
					return NULL;
				}
#ifdef DEBUG
	fflush(ht->keyFP);
#endif
				ht->anLastBlockSize[hashIndex] = 0;
			}

			/* add new triple */
			fseek(ht->dataFP, 0, SEEK_END);
			lastDataPtr = ftell(ht->dataFP);
			/* write new data */
			if (dataLength != fwrite(data, 1, dataLength, ht->dataFP))
			{
				perror("Could not write DEHT new data");
				return NULL;
			}
#ifdef DEBUG
	fflush(ht->dataFP);
#endif
			lastPtr = ht->hashPointersForLastBlockImageInMemory[hashIndex] + sizeof(BLOCK_HEADER) + sizeof(TRIPLE)*ht->anLastBlockSize[hashIndex];
			triple.dataptr = lastDataPtr;
			triple.datalen = dataLength;
			memset(&triple.key, 0, sizeof(triple.key)); /* zero */
			memcpy(&triple.key, key, MIN(keyLength, sizeof(triple.key)));
			fseek(ht->keyFP, lastPtr, SEEK_SET);
			/* write new key */
			if (sizeof(triple) != fwrite(&triple, 1, sizeof(triple), ht->keyFP))
			{
				perror("Could not write DEHT new key");
				return NULL;
			}
#ifdef DEBUG
	fflush(ht->keyFP);
#endif
			ht->anLastBlockSize[hashIndex]++;
		}
	}
	return DEHT_STATUS_SUCCESS;
}

/************************************************************************************/
/* Function write_DEHT_pointers_table writes pointer of tables RAM to Disk & release*/
/* Input: DEHT to act on.                                                           */
/* Output:                                                                          */
/* If not RAM pointer is NULL, return DEHT_STATUS_NOT_NEEDED                        */
/* if fail return DEHT_STATUS_FAIL, if success return DEHT_STATUS_SUCCESS           */
/* Note: do not forget to use "free" and put NULL.                                  */
/************************************************************************************/
int write_DEHT_pointers_table(DEHT *ht)
{
	if (!ht->hashTableOfPointersImageInMemory)
		return DEHT_STATUS_NOT_NEEDED;

	fseek(ht->keyFP, sizeof(ht->header), SEEK_SET);

	if (ht->header.numEntriesInHashTable != fwrite(ht->hashTableOfPointersImageInMemory,
			sizeof(DEHT_DISK_PTR), ht->header.numEntriesInHashTable, ht->keyFP))
	{
		perror("Could not write DEHT pointers table");
		return DEHT_STATUS_FAIL;
	}
	fflush(ht->keyFP);
	return DEHT_STATUS_SUCCESS;
}

/********************************************************************************/
/* Function query_DEHT query a key.                                             */
/* Inputs: DEHT to query in, key input and data output buffer.                  */
/* Output:                                                                      */
/* If successfully insert returns number of bytes fullfiled in data buffer      */
/* If not found returns DEHT_STATUS_NOT_NEEDED                                  */
/* If fail returns DEHT_STATUS_FAIL                                             */
/* Notes:                                                                       */
/* If hashTableOfPointersImageInMemory!=NULL use it to save single seek.        */
/* Else access using table of pointers on disk.                                 */
/* "ht" argument is non const as fseek is non const too (will change "keyFP")   */
/********************************************************************************/
int query_DEHT ( DEHT *ht, const unsigned char *key, int keyLength,
				 unsigned char *data, int dataMaxAllowedLength)
{
	int retVal = 0;
	unsigned char** dataPointer = calloc(2,sizeof(char*));
	if (mult_query_DEHT (ht, key, keyLength, data, dataMaxAllowedLength, dataPointer,2) == 0)
	{
		free (dataPointer);
		return DEHT_STATUS_NOT_NEEDED;
	}
	retVal = dataPointer[1] - dataPointer[0];
	free(dataPointer);
	return retVal;
}

/********************************************************************************/
/* Function mult_query_DEHT query a key and return all possible matches.        */
/* Inputs: DEHT to query in, key input, data output buffer ans its size, 		*/
/*         array of pointers to output buffer and its size.						*/
/* Output:                                                                      */
/* If successfully query returns number of matches found 	 			        */
/* If fail returns DEHT_STATUS_FAIL                                             */
/* Notes:                                                                       */
/* If hashTableOfPointersImageInMemory!=NULL use it to save single seek.        */
/* Else access using table of pointers on disk.                                 */
/* "ht" argument is non const as fseek is non const too (will change "keyFP")   */
/********************************************************************************/
int mult_query_DEHT ( DEHT *ht, const unsigned char *key, int keyLength,
				 unsigned char *data, int dataMaxAllowedLength,
				 unsigned char **dataPointer, int dataPointerLength)
{
	int hashIndex = ht->hashFunc(key, keyLength, ht->header.numEntriesInHashTable);
	BLOCK_HEADER* bheader = (BLOCK_HEADER*)calloc(1, sizeof(BLOCK_HEADER));;
	TRIPLE* block = (TRIPLE*)calloc(ht->header.nPairsPerBlock, sizeof(TRIPLE));
	char quit = 0;
	int counter = 0;
	int numOfMatches = 0;
	unsigned char* lastDataPtr = data;
	dataPointerLength--;

	if (ht == NULL)
		return DEHT_STATUS_FAIL;

	if (ht->hashTableOfPointersImageInMemory[hashIndex] == 0)
	{
		return 0;
	}

	fseek(ht->keyFP, ht->hashTableOfPointersImageInMemory[hashIndex], SEEK_SET);

	while (!quit)
	{
		int readbytes = fread(bheader, 1, sizeof(bheader), ht->keyFP);
		long test = ftell(ht->keyFP);
		if (sizeof(bheader) != readbytes)
		{
			perror("Could not read DEHT block header");
			return 0;
		}

		/* read whole block */
		if (ht->header.nPairsPerBlock == fread(block, ht->header.nPairsPerBlock, sizeof(TRIPLE), ht->keyFP))
		{
			perror("Could not read DEHT whole block");
			return 0;
		}

		/* iterate over block triplets */
		while (counter < ht->header.nPairsPerBlock)
		{
			if (block[counter].datalen == 0)
			{
				quit = 1;
				break;
			}
			if (ht->comparisonHashFunc(key, keyLength, block[counter].key))
			{
				/* valid match found, copy to output buffer */
				fseek(ht->dataFP, block[counter].dataptr, SEEK_SET);
				/* read data */
				if (lastDataPtr - data + block[counter].datalen > dataMaxAllowedLength)
				{
					quit = 1;
					break;
				}
				dataPointer[numOfMatches] = lastDataPtr;
				if (block[counter].datalen == fread(dataPointer[numOfMatches], block[counter].datalen, 1, ht->dataFP))
				{
					perror("Could not read DEHT data");
					return 0;
				}
				numOfMatches++;
				lastDataPtr += block[counter].datalen;
				dataPointer[numOfMatches] = lastDataPtr;
				if (numOfMatches == dataPointerLength)
				{
					quit = 1;
					break;
				}
			}
			/* advance to next block */
			counter++;
			if (counter == ht->header.nPairsPerBlock)
			{
				fseek(ht->keyFP, bheader->next, SEEK_SET);
				counter = 0;
				break;
			}
		}
	}
	return numOfMatches;
}
