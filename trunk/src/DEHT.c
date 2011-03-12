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
	return 0;
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
	if ((d->dataFP = fopen(d->sDataFileName, "wb")) == NULL)
	{
		perror("Could not open DEHT data file");
		return NULL;
	}
	if ((d->keyFP = fopen(d->sKeyFileName, "wb")) == NULL)
	{
		perror("Could not open DEHT key file");
		return NULL;
	}

	//TODO: init inserts helpers
	d->anLastBlockSize = NULL;
	d->hashPointersForLastBlockImageInMemory = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR));
	d->hashTableOfPointersImageInMemory = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR));

	if (sizeof(d->header) != fwrite(&(d->header), sizeof(d->header), 1, d->keyFP))
	{
		perror("Could not write DEHT header");
		return NULL;
	}

	if (sizeof(d->hashTableOfPointersImageInMemory) != fwrite(&(d->hashTableOfPointersImageInMemory),
			sizeof(d->hashTableOfPointersImageInMemory), 1, d->keyFP))
	{
		perror("Could not write DEHT pointers table");
		return NULL;
	}
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
	PAIR* block = calloc(ht->header.nPairsPerBlock, sizeof(PAIR));

	int hashIndex = ht->hashFunc(key, keyLength, ht->header.numEntriesInHashTable);
	if (ht->hashTableOfPointersImageInMemory)
	{
		if (ht->hashPointersForLastBlockImageInMemory)
		{
			if (ht->hashPointersForLastBlockImageInMemory[hashIndex] == 0)
			{
				if (sizeof(BLOCK_HEADER) != fwrite(bheader,	sizeof(BLOCK_HEADER), 1, ht->keyFP))
				{
					perror("Could not write DEHT new block header");
					return NULL;
				}
				if (sizeof(block) != fwrite(block, sizeof(block), 1, ht->keyFP))
				{
					perror("Could not write DEHT new block");
					return NULL;
				}
			}
			else
			{

			}
		}
	}
	return DEHT_STATUS_SUCCESS;
}
