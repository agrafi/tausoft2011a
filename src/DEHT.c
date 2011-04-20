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
	unsigned char* outbuf = calloc(1, MD5_OUTPUT_LENGTH_IN_BYTES);
	int retVal = 0;
	MD5BasicHash(keyBuf, keySizeof, outbuf);
	retVal = (*(int*)(outbuf)) & (nTableSize-1);
	free(outbuf);
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

void release_deht(DEHT* d)
{
	if (d->hashPointersForLastBlockImageInMemory)
	{
		free(d->hashPointersForLastBlockImageInMemory);
		d->hashPointersForLastBlockImageInMemory = NULL;
	}

	if (d->anLastBlockSize)
	{
		free(d->anLastBlockSize);
		d->anLastBlockSize = NULL;
	}

	if (d->hashTableOfPointersImageInMemory)
	{
		free(d->hashTableOfPointersImageInMemory);
		d->hashTableOfPointersImageInMemory = NULL;
	}

	if (d->dataFP)
		fclose(d->dataFP);
	if (d->keyFP)
		fclose(d->keyFP);
	if (d->seedFP)
		fclose(d->seedFP);
	free(d);
	return;
}

DEHT *create_empty_DEHT(const char *prefix,/*add .key and .data to open two files return NULL if fail creation*/
                        hashKeyIntoTableFunctionPtr hashfun, hashKeyforEfficientComparisonFunctionPtr validfun,
                        const char *dictName,   /*e.g. MD5\0 */
                        int numEntriesInHashTable, int nPairsPerBlock, int nBytesPerKey) /*optimization preferences*/
{
	DEHT* d = calloc(1, sizeof(DEHT));
	if (!d)
		return NULL;

	sprintf(d->sKeyFileName, "%s.key", prefix);
	sprintf(d->sDataFileName, "%s.data", prefix);
	sprintf(d->sSeedFileName, "%s.seed", prefix);
	d->hashFunc = hashfun;
	d->comparisonHashFunc = validfun;
	snprintf(d->header.sHashName, sizeof(d->header.sHashName), "%s", dictName);
	d->header.nPairsPerBlock = nPairsPerBlock;
	d->header.numEntriesInHashTable = numEntriesInHashTable;
	d->header.nBytesPerValidationKey = nBytesPerKey;

	if (fileexists(d->sKeyFileName))
	{
		fprintf(stderr, "Error: File \"%s\" already exists\n", d->sKeyFileName);
		release_deht(d);
		return NULL;
	}
	if (fileexists(d->sDataFileName))
	{
		fprintf(stderr, "Error: File \"%s\" already exists\n", d->sDataFileName);
		release_deht(d);
		return NULL;
	}
	if (fileexists(d->sSeedFileName))
	{
		fprintf(stderr, "Error: File \"%s\" already exists\n", d->sSeedFileName);
		release_deht(d);
		return NULL;
	}

	if ((d->dataFP = fopen(d->sDataFileName, "w+b")) == NULL)
	{
		perror("Could not open DEHT data file");
		release_deht(d);
		return NULL;
	}
	if ((d->keyFP = fopen(d->sKeyFileName, "w+b")) == NULL)
	{
		perror("Could not open DEHT key file");
		release_deht(d);
		return NULL;
	}
	if ((d->seedFP = fopen(d->sSeedFileName, "w+b")) == NULL)
	{
		perror("Could not open DEHT seed file");
		release_deht(d);
		return NULL;
	}

	d->anLastBlockSize = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR)); /*Tail offset*/
	if (!d->anLastBlockSize)
	{
		release_deht(d);
		return NULL;
	}

	d->hashPointersForLastBlockImageInMemory = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR)); /*Tail*/
	if (!d->hashPointersForLastBlockImageInMemory)
	{
		release_deht(d);
		return NULL;
	}

	d->hashTableOfPointersImageInMemory = calloc(d->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR));
	if (!d->hashTableOfPointersImageInMemory)
	{
		release_deht(d);
		return NULL;
	}

	int written = 0;
	if (sizeof(d->header) != (written = fwrite(&(d->header), 1, sizeof(d->header), d->keyFP)))
	{
		perror("Could not write DEHT header");
		release_deht(d);
		return NULL;
	}

	if (d->header.numEntriesInHashTable != fwrite(d->hashTableOfPointersImageInMemory,
			sizeof(DEHT_DISK_PTR), d->header.numEntriesInHashTable, d->keyFP))
	{
		perror("Could not write DEHT pointers table");
		release_deht(d);
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
	BLOCK_HEADER bheader;
	TRIPLE block[ht->header.nPairsPerBlock];
	DEHT_DISK_PTR lastPtr = 0;
	DEHT_DISK_PTR lastDataPtr = 0;
	TRIPLE triple;
	memset(&bheader, 0, sizeof(bheader));
	memset(&block, 0, sizeof(block));
	memset(&triple, 0, sizeof(triple));

	if (0 != fseek(ht->keyFP, 0, SEEK_END))
	{
		perror("Could not seek to keyFP EOF");
		return DEHT_STATUS_FAIL;
	}

	if (-1 == (lastPtr = ftell(ht->keyFP)))
	{
		perror("Could not ftell keyFP");
		return DEHT_STATUS_FAIL;
	}

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

					if (0 != fseek(ht->keyFP, ht->hashPointersForLastBlockImageInMemory[hashIndex], SEEK_SET))
					{
						perror("Could not seek keyFP");
						return DEHT_STATUS_FAIL;
					}

					bheader.next = lastPtr;
					if (sizeof(BLOCK_HEADER) != fwrite(&bheader, 1, sizeof(BLOCK_HEADER), ht->keyFP))
					{
						perror("Could not write DEHT new block header");
						return DEHT_STATUS_FAIL;
					}
				}

				/* add new block the the end with empty header and fresh blocks */
				ht->hashPointersForLastBlockImageInMemory[hashIndex] = lastPtr;
				if (0 != fseek(ht->keyFP, lastPtr, SEEK_SET))
				{
					perror("Could not seek keyFP");
					return DEHT_STATUS_FAIL;
				}

				bheader.next = 0;
				if (sizeof(BLOCK_HEADER) != fwrite(&bheader, 1, sizeof(BLOCK_HEADER), ht->keyFP))
				{
					perror("Could not write DEHT new block header");
					return DEHT_STATUS_FAIL;
				}
				if (ht->header.nPairsPerBlock != fwrite(&block, sizeof(TRIPLE), ht->header.nPairsPerBlock, ht->keyFP))
				{
					perror("Could not write DEHT new block");
					return DEHT_STATUS_FAIL;
				}
				ht->anLastBlockSize[hashIndex] = 0;
			}

			/* add new triple */
			if (0 != fseek(ht->dataFP, 0, SEEK_END))
			{
				perror("Could not seek dataFP");
				return DEHT_STATUS_FAIL;
			}

			if (-1 == (lastDataPtr = ftell(ht->dataFP)))
			{
				perror("Could not ftell dataFP");
				return DEHT_STATUS_FAIL;
			}

			/* write new data */
			if (dataLength != fwrite(data, 1, dataLength, ht->dataFP))
			{
				perror("Could not write DEHT new data");
				return DEHT_STATUS_FAIL;
			}
			lastPtr = ht->hashPointersForLastBlockImageInMemory[hashIndex] + sizeof(BLOCK_HEADER) + sizeof(TRIPLE)*ht->anLastBlockSize[hashIndex];
			triple.dataptr = lastDataPtr;
			triple.datalen = dataLength;
			memset(&triple.key, 0, sizeof(triple.key)); /* zero */
			memcpy(&triple.key, key, MIN(keyLength, sizeof(triple.key)));

			if (0 != fseek(ht->keyFP, lastPtr, SEEK_SET))
			{
				perror("Could not seek keyFP");
				return DEHT_STATUS_FAIL;
			}

			/* write new key */
			if (sizeof(triple) != fwrite(&triple, 1, sizeof(triple), ht->keyFP))
			{
				perror("Could not write DEHT new key");
				return DEHT_STATUS_FAIL;
			}
			ht->anLastBlockSize[hashIndex]++;
		}
	}
	return DEHT_STATUS_SUCCESS;
}

/********************************************************************************/
/* Function insert_uniquely_DEHT inserts an ellement.                           */
/* Inputs: DEHT to insert into, key and data (as binary buffer with size)       */
/* Output: just status of action:                                               */
/* If exist updates data and returns DEHT_STATUS_NOT_NEEDED                     */
/* If successfully insert returns DEHT_STATUS_SUCCESS.                          */
/* If fail, returns C                                            */
/* Notes:                                                                       */
/* if hashTableOfPointersImageInMemory use it                                   */
/* if  null, do not load table of pointers into memory just make simple         */
/* insert using several fseek when necessary.                                   */
/********************************************************************************/
int insert_uniquely_DEHT ( DEHT *ht, const unsigned char *key, int keyLength,
				 const unsigned char *data, int dataLength)
{
	int retVal = query_DEHT ( ht, key, keyLength, (unsigned char *)data, dataLength);
	if(retVal == DEHT_STATUS_FAIL)
	{
		return DEHT_STATUS_FAIL;
	}
	else if(retVal == 0)
	{
		return add_DEHT(ht, key, keyLength, data, dataLength);
	}

	return DEHT_STATUS_NOT_NEEDED;
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

	if (0 != fseek(ht->keyFP, sizeof(ht->header), SEEK_SET))
	{
		perror("Could not seek keyFP");
		return DEHT_STATUS_FAIL;
	}
	if (ht->header.numEntriesInHashTable != fwrite(ht->hashTableOfPointersImageInMemory,
			sizeof(DEHT_DISK_PTR), ht->header.numEntriesInHashTable, ht->keyFP))
	{
		perror("Could not write DEHT pointers table");
		return DEHT_STATUS_FAIL;
	}

	if (0 != fflush(ht->keyFP))
	{
		perror("Could not flush keyFP");
		return DEHT_STATUS_FAIL;
	}

	free(ht->hashTableOfPointersImageInMemory);
	ht->hashTableOfPointersImageInMemory = NULL;
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
	if (!dataPointer)
	{
		return DEHT_STATUS_FAIL;
	}

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
	BLOCK_HEADER bheader;
	TRIPLE block[ht->header.nPairsPerBlock];
	char quit = 0;
	int counter = 0;
	int numOfMatches = 0;
	unsigned char* lastDataPtr = data;
	dataPointerLength--;

	memset(&bheader, 0, sizeof(bheader));
	memset(&block, 0, sizeof(block));

	if (ht == NULL)
		return DEHT_STATUS_FAIL;

	if (dataPointer != NULL)
	{
		memset(dataPointer, 0, dataPointerLength * sizeof(unsigned char *));
	}

	if (ht->hashTableOfPointersImageInMemory[hashIndex] == 0)
	{
		return 0;
	}

	if (0 != fseek(ht->keyFP, ht->hashTableOfPointersImageInMemory[hashIndex], SEEK_SET))
	{
		perror("Could not seek keyFP");
		return DEHT_STATUS_FAIL;
	}

	while (!quit)
	{
		if (sizeof(bheader) != fread(&bheader, 1, sizeof(bheader), ht->keyFP))
		{
			perror("Could not read DEHT block header");
			return 0;
		}

		/* read whole block */
		if (ht->header.nPairsPerBlock == fread(&block, ht->header.nPairsPerBlock, sizeof(TRIPLE), ht->keyFP))
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
				if (0 != fseek(ht->dataFP, block[counter].dataptr, SEEK_SET))
				{
					perror("Could not seek dataFP");
					return DEHT_STATUS_FAIL;
				}

				/* read data */
				if (lastDataPtr - data + block[counter].datalen > dataMaxAllowedLength)
				{
					quit = 1;
					break;
				}
				dataPointer[numOfMatches] = lastDataPtr;
				if (block[counter].datalen != fread(dataPointer[numOfMatches], 1, block[counter].datalen, ht->dataFP))
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
				if (0 != fseek(ht->keyFP, bheader.next, SEEK_SET))
				{
					perror("Could not seek keyFP");
					return DEHT_STATUS_FAIL;
				}
				counter = 0;
				break;
			}
		}
	}
	return numOfMatches;
}

/************************************************************************************/
/* Function lock_DEHT_files closes the DEHT files and release memory.               */
/* Input: DEHT to act on. No Output (never fail).                                   */
/* Notes:                                                                           */
/* calls write_DEHT_hash_table if necessary, call "free" when possible.             */
/* use "fclose" command. do not free "FILE *"                                       */
/************************************************************************************/
void lock_DEHT_files(DEHT *ht)
{
	write_DEHT_pointers_table(ht);
	release_deht(ht);
}

/********************************************************************************/
/* Function load_DEHT_from_files importes files created by previously used DEHT */
/* Inputs: file names on disk (as prefix).                                      */
/* Output: an allocated DEHT struct pointer.                                    */
/* Notes:                                                                       */
/* It open files (RW permissions) and create appropriate data-strucre on memory */
/* hashTableOfPointersImageInMemory, hashPointersForLastBlockImageInMemory:=NULL*/
/* Returns NULL if fail (e.g. files are not exist) with message to stderr       */
/********************************************************************************/
DEHT *load_DEHT_from_files(const char *prefix,
						   hashKeyIntoTableFunctionPtr hashfun, hashKeyforEfficientComparisonFunctionPtr validfun)
{
	DEHT* d = calloc(1, sizeof(DEHT));
	sprintf(d->sKeyFileName, "%s.key", prefix);
	sprintf(d->sDataFileName, "%s.data", prefix);
	sprintf(d->sSeedFileName, "%s.seed", prefix);
	d->hashFunc = hashfun;
	d->comparisonHashFunc = validfun;

	if ((d->dataFP = fopen(d->sDataFileName, "r+b")) == NULL)
	{
		perror("Could not open DEHT data file");
		return NULL;
	}
	if ((d->keyFP = fopen(d->sKeyFileName, "r+b")) == NULL)
	{
		perror("Could not open DEHT key file");
		return NULL;
	}
	if ((d->seedFP = fopen(d->sSeedFileName, "r+b")) == NULL)
	{
		perror("Could not open DEHT seed file");
		return NULL;
	}

	if (0 != fseek(d->keyFP, 0, SEEK_SET))
	{
		perror("Could not seek keyFP");
		return NULL;
	}

	/* read header */
	if (sizeof(d->header) != fread(&(d->header), 1,sizeof(d->header), d->keyFP))
	{
		perror("Could not read DEHT header");
		return NULL;
	}

	if (DEHT_STATUS_FAIL == read_DEHT_pointers_table(d))
	{
		perror("Could not read_DEHT_pointers_table");
		return NULL;
	}

	if (DEHT_STATUS_FAIL == calc_DEHT_last_block_per_bucket(d))
	{
		perror("Could not calc_DEHT_last_block_per_bucket");
		return NULL;
	}
	return d;

}
/************************************************************************************/
/* Function read_DEHT_pointers_table loads pointer of tables from disk into RAM     */
/* It will be used for effciency, e.g. when many queries expected soon              */
/* Input: DEHT to act on. (will change member hashTableOfPointersImageInMemory).    */
/* Output:                                                                          */
/* If it is already cached, do nothing and return DEHT_STATUS_NOT_NEEDED.           */
/* If fail, return DEHT_STATUS_FAIL, if success return DEHT_STATUS_NOT_SUCCESS      */
/************************************************************************************/
int read_DEHT_pointers_table(DEHT *ht)
{
	if (ht->hashTableOfPointersImageInMemory)
		return DEHT_STATUS_NOT_NEEDED;

	ht->hashTableOfPointersImageInMemory = calloc(ht->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR));
	if (!ht->hashTableOfPointersImageInMemory)
	{
		return DEHT_STATUS_FAIL;
	}

	if (0 != fseek(ht->keyFP, sizeof(ht->header), SEEK_SET))
	{
		perror("Could not seek keyFP");
		free(ht->hashTableOfPointersImageInMemory);
		return DEHT_STATUS_FAIL;
	}

	/* read table of pointers */
	if (ht->header.numEntriesInHashTable != fread(ht->hashTableOfPointersImageInMemory,
			sizeof(DEHT_DISK_PTR), ht->header.numEntriesInHashTable, ht->keyFP))
	{
		perror("Could not read DEHT table of pointers");
		free(ht->hashTableOfPointersImageInMemory);
		return DEHT_STATUS_FAIL;
	}

	return calc_DEHT_last_block_per_bucket(ht);
}

/************************************************************************************/
/* Function calc_DEHT_last_block_per_bucket calculate all rear pointers on key file */
/*   to enable insertion with a single seek. Will be called by user when many insert*/
/*   calls are expected. Note that these has no parallel on disk thus no "write"    */
/* Input: DEHT to act on (modify hashPointersForLastBlockImageInMemory)             */
/* Output:                                                                          */
/* If it is already exist, do nothing and return DEHT_STATUS_NOT_NEEDED.            */
/* If fail, return DEHT_STATUS_FAIL, if success return DEHT_STATUS_NOT_SUCCESS      */
/************************************************************************************/
int calc_DEHT_last_block_per_bucket(DEHT *ht)
{
	int i = 0, counter = 0;
	BLOCK_HEADER bheader;
	TRIPLE block[ht->header.nPairsPerBlock];

	memset(&bheader, 0, sizeof(bheader));
	memset(&block, 0, sizeof(block));

	if (ht->hashPointersForLastBlockImageInMemory)
	{
		return DEHT_STATUS_NOT_NEEDED;
	}

	ht->anLastBlockSize = calloc(ht->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR)); /*Tail offset*/
	if (!ht->anLastBlockSize)
	{
		return DEHT_STATUS_FAIL;
	}

	ht->hashPointersForLastBlockImageInMemory = calloc(ht->header.numEntriesInHashTable, sizeof(DEHT_DISK_PTR)); /*Tail*/
	if (!ht->hashPointersForLastBlockImageInMemory)
	{
		free(ht->anLastBlockSize);
		return DEHT_STATUS_FAIL;
	}

	for (i = 0; i < ht->header.numEntriesInHashTable; i++)
	{
		if (ht->hashTableOfPointersImageInMemory[i] != 0)
		{
			/* find last block */
			ht->hashPointersForLastBlockImageInMemory[i] = ht->hashTableOfPointersImageInMemory[i];
			if (0 != fseek(ht->keyFP, ht->hashTableOfPointersImageInMemory[i], SEEK_SET))
			{
				perror("Could not seek keyFP");
				free(ht->hashTableOfPointersImageInMemory);
				free(ht->anLastBlockSize);
				return DEHT_STATUS_FAIL;
			}
			while (1)
			{
				if (sizeof(bheader) != fread(&bheader, 1, sizeof(bheader), ht->keyFP))
				{
					perror("Could not read DEHT block header");
					free(ht->hashTableOfPointersImageInMemory);
					free(ht->anLastBlockSize);
					return DEHT_STATUS_FAIL;
				}
				if (bheader.next == 0)
					break;
				ht->hashPointersForLastBlockImageInMemory[i] = bheader.next;
			}

			/* enumerate triplets on last block */
			if (0 != fseek(ht->keyFP, ht->hashPointersForLastBlockImageInMemory[i], SEEK_SET))
			{
				perror("Could not seek keyFP");
				free(ht->hashTableOfPointersImageInMemory);
				free(ht->anLastBlockSize);
				return DEHT_STATUS_FAIL;
			}
			/* read whole block */
			if (ht->header.nPairsPerBlock == fread(block, ht->header.nPairsPerBlock, sizeof(TRIPLE), ht->keyFP))
			{
				perror("Could not read DEHT whole block");
				free(ht->hashTableOfPointersImageInMemory);
				free(ht->anLastBlockSize);
				return DEHT_STATUS_FAIL;
			}

			/* iterate over block triplets */
			counter = 0;
			while (counter < ht->header.nPairsPerBlock)
			{
				if (block[counter].datalen == 0)
					break;
				counter++;
			}
			ht->anLastBlockSize[i] = counter;
		}
	}
	return DEHT_STATUS_SUCCESS;
}

/************************************************************************************/
/* Function read_DEHT_Seed loads rainbow table seeds from disk into RAM.			*/
/* Input: DEHT to act on, output buffer and its size.								*/
/* Return value: DEHT_STATUS_FAIL on failure, or DEHT_STATUS_SUCCESS on success.	*/
/************************************************************************************/
int read_DEHT_Seed(DEHT * d, void * table,int size)
{
	if (size != fread(table, sizeof(unsigned long), size, d->seedFP))
	{
		perror("Could not read DEHT seed table");
		return DEHT_STATUS_FAIL;
	}
	return DEHT_STATUS_SUCCESS;
}


/************************************************************************************/
/* Function write_DEHT_Seed dumps rainbow table seeds from RAM into disk.			*/
/* Input: DEHT to act on, input buffer and its size.								*/
/* Return value: DEHT_STATUS_FAIL on failure, or DEHT_STATUS_SUCCESS on success.	*/
/************************************************************************************/
int write_DEHT_Seed(DEHT * d, const void * table,int size)
{
	if (size != fwrite(table, sizeof(unsigned long), size, d->seedFP))
	{
		perror("Could not write DEHT seed table");
		return DEHT_STATUS_FAIL;
	}
	return DEHT_STATUS_SUCCESS;
}
