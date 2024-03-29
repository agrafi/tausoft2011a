/********************************************************************/
/* File DEHT - Disk Embedded Hash Table. An API you must implement  */
/* It supports varied sizes binary key to binary data - very generic*/
/* Has no necessary link to rainbow tables, passwords, etc.         */
/* Read theory of DEHT before this interface                        */
/********************************************************************/
#ifndef _DEHT_H_
#define _DEHT_H_

#include <stdio.h>

/********************************************************************/
/* type DEHT_DISK_PTR stands for "pointers" representation in DEHT  */
/* Data-type of long (argument of "fseek" function) represents an   */
/* offset in a file, which is "disk pointers" in our implementation */
/********************************************************************/
#define DEHT_DISK_PTR    long

/******************************************************************/
/* structure of "first level header" - basic preferences of a DEHT*/
/******************************************************************/
struct DEHTpreferences
{
    char sHashName[16];        /*Name for identification, e.g. "MD5\0" */
    int numEntriesInHashTable; /*typically few millions*/
    int nPairsPerBlock;        /*typically few hundreds*/
    int nBytesPerValidationKey;/*length of key to be compared into,
							    e.g. 8 means 64bit key for validation*/
	/*********************************************************/
	/*It is completely OK to add several members of your own */
	/*Just remember that this struct is saved "as is" to disk*/
	/*So no pointers should be written here                  */
	/*********************************************************/
};

/******************************************************************/
/* Kind of data-structure DEHT_STATUS that can be -1,0,1 as flags */
/******************************************************************/
#define DEHT_STATUS_SUCCESS        1
#define DEHT_STATUS_FAIL          -1
#define DEHT_STATUS_NOT_NEEDED     0

/****************************************************************************/
/* type definition of hashKeyIntoTableFunctionPtr:                          */
/* Definition of what is a data-structre hash-function (not the cryptic one)*/
/* These function take a key and output an index in pointer table           */
/* Note that these function operates on the original key (not condensed one)*/
/* These function shall never fail (i.e. never return -1 or so)             */
/****************************************************************************/
typedef int (*hashKeyIntoTableFunctionPtr)(const unsigned char *,int,int);
/*Arguments are: */
/* const unsigned char *keyBuf, i.e. Binary buffer input*/
/* int keySizeof , i.e. in this project this is crypt output size, */
/*          but in real life this size may vary (e.g. string input)*/
/* int nTableSize, i.e. Output is 0 to (nTableSize-1) to fit table of pointers*/

/****************************************************************************/
/* type definition of hashKeyforEfficientComparisonFunctionPtr:             */
/* I is made to create a key signature (stored in DEHT) that distinguish    */
/* it from any other key in same bucket. Namely to correct false matches    */
/* caused by the hashKeyIntoTableFunctionPtr, thus must be independent of it*/
/* Note that these functions consider nBytesPerValidationKey as hard coded  */
/* E.g. stringTo32bit(very widely used) or cryptHashTo64bit(as in this proj)*/
/****************************************************************************/
typedef int (*hashKeyforEfficientComparisonFunctionPtr)(const unsigned char *,int, unsigned char *);
/*Arguments are: */
/* const unsigned char *keyBuf, i.e. Binary buffer input*/
/* int keySizeof , i.e. in this project this is crypt output size, */
/*          but in real life this size may vary (e.g. string input)*/
/* unsigned char *validationKeyBuf, i.e. Output buffer, assuming allocated with nBytesPerValidationKey bytes*/


/****************************************************************************/
/* type definition of DEHT ! a struct containing all required to specify one*/
/****************************************************************************/
typedef struct /*This struct holds all needed during actual calls*/
{
    char sKeyFileName[80]; /*filename (as OS recognize) of .key */
    char sDataFileName[80];/*filename (as OS recognize) of .data */
	char sSeedFileName[80];/*filename (as OS recognize) of .seed */
    FILE *keyFP;           /*file pointer to the .key file as stdio recognize*/
    FILE *dataFP;
	FILE *seedFP;
    struct DEHTpreferences header;
    hashKeyIntoTableFunctionPtr hashFunc;                          /*key to table of pointers*/
	hashKeyforEfficientComparisonFunctionPtr comparisonHashFunc;   /*key to validation process (distinguish collision for real match*/
    DEHT_DISK_PTR *hashTableOfPointersImageInMemory;      /*null or some copy of what in file in case we cache it - efficient to cache this and header only*/
	DEHT_DISK_PTR *hashPointersForLastBlockImageInMemory; /*null or some intermidiate to know whenever insert. It has no parallel on disk*/
	int *anLastBlockSize; /*null or some intermidiate to know whenever insert. It has no parallel on disk. Block size to enable quick insert*/
	/***YOU ARE ALLOWED TO ADD HERE EXTRA MEMBERS, BUT BE EFFICIENT**/
	/***I don't think extra members are necessary                  **/
}DEHT;

/********************************************************************************/
/* Function create_empty_DEHT creates a new DEHT.                               */
/* Inputs: file names on disk (as prefix), hashing functions,                   */
/*    identification name, and parameters regarding memory management           */
/* Output:                                                                      */
/* If fail, Returns NULL and prints informative error to stderr)                */
/* It dump header by itself. Also null table of pointers.                       */
/* Notes:                                                                       */
/* Open them in RW permission (if exist then fail, do not overwrite).           */
/* hashTableOfPointersImageInMemory, hashPointersForLastBlockImageInMemory:=NULL*/
/********************************************************************************/
DEHT *create_empty_DEHT(const char *prefix,/*add .key and .data to open two files return NULL if fail creation*/
                        hashKeyIntoTableFunctionPtr hashfun, hashKeyforEfficientComparisonFunctionPtr validfun,
                        const char *dictName,   /*e.g. MD5\0 */
                        int numEntriesInHashTable, int nPairsPerBlock, int nBytesPerKey); /*optimization preferences*/

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
						   hashKeyIntoTableFunctionPtr hashfun, hashKeyforEfficientComparisonFunctionPtr validfun);


/********************************************************************************/
/* Function insert_uniquely_DEHT inserts an ellement.                           */
/* Inputs: DEHT to insert into, key and data (as binary buffer with size)       */
/* Output: just status of action:                                               */
/* If exist updates data and returns DEHT_STATUS_NOT_NEEDED                     */
/* If successfully insert returns DEHT_STATUS_SUCCESS.                          */
/* If fail, returns DEHT_STATUS_FAIL                                            */
/* Notes:                                                                       */
/* if hashTableOfPointersImageInMemory use it                                   */
/* if  null, do not load table of pointers into memory just make simple         */
/* insert using several fseek when necessary.                                   */
/********************************************************************************/
int insert_uniquely_DEHT ( DEHT *ht, const unsigned char *key, int keyLength,
				 const unsigned char *data, int dataLength);

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
				 const unsigned char *data, int dataLength);

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
				 unsigned char *data, int dataMaxAllowedLength);

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
				 unsigned char **dataPointer, int dataPointerLength);


/************************************************************************************/
/* Function read_DEHT_pointers_table loads pointer of tables from disk into RAM     */
/* It will be used for effciency, e.g. when many queries expected soon              */
/* Input: DEHT to act on. (will change member hashTableOfPointersImageInMemory).    */
/* Output:                                                                          */
/* If it is already cached, do nothing and return DEHT_STATUS_NOT_NEEDED.           */
/* If fail, return DEHT_STATUS_FAIL, if success return DEHT_STATUS_NOT_SUCCESS      */
/************************************************************************************/
int read_DEHT_pointers_table(DEHT *ht);

/************************************************************************************/
/* Function write_DEHT_pointers_table writes pointer of tables RAM to Disk & release*/
/* Input: DEHT to act on.                                                           */
/* Output:                                                                          */
/* If not RAM pointer is NULL, return DEHT_STATUS_NOT_NEEDED                        */
/* if fail return DEHT_STATUS_FAIL, if success return DEHT_STATUS_SUCCESS           */
/* Note: do not forget to use "free" and put NULL.                                  */
/************************************************************************************/
int write_DEHT_pointers_table(DEHT *ht);

/************************************************************************************/
/* Function calc_DEHT_last_block_per_bucket calculate all rear pointers on key file */
/*   to enable insertion with a single seek. Will be called by user when many insert*/
/*   calls are expected. Note that these has no parallel on disk thus no "write"    */
/* Input: DEHT to act on (modify hashPointersForLastBlockImageInMemory)             */
/* Output:                                                                          */
/* If it is already exist, do nothing and return DEHT_STATUS_NOT_NEEDED.            */
/* If fail, return DEHT_STATUS_FAIL, if success return DEHT_STATUS_NOT_SUCCESS      */
/************************************************************************************/
int calc_DEHT_last_block_per_bucket(DEHT *ht);

/************************************************************************************/
/* Function lock_DEHT_files closes the DEHT files and release memory.               */
/* Input: DEHT to act on. No Output (never fail).                                   */
/* Notes:                                                                           */
/* calls write_DEHT_hash_table if necessary, call "free" when possible.             */
/* use "fclose" command. do not free "FILE *"                                       */
/************************************************************************************/
void lock_DEHT_files(DEHT *ht);


/************************************************************************************/
/* Function read_DEHT_Seed loads rainbow table seeds from disk into RAM.			*/
/* Input: DEHT to act on, output buffer and its size.								*/
/* Return value: DEHT_STATUS_FAIL on failure, or DEHT_STATUS_SUCCESS on success.	*/
/************************************************************************************/
int read_DEHT_Seed(DEHT *, void *,int);


/************************************************************************************/
/* Function write_DEHT_Seed dumps rainbow table seeds from RAM into disk.			*/
/* Input: DEHT to act on, input buffer and its size.								*/
/* Return value: DEHT_STATUS_FAIL on failure, or DEHT_STATUS_SUCCESS on success.	*/
/************************************************************************************/
int write_DEHT_Seed(DEHT *, const void *,int);

/*****           You may add here more functions for your own use.           ********/

int hashfun(const unsigned char *keyBuf, int keySizeof, int nTableSize);
int validfun(const unsigned char *keyBuf, int keySizeof,
		unsigned char *validationKeyBuf);

typedef struct element_struct {
	unsigned char key[8];
	int datalen;
	DEHT_DISK_PTR dataptr;
} TRIPLE;

typedef struct block_struct_header
{
	DEHT_DISK_PTR next;
} BLOCK_HEADER;

typedef struct deht_table_struct {
	DEHT_DISK_PTR	ind[65536];
} DEHT_TABLE;

#endif
/************************* EOF (DEHT.h) ****************/

