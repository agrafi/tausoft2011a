/*
 * This is the rules header files. It contains the structs definitions of the way
 * we represent the rules, and the rules.c functions prototypes.
 */

#ifndef RULES_H_
#define RULES_H_

#include "helpers.h"

/* This enum defines the rules types */
enum CELLTYPE {
	NUMBERS,
	LETTERS,
	ALPHANUMERIC,
	CHARACTER,
	LEX,
	LEXCS
};

/* This is the smallest form of a password containing only type and range
 * e.g. *3 contains three passcells of type LETTERS and eachrange is 52
 */
typedef struct passcell_struct {
	enum CELLTYPE type;
	unsigned long range;
} passcell;

/* passblock contains several passcell of the same type.
 * e.g: ^3 is a passblock of type numbers with 3 cells.
 */
typedef struct passblock_struct {
	enum CELLTYPE type;
	unsigned long range;
	unsigned long numOfCells;
	passcell* cells;
} passblock;

/*
 * passterm contains several passblocks.
 * e.g: ^2#*3 is a passterm containing the passblocks: ^2 , # and *3.
 */
typedef struct passterm_struct {
	unsigned long numOfBlocks;
	unsigned long numOfPasswords;
	char* term;
	passblock* blocks;
} passterm;

/*
 * passgencontext contains several pass terms.
 * e.g: *3^1+#^2 is a passgencontext containing the passterms: *3^1 and #^2.
 */
typedef struct passgencontext_struct {
	unsigned long numOfTerms;
	unsigned long numOfPasswords;
	passterm* terms;
	char rule[MAX_FIELD];
} passgencontext;

/*
 * This struct holds a word from the lexicon and information about the word
 */
typedef struct lexword_struct {
	char* word;
	char* wordlower;
	char* playground;
	unsigned long len;
	unsigned long numOfLettersPermutaionsInWord;
} lexword;

/*
 * This struct holds the lexicon words and information about them.
 */
typedef struct lexicon_struct {
	char* buffer;
	unsigned long numOfWordsInLexicon;
	unsigned long numOfLettersInLexicon;
	unsigned long sumOfWordsPermutationsInLexicon;
	lexword* words;
} lexicon;

/* function prototypes */
char* generatePassword(passgencontext* passgenctx, lexicon* lex, unsigned long k, char* pass);
lexicon* preprocessLexicon(char* filename);
passgencontext* createrule(char* rule, lexicon* lex, unsigned int* passgensize);
void freelex(lexicon* lex);
void freerule(passgencontext* ctx);
#endif /* RULES_H_ */
