/*
 * rules.h
 *
 *  Created on: Mar 2, 2011
 *      Author: a
 */

#ifndef RULES_H_
#define RULES_H_

#include "helpers.h"

enum CELLTYPE {
	NUMBERS,
	LETTERS,
	ALPHANUMERIC,
	CHARACTER,
	LEX,
	LEXCS
};

typedef struct passcell_struct {
	enum CELLTYPE type;
	unsigned long range;
} passcell;

typedef struct passblock_struct {
	enum CELLTYPE type;
	unsigned long range;
	unsigned long numOfCells;
	passcell* cells;
} passblock;

typedef struct passterm_struct {
	unsigned long numOfBlocks;
	unsigned long numOfPasswords;
	char* term;
	passblock* blocks;
} passterm;

typedef struct passgencontext_struct {
	unsigned long numOfTerms;
	unsigned long numOfPasswords;
	passterm* terms;
	char rule[MAX_FIELD];
} passgencontext;

typedef struct lexword_struct {
	char* word;
	char* wordlower;
	char* playground;
	unsigned long len;
	unsigned long numOfLettersPermutaionsInWord;
} lexword;
typedef struct lexicon_struct {
	char* buffer;
	unsigned long numOfWordsInLexicon;
	unsigned long numOfLettersInLexicon;
	unsigned long sumOfWordsPermutationsInLexicon;
	lexword* words;
} lexicon;

char* generatePassword(passgencontext* passgenctx, lexicon* lex, unsigned long k, char* pass);
lexicon* preprocessLexicon(char* filename);
passgencontext* createrule(char* rule, lexicon* lex, unsigned int* passgensize);
void freelex(lexicon* lex);
void freerule(passgencontext* ctx);
#endif /* RULES_H_ */
