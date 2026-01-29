#ifndef LANGUAGES_H
#define LANGUAGES_H

#define MAXLANGLINELEN 1024

#define TR(eng) (translation(eng) )

/* Global variables */

/* If we are building C++ with qt, we cannot define globals here.
 * Keep them for the console interface, but avoid defining them 
 * here if we are building QT interface 
 */
#ifndef QT_CORE_LIB
char **lang_strings;
unsigned int nlines;
char langline[MAXLANGLINELEN];
#endif

/* Returns the greatest value between a and b */
int greatest(int a, int b);

/* rc on means that the program has been started with rc option and
 * so no information about language has to be printed out.
 */
int allocate_translation_strings(const char* lang_filename, short rc);

/* Returns the translated string langline, 
 * declared global so not destroyed at the
 * end of the function execution.
 */
char* translation(const char* eng);

/* Returns the translation of the char.
 * Remember that the user will type the char in
 * his own language, and so translation must be
 * inverted.
 */
char char_translation(char c);

int free_lang_strings(void);

#endif
