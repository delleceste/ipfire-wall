Syntax files are opened and parsed in order:

They must be called syntaxN.txt, where N is an integer from 0 to 99.

syntax.txt is accepted and is the first file processed, then syntax1.txt, syntax2.txt and so on.

This guarantees a hierarchy in syntax processing

Keywords in a single syntax file are sorted by length: from the longest to the shortest

