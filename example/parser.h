#ifndef PARSDFSFSDFF
#define PARSDFSFSDFF


#include "cJSON.h"

#include "Correlation.h"



void parse_text();

Backlogs * parse_directive();

void  ParseDirective(Correlation * corre);

void PrintBacklog(Backlogs * backlogs);

void RecurseTree(TreeNode* node);

void RecurseJsonNode(TreeNode * treenode, cJSON *jsonnode);

#endif // PARSDFSFSDFF
