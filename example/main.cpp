#include "Correlation.h"
#include <iostream>
#include "cJSON.h"
#include "parser.h"
#include <stdio.h>

using namespace std;

Correlation corre;


/*

1. ��ʼ��2��directive
2. ���뽫directive�Ĺ���
3. �����¼��鿴ƥ����
3. directive����
*/


int main()
{
    parse_text();
    cout << "Hello world!" << endl;
    Event event;
    //cout << xmltest() << endl;
    corre.DoCorrelation(event);



    parse_directive();


    cin.get();
    return 0;
}
