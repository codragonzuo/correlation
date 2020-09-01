#include "Correlation.h"
#include <iostream>
#include "cJSON.h"
#include "parser.h"
#include <stdio.h>

using namespace std;

Correlation corre;


/*

1. 初始化2个directive
2. 加入将directive的规则
3. 构造事件查看匹配结果
3. directive解析
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
