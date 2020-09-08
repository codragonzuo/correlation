#include "Correlation.h"
#include <iostream>
#include "cJSON.h"
#include "parser.h"
#include <stdio.h>

using namespace std;

Correlation corre;
Backlogs * backlogs;
Event event;
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


    backlogs = ParseDirective();
    PrintBacklog(backlogs);

    if (backlogs->GetRootNode() == NULL) return 0;


    //backlogs->SetCurrentRuleNode(backlogs->GetRootNode());

    if (backlogs->GetCurrentRuleNode()==NULL) return 0;


    corre.AddBacklogs(backlogs);

    event.plugin_sid = 18106;
    corre.DoCorrelation(event);

    event.plugin_sid = 18106;
    corre.DoCorrelation(event);


    //字符串分割测试
    vector<string> vecStr;
    string a("1001,1002,1003:1004,1005");
    string b;


    SplitString(a, vecStr, ",");
    vector<string>::iterator  it;
    for (it=vecStr.begin(); it!=vecStr.end(); it++)
    {
        b = *it;
        printf("-%s\n", b.c_str() );
    }
    printf("-%s\n", a.substr(0,1).c_str() );
    if (a.substr(0,1) == "1")
        printf("first char is 1\n");

    cin.get();
    return 0;
}
