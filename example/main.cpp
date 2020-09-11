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
    int x = 1551;

    Backlogs h;
    h.directive_id = 1001;
    h.name = "myname";
    h.a = &x;

    //规则树节点如何 克隆？？？？


    Backlogs m = h;
    printf("directive_id: %d,  name:%s  0x%x   0x%x\n", m.directive_id, m.name.c_str(), &x , m.a);


    parse_text();
    cout << "Hello world!" << endl;
    vector<int> octetsIP;
    string strIp = "192.169.100.21";
    vector<int>::iterator  itr;
    int num;
    IpAddress *srcIpa;
    IpAddress *dstIpa;

    if (GetOctetsIP(strIp, octetsIP)==0)
    {
        for (itr=octetsIP.begin(); itr!=octetsIP.end(); itr++)
        {
            num = *itr;
            printf("%d.", num);
        }
        printf("\n");
    }

    //定义事件的IP
    string srcIp = "192.169.100.21";
    string dstIp = "192.169.100.91";

    if (GetOctetsIP(srcIp, octetsIP)==0)
    {
        srcIpa = new IpAddress(srcIp);
        dstIpa = new IpAddress(srcIp);
    }
    event.SrcIp = srcIpa;
    event.DstIp = dstIpa;


    ParseDirective(&corre);
    PrintBacklog(backlogs);

    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
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
