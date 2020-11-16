#include "Correlation.h"
#include <iostream>
#include <sstream>
#include "cJSON.h"
#include "parser.h"
#include <stdio.h>

using namespace std;

Correlation corre;
Backlogs * backlogs;
Event event;
int Testmain();
void ParserEvent(char * strEvent);


int  main(int argc, char **argv)
{
    int x = 1551;
    int num;
    Backlogs h;
    h.directive_id = 1001;
    h.name = "myname";
    h.a = &x;

    
    printf("\n--------------\n");

    Backlogs m = h;
    printf("directive_id: %d,  name:%s  0x%x   0x%x\n", m.directive_id, m.name.c_str(), &x , m.a);


    parse_text();
    cout << "Hello world!" << endl;
    vector<int> octetsIP;
    string strIp = "192.169.100.21";
    vector<int>::iterator  itr;

    string srcIpa;
    string dstIpa;

    if (GetOctetsIP(strIp, octetsIP)==0)
    {
        for (itr=octetsIP.begin(); itr!=octetsIP.end(); itr++)
        {
            num = *itr;
            printf("%d.", num);
        }
        printf("\n");
    }

    event.SrcIp = "192.169.100.21";
    event.DstIp = "192.169.100.91";
    event.srcport = 20;
    event.dstport = 30;



    ParseDirective(&corre);
    PrintBacklog(backlogs);

    num=1;
    for (num = 1; num<2270; num++)//2270
    {
        printf("%d event\n", num);
        event.plugin_sid = 18106;
        event.plugin_id  = 7085;
        event.srcport++;
        event.dstport++;
        corre.DoCorrelation(&event);
    }


    /*
    printf("%d event\n", ++num);
    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

    printf("%d event\n", ++num);
    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

    printf("%d event\n", ++num);
    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

    printf("%d event\n", ++num);
    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

    printf("%d event\n", ++num);
    event.plugin_sid = 18106;
    event.plugin_id  = 7085;
    corre.DoCorrelation(event);

*/
    //×Ö·û´®·Ö¸î²âÊÔ
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

	Testmain();
    cin.get();
    return 0;
}

