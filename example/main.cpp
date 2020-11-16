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
void ParserEvent(char * strEvent);
int Testmain();
int producer_init();
int sendMessage(std::string msg);
void CorreEvent(Event * event)
{
	corre.DoCorrelation(event);
}

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
        //printf("%d event\n", num);
        event.plugin_sid = 18106;
        event.plugin_id  = 7085;
        event.srcport++;
        event.dstport++;
        //corre.DoCorrelation(&event);
    }

    producer_init();

    printf("Send Msg !\n");
    std::string msg = "Send Mst to Kafka";
    sendMessage(msg);

	Testmain();
    cin.get();
    return 0;
}

