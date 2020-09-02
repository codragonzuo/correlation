#include "parser.h"
#include <iostream>
#include <string>
#include <cstring>
#include "cJSON.h"
#include "Correlation.h"
#include <stdio.h>

//using namespace std;

/*
<directive id="50013" name="AV-FREE-FEED Bruteforce attack, HTTP authentication attack against SRC_IP" priority="4">
   <rule type="detector" name="Web server 401 error code (Unauthorized)" reliability="2" occurrence="1" from="ANY" to="ANY" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2009346" protocol="ANY">
        <rules>
             <rule type="detector" name="Web server 401 error code (Unauthorized)" reliability="6" occurrence="3" from="1:SRC_IP" to="1:DST_IP" time_out="120" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2009346">
                 <rules>
                     <rule type="detector" name="Web server 401 error code (Unauthorized)" reliability="8" occurrence="10" from="1:SRC_IP" to="1:DST_IP" time_out="360" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2009346">
                       <rules>
                         <rule type="detector" name="Web server 401 error code (Unauthorized)" reliability="10" occurrence="1000" from="1:SRC_IP" to="1:DST_IP" time_out="3600" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2009346"/>
                       </rules>
                     </rule>
                 </rules>
             </rule>
        </rules>
    </rule>
</directive>
*/

/*
<directive id="50028" name="AV-FREE-FEED Bruteforce attack, FTP authentication attack against SRC_IP" priority="4">
    <rule type="detector" name="FTP authentication failed attempts detected" reliability="4" occurrence="1" from="HOME_NET" to="!HOME_NET" port_from="21" port_to="ANY" plugin_id="1001" plugin_sid="2002383" protocol="TCP">
        <rules>
            <rule type="detector" name="FTP authentication failed attempts detected" reliability="8" occurrence="10" from="1:SRC_IP" to="1:DST_IP" time_out="1800" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2002383" protocol="TCP">
            <rule type="detector" name="FTP authentication as administrator failed attempts detected" reliability="8" occurrence="10" from="1:DST_IP" to="1:SRC_IP" time_out="1800" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2010643" protocol="TCP">
                <rules>
                    <rule type="detector" name="FTP authentication failed attempts detected" reliability="10" occurrence="100" from="1:SRC_IP" to="1:DST_IP" time_out="3600" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2002383" protocol="TCP">
                    <rule type="detector" name="FTP authentication as administrator failed attempts detected" reliability="8" occurrence="100" from="1:DST_IP" to="1:SRC_IP" time_out="1800" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2010643" protocol="TCP">
                        <rules>
                            <rule type="detector" name="FTP authentication failed attempts detected" reliability="10" occurrence="1000" from="1:SRC_IP" to="1:DST_IP" time_out="3600" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2002383" protocol="TCP">
                            <rule type="detector" name="FTP authentication as administrator failed attempts detected" reliability="8" occurrence="1000" from="1:DST_IP" to="1:SRC_IP" time_out="1800" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2010643" protocol="TCP">
                                <rules>
                                    <rule type="detector" name="FTP authentication failed attempts detected" reliability="10" occurrence="10000" from="1:SRC_IP" to="1:DST_IP" plugin_id="1001" plugin_sid="2002383" protocol="TCP"/>
                                    <rule type="detector" name="FTP authentication as administrator failed attempts detected" reliability="8" occurrence="10000" from="1:DST_IP" to="1:SRC_IP" time_out="1800" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="2010643" protocol="TCP"/>
                                </rules>
                            </rule>
                            </rule>
                        </rules>
                    </rule>
                    </rule>
                </rules>
            </rule>
            </rule>
        </rules>
    </rule>
</directive>
*/


char directive_text[] ="{\"directive\": [{\"@id\": \"50005\", \"@name\": \"AV-FREE-FEED Bruteforce attack, Windows authentication attack against DST_IP\", \"@priority\": \"4\", \"rule\": {\"@type\": \"detector\", \"@name\": \"Windows authentication failure attempts\", \"@reliability\": \"1\", \"@occurrence\": \"1\", \"@from\": \"ANY\", \"@to\": \"ANY\", \"@port_from\": \"ANY\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"2\", \"@occurrence\": \"3\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"15\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"4\", \"@occurrence\": \"10\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"30\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"6\", \"@occurrence\": \"50\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"300\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"10\", \"@occurrence\": \"200\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"1000\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"10\", \"@occurrence\": \"2000\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"3600\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\"}}}}}}}}}}}}]}";

char text[] = "{\"timestamp\":\"2019-03-03 08:45:57\", \"value\":1}";




/*
{"directive": [{"@id": "50005", "@name": "AV-FREE-FEED Bruteforce attack, Windows authentication attack against DST_IP", "@priority": "4", "rule": {"@type": "detector", "@name": "Windows authentication failure attempts", "@reliability": "1", "@occurrence": "1", "@from": "ANY", "@to": "ANY", "@port_from": "ANY", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "2", "@occurrence": "3", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "15", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "4", "@occurrence": "10", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "30", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "6", "@occurrence": "50", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "300", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "10", "@occurrence": "200", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "1000", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "10", "@occurrence": "2000", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "3600", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136"}}}}}}}}}}}}]}
*/

void parse_directive()
{
    // printf("%s\n", directive_text);
    cJSON *json;
    //*json_value, *json_timestamp;
    cJSON *directives;
    cJSON *directive;
    cJSON *directive_id;
    cJSON *directive_name;
    cJSON *directive_priority;
    cJSON *directive_rule;
    cJSON *rule_type;
    cJSON *rule_name;
    cJSON *rule_reliability;
    cJSON *rule_occurrence;
    cJSON *rule_from;
    cJSON *rule_to;
    cJSON *rule_port_from;
    cJSON *rule_timeout;
    cJSON *rule_port_to;
    cJSON *rule_plugin_id;
    cJSON *rule_plugin_sid;

    cJSON *rules;

    //const cJSON *resolution = NULL;

    json = cJSON_Parse(directive_text);
    if(NULL == json)
    {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return;
    }


    directives = cJSON_GetObjectItem(json, "directive");
    //printf("%d\n",directives);
    if(directives->type == cJSON_Number)
    {
        printf("value: %d\n", directives->valueint);
    }

    //cJSON_ArrayForEach(directive, directives)
    if (directives) directive = directives->child;
    while (directive)
    {
        Backlogs *backlogs = new Backlogs();

        directive_id = cJSON_GetObjectItem(directive, "@id");
        if (cJSON_IsString(directive_id) && (directive_id->valuestring != NULL))
        {
            printf("directive id : \"%s\"   num:%d\n", directive_id->valuestring, std::stoi(directive_id->valuestring, 0, 10));
            backlogs->directive_id = stoi(directive_id->valuestring, 0, 10);
        }
        directive_name = cJSON_GetObjectItem(directive, "@name");
        if (cJSON_IsString(directive_name) && (directive_name->valuestring != NULL))
        {
            printf("directive name : \"%s\"\n", directive_name->valuestring);
            backlogs->name=directive_name->valuestring;
            //cout << backlogs->name << endl;
        }
        directive_priority = cJSON_GetObjectItem(directive, "@priority");
        if (cJSON_IsString(directive_priority) && (directive_priority->valuestring != NULL))
        {
            printf("directive priority : \"%s\"\n", directive_priority->valuestring);
            backlogs->priority = stoi(directive_priority->valuestring, 0, 10);
        }

        directive_rule = cJSON_GetObjectItem(directive, "rule");
        while (directive_rule!= 0)
        {
            Rule *rule = new Rule();
            /* 1. type */
            rule_type = cJSON_GetObjectItem(directive_rule, "@type");
            if (cJSON_IsString(rule_type) && (rule_type->valuestring != NULL))
            {
                printf("1  rule_type  : \"%s\"\n", rule_type->valuestring);
                rule->type = rule_type->valuestring;
            }

            /* 2. name */
            rule_name = cJSON_GetObjectItem(directive_rule, "@name");
            if (cJSON_IsString(rule_name) && (rule_name->valuestring != NULL))
            {
                printf("2  rule_name  : \"%s\"\n", rule_name->valuestring);
                rule->name = rule_name->valuestring;
            }

            /* 3. reliability */
            rule_reliability = cJSON_GetObjectItem(directive_rule, "@reliability");
            if (cJSON_IsString(rule_reliability) && (rule_reliability->valuestring != NULL))
            {
                printf("3  rule_reliability  : \"%s\"\n", rule_reliability->valuestring);
                rule->reliability = stoi(rule_reliability->valuestring, 0, 10);
            }

            /* 4. occurrence */
            rule_occurrence = cJSON_GetObjectItem(directive_rule, "@occurrence");
            if (cJSON_IsString(rule_occurrence) && (rule_occurrence->valuestring != NULL))
            {
                printf("4  rule_occurrence  : \"%s\"\n", rule_occurrence->valuestring);
                rule->occurrence = stoi(rule_occurrence->valuestring, 0, 10);
            }

            /* 5. from */
            rule_from = cJSON_GetObjectItem(directive_rule, "@from");
            if (cJSON_IsString(rule_from) && (rule_from->valuestring != NULL))
            {
                printf("5  rule_from  : \"%s\"\n", rule_from->valuestring);
                rule->from = rule_from->valuestring;
            }

            /* 6. to */
            rule_to = cJSON_GetObjectItem(directive_rule, "@to");
            if (cJSON_IsString(rule_to) && (rule_to->valuestring != NULL))
            {
                printf("6  rule_to  : \"%s\"\n", rule_to->valuestring);
                rule->to = rule_to->valuestring;
            }

            /* 7. port from */
            rule_port_from = cJSON_GetObjectItem(directive_rule, "@port_from");
            if (cJSON_IsString(rule_port_from) && (rule_port_from->valuestring != NULL))
            {
                printf("7  rule_port_from : \"%s\"\n", rule_port_from->valuestring);
                rule->port_from = rule_port_from->valuestring;
            }

            /* 8. timeout */
            rule_timeout = cJSON_GetObjectItem(directive_rule, "@time_out");
            if (cJSON_IsString(rule_timeout) && (rule_timeout->valuestring != NULL))
            {
                printf("8  rule_timeout  : \"%s\"\n", rule_timeout->valuestring);
                rule->timeout = stoi(rule_timeout->valuestring, 0, 10);
            }

            /* 9. port to */
            rule_port_to = cJSON_GetObjectItem(directive_rule, "@port_to");
            if (cJSON_IsString(rule_port_to) && (rule_port_to->valuestring != NULL))
            {
                printf("9  rule_port_to : \"%s\"\n", rule_port_to->valuestring);
                rule->port_to = rule_port_to->valuestring;
            }

            /* 10. plug id */
            rule_plugin_id = cJSON_GetObjectItem(directive_rule, "@plugin_id");
            if (cJSON_IsString(rule_plugin_id) && (rule_plugin_id->valuestring != NULL))
            {
                printf("10 rule_plugin_id  : \"%s\"\n", rule_plugin_id->valuestring);
                rule->plugin_id = rule_plugin_id->valuestring;
            }

            /* 11. plug sid */
            rule_plugin_sid = cJSON_GetObjectItem(directive_rule, "@plugin_sid");
            if (cJSON_IsString(rule_plugin_sid) && (rule_plugin_sid->valuestring != NULL))
            {
                printf("11 rule_plugin_sid  : \"%s\"\n", rule_plugin_sid->valuestring);
                rule->plugin_sid = rule_plugin_sid->valuestring;
            }

            /* rules */
            rules = cJSON_GetObjectItem(directive_rule, "rules");
            if (cJSON_IsString(rules) && (rules->valuestring != NULL))
            {
                //printf("rules  : \"%s\"\n", rules->valuestring);
            }
            if ((rules !=0 ) &&  (rules->child))
                directive_rule = rules->child;
            else
            {
                directive_rule = directive_rule->next;
            }
        }
        directive = directive->next;
    }
}




void parse_text()
{
    cJSON *json, *json_value, *json_timestamp;

    json = cJSON_Parse(text);
    if(NULL == json)
    {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return;
    }

    json_value = cJSON_GetObjectItem(json, "value");
    if(json_value->type == cJSON_Number)
    {
        printf("value: %d\n", json_value->valueint);
    }

    json_timestamp = cJSON_GetObjectItem(json, "timestamp");
    if(json_timestamp->type == cJSON_String)
    {
        printf("%s\n", json_timestamp->valuestring);
    }

    cJSON_Delete(json);

    return;
}
