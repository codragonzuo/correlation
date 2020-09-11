#include "parser.h"
#include <iostream>
#include <string>
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
<directive id="50113" name="AV-FREE-FEED Bruteforce attack, SSH service authentication attack against DST_IP" priority="4">
   <rule type="detector" name="SSH service authentication attempt failed detected" reliability="1" occurrence="1" from="ANY" to="ANY" port_from="ANY" port_to="ANY" plugin_id="4003" plugin_sid="1">
      <rules>
         <rule type="detector" name="SSH service authentication attempt failed detected" reliability="2" occurrence="5" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="30" port_to="ANY" plugin_id="4003" plugin_sid="1">
            <rules>
               <rule type="detector" name="SSH service authentication attempt failed detected" reliability="4" occurrence="10" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="60" port_to="ANY" plugin_id="4003" plugin_sid="1">
                  <rules>
                     <rule type="detector" name="SSH service authentication attempt failed detected" reliability="6" occurrence="100" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="3000" port_to="ANY" plugin_id="4003" plugin_sid="1">
                        <rules>
                           <rule type="detector" name="SSH service authentication attempt failed detected" reliability="8" occurrence="1000" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="36000" port_to="ANY" plugin_id="4003" plugin_sid="1">
                              <rules>
                                 <rule type="detector" name="SSH service authentication attempt failed detected" reliability="10" occurrence="10000" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="86400" port_to="ANY" plugin_id="4003" plugin_sid="1"/>
                                 <rule type="detector" name="SSH service authentication sucessful" reliability="10" occurrence="1" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="10" port_to="ANY" plugin_id="4003" plugin_sid="7"/>
                              </rules>
                           </rule>
                           <rule type="detector" name="SSH service authentication sucessful" reliability="1" occurrence="1" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="10" port_to="ANY" plugin_id="4003" plugin_sid="7"/>
                        </rules>
                     </rule>
                     <rule type="detector" name="SSH service authentication sucessful" reliability="10" occurrence="1" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="10" port_to="ANY" plugin_id="4003" plugin_sid="7"/>
                  </rules>
               </rule>
            <rule type="detector" name="SSH service authentication sucessful" reliability="10" occurrence="1" from="1:SRC_IP" to="1:DST_IP" port_from="ANY" time_out="10" port_to="ANY" plugin_id="4003" plugin_sid="7"/>
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


char directive_text[] ="{\"directive\": [{\"@id\": \"50005\", \"@name\": \"AV-FREE-FEED Bruteforce attack, Windows authentication attack against DST_IP\", \"@priority\": \"4\", \"rule\": {\"@type\": \"detector\", \"@name\": \"Windows authentication failure attempts\", \"@reliability\": \"1\", \"@occurrence\": \"1\", \"@from\": \"ANY\", \"@to\": \"ANY\", \"@port_from\": \"ANY\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"2\", \"@occurrence\": \"3\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"15\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"4\", \"@occurrence\": \"10\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"30\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"6\", \"@occurrence\": \"50\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"300\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"10\", \"@occurrence\": \"200\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"1000\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\", \"rules\": {\"rule\": {\"@type\": \"detector\", \"@name\": \"Windows Authentication failure\", \"@reliability\": \"10\", \"@occurrence\": \"2000\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"3600\", \"@port_to\": \"ANY\", \"@plugin_id\": \"7085\", \"@plugin_sid\": \"18106,18130,18135,18136\"}}}}}}}}}}}},{\"@id\": \"50113\", \"@name\": \"AV-FREE-FEED Bruteforce attack, SSH service authentication attack against DST_IP\", \"@priority\": \"4\", \"rule\": {\"@type\": \"detector1\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"1\", \"@occurrence\": \"1\", \"@from\": \"ANY\", \"@to\": \"ANY\", \"@port_from\": \"ANY\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": {\"@type\": \"detector2\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"2\", \"@occurrence\": \"5\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"30\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector3\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"4\", \"@occurrence\": \"10\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"60\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector4\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"6\", \"@occurrence\": \"100\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"3000\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector5\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"8\", \"@occurrence\": \"1000\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"36000\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector6\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"10\", \"@occurrence\": \"10000\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"86400\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\"}, {\"@type\": \"detector7\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"10\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}, {\"@type\": \"detector8\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"1\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}, {\"@type\": \"detector9\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"10\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}, {\"@type\": \"detector10\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"10\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}}}}]}";

char text[] = "{\"timestamp\":\"2019-03-03 08:45:57\", \"value\":1}";

//char directive_text[] ="{\"directive\": [{\"@id\": \"50113\", \"@name\": \"AV-FREE-FEED Bruteforce attack, SSH service authentication attack against DST_IP\", \"@priority\": \"4\", \"rule\": {\"@type\": \"detector1\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"1\", \"@occurrence\": \"1\", \"@from\": \"ANY\", \"@to\": \"ANY\", \"@port_from\": \"ANY\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": {\"@type\": \"detector2\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"2\", \"@occurrence\": \"5\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"30\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector3\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"4\", \"@occurrence\": \"10\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"60\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector4\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"6\", \"@occurrence\": \"100\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"3000\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector5\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"8\", \"@occurrence\": \"1000\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"36000\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\", \"rules\": {\"rule\": [{\"@type\": \"detector6\", \"@name\": \"SSH service authentication attempt failed detected\", \"@reliability\": \"10\", \"@occurrence\": \"10000\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"86400\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"1\"}, {\"@type\": \"detector7\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"10\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}, {\"@type\": \"detector8\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"1\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}, {\"@type\": \"detector9\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"10\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}, {\"@type\": \"detector10\", \"@name\": \"SSH service authentication sucessful\", \"@reliability\": \"10\", \"@occurrence\": \"1\", \"@from\": \"1:SRC_IP\", \"@to\": \"1:DST_IP\", \"@port_from\": \"ANY\", \"@time_out\": \"10\", \"@port_to\": \"ANY\", \"@plugin_id\": \"4003\", \"@plugin_sid\": \"7\"}]}}}}}]}";




/*
{"directive": [{"@id": "50005", "@name": "AV-FREE-FEED Bruteforce attack, Windows authentication attack against DST_IP", "@priority": "4", "rule": {"@type": "detector", "@name": "Windows authentication failure attempts", "@reliability": "1", "@occurrence": "1", "@from": "ANY", "@to": "ANY", "@port_from": "ANY", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "2", "@occurrence": "3", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "15", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "4", "@occurrence": "10", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "30", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "6", "@occurrence": "50", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "300", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "10", "@occurrence": "200", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "1000", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136", "rules": {"rule": {"@type": "detector", "@name": "Windows Authentication failure", "@reliability": "10", "@occurrence": "2000", "@from": "1:SRC_IP", "@to": "1:DST_IP", "@port_from": "ANY", "@time_out": "3600", "@port_to": "ANY", "@plugin_id": "7085", "@plugin_sid": "18106,18130,18135,18136"}}}}}}}}}}}}]}
*/
#if 0
Backlogs *  parse_directive()
{
    Backlogs *backlogs;
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

    TreeNode * currentnode = NULL;
    TreeNode * lastnode = NULL;

    int ruletype = RULE_TYPE_PARENT;

    //const cJSON *resolution = NULL;

    json = cJSON_Parse(directive_text);
    if(NULL == json)
    {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return NULL;
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
        backlogs = new Backlogs();

        directive_id = cJSON_GetObjectItem(directive, "@id");
        if (cJSON_IsString(directive_id) && (directive_id->valuestring != NULL))
        {
            printf("directive id : \"%s\"   num:%d\n", directive_id->valuestring, stoi(directive_id->valuestring, 0, 10));
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
                rule->SetRulePort(rule_port_from->valuestring, true);
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
                rule->SetRulePort(rule_port_from->valuestring, false);
            }

            /* 10. plug id */
            rule_plugin_id = cJSON_GetObjectItem(directive_rule, "@plugin_id");
            if (cJSON_IsString(rule_plugin_id) && (rule_plugin_id->valuestring != NULL))
            {
                printf("10 rule_plugin_id  : \"%s\"\n", rule_plugin_id->valuestring);
                rule->plugin_id = stoi(rule_plugin_id->valuestring);
            }

            /* 11. plug sid */
            rule_plugin_sid = cJSON_GetObjectItem(directive_rule, "@plugin_sid");
            if (cJSON_IsString(rule_plugin_sid) && (rule_plugin_sid->valuestring != NULL))
            {
                printf("11 rule_plugin_sid  : \"%s\"\n", rule_plugin_sid->valuestring);
                rule->plugin_sid = stoi(rule_plugin_sid->valuestring);
            }

            //创建根节点
            if (lastnode == NULL)
            {
                currentnode = new TreeNode(NULL);
                currentnode->SetRule(rule);

                //设置指令根节点
                backlogs->SetRootNode(currentnode);
            }
            else
            {
                 //
                 if  (ruletype == RULE_TYPE_CHILD)
                 {
                     //是上一节点的孩子节点
                     currentnode = lastnode->AddChild();
                     currentnode->SetRule(rule);

                 }
                 else if (ruletype == RULE_TYPE_BRO)
                 {
                     //是上一节点的兄弟节点，同一个父节点

                     currentnode = lastnode->GetParent()->AddChild();
                     currentnode->SetRule(rule);

                 }
            }

            /* rules */
            rules = cJSON_GetObjectItem(directive_rule, "rules");
            if (cJSON_IsString(rules) && (rules->valuestring != NULL))
            {
                //printf("rules  : \"%s\"\n", rules->valuestring);
            }
            if ((rules !=0 ) &&  (rules->child))
            {
                directive_rule = rules->child;     //下一规则是孩子节点
                ruletype = RULE_TYPE_CHILD;
                            }
            else
            {
                directive_rule = directive_rule->child; //下一规则是兄弟节点
                ruletype = RULE_TYPE_BRO;
            }
            lastnode = currentnode;
        }
        directive = directive->next;
    }
    return backlogs;
}
#endif // 0

void  ParseDirective(Correlation * corre)
{
    Backlogs *backlogs;
    // printf("%s\n", directive_text);
    cJSON *json;
    //*json_value, *json_timestamp;
    cJSON *directives;
    cJSON *directive;
    cJSON *directive_id;
    cJSON *directive_name;
    cJSON *directive_priority;
    cJSON *directive_rule;


    TreeNode * rulenode =NULL;


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
        backlogs = new Backlogs();

        directive_id = cJSON_GetObjectItem(directive, "@id");
        if (cJSON_IsString(directive_id) && (directive_id->valuestring != NULL))
        {
            printf("directive id : \"%s\"   num:%d\n", directive_id->valuestring, stoi(directive_id->valuestring, 0, 10));
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
        rulenode = new TreeNode(NULL);
        backlogs->SetRootNode(rulenode);
        backlogs->SetCurrentRuleNode(rulenode);
        if (directive_rule!= 0)
        {
             RecurseJsonNode(rulenode, directive_rule);
        }
        directive = directive->next;

        corre->AddBacklogs(backlogs);
        PrintBacklog(backlogs);
    }

    return;
}

void RecurseJsonNode(TreeNode * treenode, cJSON *jsonnode)
{
    /*  */

    //Rule * rule;
    TreeNode* childnode;
    TreeNode* currentnode;
    //TreeNode* lastnode;
    cJSON*    rules;
    cJSON*    childjsonnode;
    cJSON* directive_rule;
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
    cJSON *rule_protocol;
    int array_size;

    directive_rule = jsonnode;
    currentnode = treenode;


//    int array_size = cJSON_GetArraySize(jsonnode);
    if (directive_rule == 0) return;

    if (cJSON_HasObjectItem(directive_rule, "@type")!= 0) /* rule + rules */
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
            rule->SetRuleIp(rule_from->valuestring, true);
        }

        /* 6. to */
        rule_to = cJSON_GetObjectItem(directive_rule, "@to");
        if (cJSON_IsString(rule_to) && (rule_to->valuestring != NULL))
        {
            printf("6  rule_to  : \"%s\"\n", rule_to->valuestring);
            rule->to = rule_to->valuestring;
            rule->SetRuleIp(rule_to->valuestring, false);
        }

        /* 7. port from */
        //sim_xml_directive_set_rule_ports
        rule_port_from = cJSON_GetObjectItem(directive_rule, "@port_from");
        if (cJSON_IsString(rule_port_from) && (rule_port_from->valuestring != NULL))
        {
            printf("7  rule_port_from : \"%s\"\n", rule_port_from->valuestring);
            rule->port_from = rule_port_from->valuestring;
            rule->SetRuleMatchPort(rule_port_from->valuestring, true);
            //引用
            // 无引用

        }

        /* 8. timeout */
        rule_timeout = cJSON_GetObjectItem(directive_rule, "@time_out");
        if (cJSON_IsString(rule_timeout) && (rule_timeout->valuestring != NULL))
        {
            printf("8  rule_timeout  : \"%s\"\n", rule_timeout->valuestring);
            rule->mRuleTimeOut = stoi(rule_timeout->valuestring, 0, 10);
        }

        /* 9. port to */
        rule_port_to = cJSON_GetObjectItem(directive_rule, "@port_to");
        if (cJSON_IsString(rule_port_to) && (rule_port_to->valuestring != NULL))
        {
            printf("9  rule_port_to : \"%s\"\n", rule_port_to->valuestring);
            rule->port_to = rule_port_to->valuestring;
            rule->SetRuleMatchPort(rule_port_to->valuestring, false);
        }

        /* 10. plug id */
        rule_plugin_id = cJSON_GetObjectItem(directive_rule, "@plugin_id");
        if (cJSON_IsString(rule_plugin_id) && (rule_plugin_id->valuestring != NULL))
        {
            printf("10 rule_plugin_id  : \"%s\"\n", rule_plugin_id->valuestring);
            rule->plugin_id = stoi(rule_plugin_id->valuestring);
        }

        /* 11. plug sid */
        rule_plugin_sid = cJSON_GetObjectItem(directive_rule, "@plugin_sid");
        if (cJSON_IsString(rule_plugin_sid) && (rule_plugin_sid->valuestring != NULL))
        {
            //rule->plugin_sid = stoi(rule_plugin_sid->valuestring);
            printf("11 rule_plugin_sid  : \"%s\"\n", rule_plugin_sid->valuestring);
            rule->SetRulePluginSid(rule_plugin_sid->valuestring);

        }

        /* 12. protocol */
        rule_protocol = cJSON_GetObjectItem(directive_rule, "@protocol");
        if (cJSON_IsString(rule_protocol) && (rule_protocol->valuestring != NULL))
        {
            rule->protocol = rule_protocol->valuestring;
            printf("12 rule_protocol  : \"%s\", %d\n", rule_protocol->valuestring, rule->protocol);

        }

        currentnode->SetRule(rule);


        if (cJSON_HasObjectItem(directive_rule, "rules")!= 0)
        {
            rules = cJSON_GetObjectItem(directive_rule, "rules");
            // childnode =  currentnode->AddChild();
            // 传入rules的是父节点
            RecurseJsonNode(currentnode, rules);
        }
    }
    else if (cJSON_HasObjectItem(directive_rule, "rule")!= 0)  /* 多个rule */
    {
        rules = cJSON_GetObjectItem(directive_rule, "rule");

        //这里判断时多个 rule 还是 rule + rulues
        if (cJSON_HasObjectItem(rules, "@type")!= 0)
        {
            childnode =  currentnode->AddChild();
            RecurseJsonNode(childnode, rules);
        }
        else
        {
            array_size = cJSON_GetArraySize(rules);
            for (int i=0; i<array_size; i++)
            {
                childjsonnode = cJSON_GetArrayItem(rules, i);
                childnode =  currentnode->AddChild();
                RecurseJsonNode(childnode, childjsonnode);
            }
        }
    }
    else if (cJSON_HasObjectItem(directive_rule, "rules")!= 0) /* rules */ /* rules里一定是rule */
    {
        rules = cJSON_GetObjectItem(directive_rule, "rules");
        array_size = cJSON_GetArraySize(rules);
        for (int i=0; i<array_size; i++)
        {
            childjsonnode = cJSON_GetArrayItem(directive_rule, i);
            childnode =  currentnode->AddChild();
            RecurseJsonNode(childnode, childjsonnode);/* 传入rule的是当前节点 */
        }
    }
}


/* 节点遍历，先孩子后兄弟 */
void RecurseTree(TreeNode* node)
{
    Rule * rule;
    TreeNode* childnode;
	if (node!= NULL)
	{
		//当前节点
        rule = node->GetRule();
        printf("rule node:0x%x name : %s  type: %s  reliabity:%d  occurence:%d\n", node, rule->name.c_str(), rule->type.c_str(), rule->reliability,rule->occurrence);

        //孩子节点
        std::vector<TreeNode*> vecTreeNode = node->GetChildren();
        vector<TreeNode*>::iterator it;
        it = vecTreeNode.begin();
        printf("vector number=%d\n", vecTreeNode.size());
        while(it != vecTreeNode.end())
        {
            childnode = *it;
            RecurseTree(childnode);
            it++;
        }
	}
}

void PrintBacklog(Backlogs * backlogs)
{
    if (backlogs == NULL) return;

    printf("------------------------------PrintBacklog-----------------------------------------\n");

    TreeNode* rulenode = backlogs->GetRootNode();

    if (rulenode == NULL) return;

    RecurseTree(rulenode);
    printf("------------------------------PrintBacklog end-------------------------------------\n");
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
