#include "Correlation.h"
#include <list>
#include <vector>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>


using namespace std;



/* �ַ����ָ�� */
void SplitString(const string& s, vector<string>& v, const string& delimiter)
{
    string::size_type pos1, pos2;
    pos2 = s.find(delimiter);
    pos1 = 0;
    while(string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2-pos1));

        pos1 = pos2 + delimiter.size();
        pos2 = s.find(delimiter, pos1);
    }
    if(pos1 != s.length())
        v.push_back(s.substr(pos1));
}

SimRuleVarType sim_get_rule_var_from_char (const char *var)
{


  if (!strcmp (var, SIM_SRC_IP_CONST))
    return SIM_RULE_VAR_SRC_IA;
  else if (!strcmp (var, SIM_DST_IP_CONST))
    return SIM_RULE_VAR_DST_IA;
  else if (!strcmp (var, SIM_SRC_PORT_CONST))
    return SIM_RULE_VAR_SRC_PORT;
  else if (!strcmp (var, SIM_DST_PORT_CONST))
    return SIM_RULE_VAR_DST_PORT;
  else if (!strcmp (var, SIM_PROTOCOL_CONST))
    return SIM_RULE_VAR_PROTOCOL;
  else if (!strcasecmp (var, SIM_PLUGIN_ID_CONST))
    return SIM_RULE_VAR_PLUGIN_ID;
  else if (!strcmp (var, SIM_PLUGIN_SID_CONST))
    return SIM_RULE_VAR_PLUGIN_SID;
  else if (!strcmp (var, SIM_SENSOR_CONST))
    return SIM_RULE_VAR_SENSOR;
  else if (!strcasecmp (var, SIM_PRODUCT_CONST))
    return SIM_RULE_VAR_PRODUCT;
  else if (!strcasecmp (var, SIM_ENTITY_CONST))
    return SIM_RULE_VAR_ENTITY;
  else if (!strcasecmp (var, SIM_CATEGORY_CONST))
    return SIM_RULE_VAR_CATEGORY;
  else if (!strcasecmp (var, SIM_SUBCATEGORY_CONST))
    return SIM_RULE_VAR_SUBCATEGORY;
  else if (!strcmp (var, SIM_FILENAME_CONST))
    return SIM_RULE_VAR_FILENAME;
  else if (!strcmp (var, SIM_USERNAME_CONST))
    return SIM_RULE_VAR_USERNAME;
  else if (!strcmp (var, SIM_PASSWORD_CONST))
    return SIM_RULE_VAR_PASSWORD;
  else if (!strcmp (var, SIM_USERDATA1_CONST))
    return SIM_RULE_VAR_USERDATA1;
  else if (!strcmp (var, SIM_USERDATA2_CONST))
    return SIM_RULE_VAR_USERDATA2;
  else if (!strcmp (var, SIM_USERDATA3_CONST))
    return SIM_RULE_VAR_USERDATA3;
  else if (!strcmp (var, SIM_USERDATA4_CONST))
    return SIM_RULE_VAR_USERDATA4;
  else if (!strcmp (var, SIM_USERDATA5_CONST))
    return SIM_RULE_VAR_USERDATA5;
  else if (!strcmp (var, SIM_USERDATA6_CONST))
    return SIM_RULE_VAR_USERDATA6;
  else if (!strcmp (var, SIM_USERDATA7_CONST))
    return SIM_RULE_VAR_USERDATA7;
  else if (!strcmp (var, SIM_USERDATA8_CONST))
    return SIM_RULE_VAR_USERDATA8;
  else if (!strcmp (var, SIM_USERDATA9_CONST))
    return SIM_RULE_VAR_USERDATA9;

  return SIM_RULE_VAR_NONE;
}

int  xmltest()
{
   //GNode node;
   return 0; //g_node_depth (&node);
}

Event::Event()
{
    //ctor
}

Event::~Event()
{
    //dtor
}

Correlation::Correlation()
{
    //ctor
}

Correlation::~Correlation()
{
    //dtor
}

void Correlation::AddBacklogs(Backlogs* pBacklogs)
{
    if (pBacklogs == NULL) return;
    this->vecBacklogs.push_back(pBacklogs);

}

Backlogs::Backlogs()
{
    matched = false;
    //ctor
}

Backlogs::~Backlogs()
{
    //dtor
}

void Backlogs::Clear()
{

}

int Backlogs::GetBacklogsId()
{
    return this->backlog_id;
}

bool Backlogs::IsMatched()
{
    if (matched)
        return true;
    else
        return false;
}

void Backlogs::SetMatched(bool matched)
{
    this->matched = matched;
}


bool Backlogs::IsTimeout()
{
    /* ��һ�ν��룬ʱ��Ϊ0������ʧЧ */
    if ((!this->time_out) || (!this->time_last))	//if directive hasn't got any time, this//is the 1st time it enteres here, so no timeout.
        return false;

    /* timeout�ж� */
    if (time (NULL) > (this->time_last + this->time_out))
        return true;

    return false;
}


// sim_directive_backlog_match_by_event  L764
bool Backlogs::MatchEvent(Event event)
{
    //�Ƿ�ƥ�䵱ǰ�¼�
    //ȡ��ǰcurrent_rule
    Rule * pRule;
    //TreeNode * currentnode;
    bool  isMatchRule;
    Rule * currentRule = NULL;
    if (CurrentNode != NULL)
        currentRule = CurrentNode->GetRule();

    if (currentRule == NULL) return false;

    TreeNode * node = NULL;
    TreeNode * child_node = NULL;



    std::vector<TreeNode*> vecTreeNode = CurrentNode->GetChildren();


    //  ���� current_rule �����к��ӽڵ�Ĺ���

    vector<TreeNode*>::iterator it;

    std::vector<TreeNode*> vecTreeNode2;
    vector<TreeNode*>::iterator it2;


    it = vecTreeNode.begin();
    while(it != vecTreeNode.end())
    {
        node = *it;


        //L784 �Ƿ�ƥ��ڵ����
        pRule = node->GetRule();
        isMatchRule = pRule->MatchEvent(event);

        time_t time_last = time (NULL);

        // L344
        if (isMatchRule == true)
        {

            //L790
            SetCurrentRuleNode(node);


            // L793 ����ʱ��
            SetTimeLastCurrentTime(time_last);

            //
            UpdateFirstLastTs(event);

            // L795
            UpdateTimeout();

            // L798 ���浱ǰ�¼����Ե�����ƥ�������У� ����ANY����� sim_rule_set_event_data
            pRule->SetEventDataToRule(event);

            // L801
            pRule->SetTimeLast(time_last);
        }


        // L803 �����ǰ�ڵ���Ҷ�ӽڵ�
        std::vector<TreeNode*>  vecTreeNode2 = node->GetChildren();
        if (vecTreeNode2.empty())
        {
            // L821 �Ѿ�������Ҷ�ӽڵ㣬˵���Ѿ�ƥ��ָ��
            this->SetMatched(true);

        }
        else
        {
            //��Ҷ�ӽڵ㣬�ѵ�ǰ���¼�ƥ������vars���ݵ���ǰ�ڵ�����к��ӽڵ�
            it2 = vecTreeNode2.begin();
            int b = 0;
            while(it2 != vecTreeNode.end())
            {

                child_node = *it2;

                pRule = (Rule*)  child_node->GetRule();
                pRule->SetTimeLast(time_last);

                // L814 �ѵ�ǰƥ������������������Var���ݵ����ӽڵ�
                SetRuleRefVars(child_node);

                it2++;

                //
                b++;
                if (b == (int)vecTreeNode2.size()) break;
            }
        }

        it++;

    }

    return true;

}



bool Backlogs::DirectiveRootRuleMatchEvent(Event event)
{

    //SimRule *rule = (SimRule *)directive->_priv->rule_root->data;
    Rule * rootrule;
    TreeNode * rootnode = this->GetRootNode();
    rootrule = rootnode->GetRule();

    bool ismatch = rootrule->MatchEvent(event);


    //match = sim_rule_match_by_event (rule, event);
    return ismatch;
}

void Backlogs::UpdateFirstLastTs(Event event)
{

    //bool  change = false;

    if(this->first_event > event.time)
    {
        this->first_event = event.time;
        //change = true;
    }

    if(this->last_event < event.time)
    {
        this->last_event = event.time;
        //change = true;
    }
}

void Backlogs::SetTimeLastCurrentTime(time_t time)
{

}

void Backlogs::UpdateTimeout()
{

}

Rule* Backlogs::GetCurrentRule()
{
    return this->CurrentNode->GetRule();
}

TreeNode* Backlogs::GetCurrentRuleNode()
{
    return this->CurrentNode;
}


void Backlogs::SetCurrentRuleNode(TreeNode *node)
{
    this->CurrentNode = node;
}



Directive* Backlogs::GetDirective()
{
    return NULL;
}



// sim_directive_set_rule_vars
// /* Fill children data with backlog data from the node level specified */
// (1)���ƥ���˵�ǰ���򣬰ѵ�ǰƥ������varsֵ���õ����к��ӽڵ㡣
// (2)�������к��ӽڵ������level:varsֵ����ָ�����к��ӽڵ�
// ��ǰ����ƥ�䣬������һ����������ñ���
void Backlogs::SetRuleRefVars(TreeNode * node)
{
    Rule * pRule;
    Rule * pRuleUp;
    TreeNode * node_up;
    RuleVar * ruleVar;
    int port;
    IpAddress* ipa;
    pRule = node->GetRule();

    /* L925 �������������vars */
    std::list <RuleVar *>::iterator it;
    it = pRule->lstRuleVar.begin();
    while (it != pRule->lstRuleVar.end())
    {
        /// ���ҵ�ǰ�ڵ��up�ڵ㣬  1<=level<=current-level �ڵ�
        ruleVar = *it;
        node_up = GetNodeBranchByLevel(node, ruleVar->level);// ����vanr->level �� �汲�ڵ�

        if (!node_up)
        {
            it++;
            continue;
        }
        pRuleUp = (Rule*)node_up->GetRule();
        //��ȡ���ù���� level:vars��ֵ�� ���õ���ǰ����vars
        switch (ruleVar->type)
        {
            /* from="1:SRC_IP" */
            case SIM_RULE_VAR_SRC_IA:
                ipa = pRuleUp->GetSrcIp();
                pRule->SetVarIp(ipa, ruleVar);
                break;
            case SIM_RULE_VAR_DST_IA:
                ipa = pRuleUp->GetDstIp();
                pRule->SetVarIp(ipa, ruleVar);
                break;
            case SIM_RULE_VAR_SRC_PORT:
                port = pRuleUp->GetSrcPort();
                switch (ruleVar->attr)
                {
                    case SIM_RULE_VAR_SRC_PORT:
                        if (ruleVar->negated)
                            pRule->AddSrcPortNot(port);
                        else
                            pRule->AddSrcPort(port);
                        break;
                    case SIM_RULE_VAR_DST_PORT:
                        if (ruleVar->negated)
                            pRule->AddDstPortNot(port);
                        else
                            pRule->AddDstPort(port);
                        break;
                    default:
                        break;
                }
                break;

            case SIM_RULE_VAR_DST_PORT:
                port = pRuleUp->GetDstPort();
                switch (ruleVar->attr)
                {
                    case SIM_RULE_VAR_SRC_PORT:
                        if (ruleVar->negated)
                            pRule->AddSrcPortNot(port);
                        else
                            pRule->AddSrcPort(port);
                        break;
                    case SIM_RULE_VAR_DST_PORT:
                        if (ruleVar->negated)
                            pRule->AddDstPortNot(port);
                        else
                            pRule->AddDstPort(port);
                        break;
                    default:
                        break;
                }
                break;
             default:
                 break;
        }

        it++;
    }


}


/*  */
TreeNode* Backlogs::GetNodeBranchByLevel(TreeNode * node, int level)
{

    int up_level;
    TreeNode * ret;

  up_level = node->GetLevel() - level;	//The root node has a depth of 1.For the children of the root node the depth is 2
  if (up_level < 1)
    return NULL;

  ret = node;
  for (int i = 0; i < up_level; i++)
  {
    ret = ret->GetParent();
  }

  return ret;


}

void  Backlogs::SetRootNode(TreeNode* rootnode)
{
    this->Rootnode = rootnode;

}

void Backlogs::SetClearAllMatchData()
{

    return;
}



TreeNode* Backlogs::GetRootNode()
{
    return this->Rootnode;
}

bool Rule::MatchEvent(Event event)
{
    if (event.plugin_sid != this->plugin_sid)
    {
        return true;
    }





    return true;
}

bool Rule::MatchEventOccurence(Event event)
{

    if (this->occurrence >1)
    {
        if   (this->timeout && this->time_last)
            this->time_last = time(NULL);
        if (this->occurrence != this->count_occu)
        {
            this->count_occu++; // ��1
            //event->count = rule->_priv->count_occu - 1; //��1
        }
        else
        {
            //event->count = rule->_priv->occurrence;
            this->count_occu = 1;   //
        }
    }
    else
    {
        event.count = 1;  // ȱʡֵ
    }

    return false;
}

void Rule::SetEventDataToRule(Event event)
{

    /* L5046 */
    //this->Sets
    this->SetSrcIp(event.SrcIp);
    this->SetDstIp(event.DstIp);
    //5055

    return;
}


void Rule::SetTimeLast(time_t time)
{
    this->time_last = time;
    return;
}


int Rule::GetSrcPort()
{
    return this->src_port;
}

int Rule::GetDstPort()
{
    return this->dst_port;
}

void Rule::AddSrcPort(int port)
{
    /* ����Hash���棬KeyΪsrcport��0-65535����ֵΪ1 */
    if ((port >=0) && (port <=65535))
    {
        this->mapSrcPort.insert(pair<int, int>(port, 1));
    }

    return;
}

void Rule::AddSrcPortNot(int port)
{
    /* ����Hash���棬KeyΪsrcport_not��0-65535����ֵΪ1 */
    /* ����Hash���棬KeyΪsrcport��0-65535����ֵΪ1 */
    if ((port >=0) && (port <=65535))
    {
        this->mapSrcPortNot.insert(pair<int, int>(port, 1));
    }
}


void Rule::AddDstPort(int port)
{
    if ((port >=0) && (port <=65535))
    {
        this->mapDstPortNot.insert(pair<int, int>(port, 1));
    }
}

void Rule::AddDstPortNot(int port)
{
    if ((port >=0) && (port <=65535))
    {
        this->mapDstPortNot.insert(pair<int, int>(port, 1));
    }
}


void Rule::SetVarIp(IpAddress *ipa, RuleVar * var)
{

    if (var->attr == SIM_RULE_VAR_SRC_IA)
    {
        if (var->negated)
        {
            this->SetSrcIpNot(ipa);
        }
        else
        {
            this->SetSrcIp(ipa);
        }
    }
    else if (var->attr == SIM_RULE_VAR_DST_IA)
    {
        if (var->negated)
        {
            this->SetDstIpNot(ipa);
        }
        else
        {
            this->SetDstIp(ipa);
        }
    }
}

void Rule::SetSrcIpNot(IpAddress* ipaddress)
{
    if (this->SrcIpNot) delete this->SrcIpNot;
    this->SrcIpNot = NULL;
    if (ipaddress) this->SrcIpNot = new IpAddress(ipaddress);
}

void Rule::SetSrcIp(IpAddress* ipaddress)
{
    if (this->SrcIp) delete this->SrcIp;
    this->SrcIp = NULL;
    if (ipaddress) this->SrcIp = new IpAddress(ipaddress);
}

void Rule::SetDstIpNot(IpAddress* ipaddress)
{
    if (this->DstIpNot) delete this->DstIpNot;
    this->DstIpNot = NULL;
    if (ipaddress) this->DstIpNot = new IpAddress(ipaddress);
}

void Rule::SetDstIp(IpAddress* ipaddress)
{
    if (this->DstIp) delete this->DstIp;
    this->DstIp = NULL;
    if (ipaddress) this->DstIp = new IpAddress(ipaddress);
}

IpAddress * Rule::GetSrcIp()
{
    return this->SrcIp;
}

IpAddress * Rule::GetSrcNotIp()
{
    return this->SrcIpNot;
}

IpAddress * Rule::GetDstIp()
{
    return this->DstIp;
}

IpAddress * Rule::GetDstNotIp()
{
    return this->DstIpNot;
}

/* ���涨���RefRuleVar��list */
void  Rule::SetRuleVarsToList(RuleVar *var)
{
    this->lstRuleVar.push_back(var);
    return;
}


/* static gboolean sim_xml_directive_set_rule_ports (SimRule * rule, gchar * value, gboolean are_src_ports)*/
void Rule::SetRulePort(char* portstring, bool is_srcport)
{
    /* ��portstring����','�ָ���ַ������� */
    //�ַ����ָ����
    vector<string> vecStr;
    string b = portstring;
    string token_value;
    bool port_neg;

    SplitString(b, vecStr, ",");
    vector<string>::iterator  it;
    for (it=vecStr.begin(); it!=vecStr.end(); it++)
    {
        b = *it;
        if (b.substr(0,1) == "!")
        {
            port_neg = true;
            token_value = b.substr(1, b.length()-1);
        }
        else
        {
            port_neg = false;
            token_value = b;
        }

        string::size_type pos2;
        pos2 = token_value.find(":");
        if (pos2 !=  token_value.npos)
        {
            //�ҵ��ָ���
            string levelstr = token_value.substr(0, pos2);

            RuleVar *var = new RuleVar();
            var->level = stoi(levelstr.c_str(), 0, 10);
            var->negated = port_neg;
            if (is_srcport)
            {
                var->attr = SIM_RULE_VAR_SRC_PORT;
            }
            else
            {
                var->attr = SIM_RULE_VAR_DST_PORT;
            }
            var->type =sim_get_rule_var_from_char(token_value.substr(pos2, token_value.length()- pos2).c_str());
            this->lstRuleVar.push_back(var);

        }
        else if (token_value != "ANY")
        {
            //û���ҵ�
            //�˿ڷ�Χ����������"1-5"
            pos2 = token_value.find("-");
            if (pos2 !=  token_value.npos)
            {
                //�ҵ��ָ���
                string startstr = token_value.substr(0, pos2);
                string endstr = token_value.substr(pos2, token_value.length()-pos2);
                int startport = stoi(startstr.c_str(), 0, 10);
                int endport = stoi(endstr.c_str(), 0, 10);
                for (int port = startport; port <= endport; port++)
                {
                    if (port_neg)       //if ports are ie. !1-5, all the ports in that range will be negated.
                    {
                        if (is_srcport)
                            this->AddSrcPortNot(port);
                        else
                            this->AddDstPortNot(port);
                    }
                    else
                    {
                        if (is_srcport)
                            this->AddSrcPort(port);
                        else
                            this->AddDstPort(port);
                    }

                }
            }
            else //ֻ��һ�����ֶ˿�
            {
                int port = stoi(token_value.c_str(), 0, 10);
                if (port_neg)
                {
                    if (is_srcport)
                        this->AddSrcPortNot(port);
                    else
                        this->AddDstPortNot(port);
                }
                else
                {
                    if (is_srcport)
                        this->AddSrcPort(port);
                    else
                        this->AddDstPort(port);
                }
            }
        }
    }

    if (is_srcport)
    {
        printf("SetRulePort SrcPort: %s\n", portstring);
    }
    else
    {
        printf("SetRulePort DstPort: %s\n", portstring);
    }

    /*���ַ���������б��� */

}

void Rule::SetRuleIp(char* ipstring, bool is_sourceip)
{
    /* ��portstring����','�ָ���ַ������� */
    vector<string> vecStr;
    string b = ipstring;
    string token_value;
    bool ip_neg;


    SplitString(b, vecStr, ",");
    vector<string>::iterator  it;
    for (it=vecStr.begin(); it!=vecStr.end(); it++)
    {
        b = *it;
        if (b.substr(0,1) == "!")
        {
            ip_neg = true;
            token_value = b.substr(1, b.length()-1);
        }
        else
        {
            ip_neg = false;
            token_value = b;
        }

        string::size_type  pos2, pos3, pos4;
        pos2 = token_value.find(":");
        pos3 = token_value.find(SIM_SRC_IP_CONST);
        pos4 = token_value.find(SIM_DST_IP_CONST);

        if ((pos2 !=  token_value.npos) && (pos3 !=  token_value.npos || pos4 !=  token_value.npos))
        {
            //�ҵ��ָ���
            string levelstr = token_value.substr(0, pos2);

            RuleVar *var = new RuleVar();
            var->level = stoi(levelstr.c_str(), 0, 10); //У�飬�Ƿ�������
            var->negated = ip_neg;
            if (is_sourceip)
            {
                var->attr = SIM_RULE_VAR_SRC_IA;
            }
            else
            {
                var->attr = SIM_RULE_VAR_DST_IA;
            }
            var->type =sim_get_rule_var_from_char(token_value.substr(pos2, token_value.length()- pos2).c_str());
            this->lstRuleVar.push_back(var);
        }
        else if (token_value == "ANY")
        {
            if (ip_neg == false) return;
            //Do Nothing

        }
        else if (token_value == SIM_HOME_NET_CONST)  ////usually, "HOME_NET"
        {
            if (ip_neg)
            {
                if (is_sourceip)
                {
                    this->SetSrcHomeNetNot(true);
                }
                else
                {
                    this->SetDstHomeNetNot(true);
                }
            }
            else
            {
                if (is_sourceip)
                {
                    this->SetSrcHomeNet(true);
                }
                else
                {
                    this->SetDstHomeNet(true);
                }
            }
        }
        else
        {
            // OSSIM�����ж����ض�IP������ !192.168.8.3 ,���� �ʲ�����
            // �ݲ���Ҫ

        }
    }

    if (is_sourceip)
    {
        printf("SetRuleIP : %s\n", ipstring);
    }
    else
    {
        printf("SetRuleIP : %s\n", ipstring);
    }
}

void Rule::SetSrcHomeNet(bool isEnable)
{

    this->SrcHomeNetEn = isEnable;
}

void Rule::SetDstHomeNet(bool isEnable)
{
    this->DstHomeNetEn = isEnable;
}

void Rule::SetSrcHomeNetNot(bool isEnable)
{

    this->SrcHomeNetNotEn = isEnable;
}

void Rule::SetDstHomeNetNot(bool isEnable)
{
    this->DstHomeNetNotEn = isEnable;
}


/* L5492 */
bool Rule::MatchSrcIp(Event event)
{
    bool isInet = true;
    bool isInetNot = true;
    bool positive_match = false;
    bool negated_match = false;
    //event.src_ia
    if (isInet) // ���������������������ж�event.src_ia�Ƿ���������
    {
        positive_match = true;
    }

    //Not����ƥ��
    if (isInetNot) // ���������������������ж�event.src_ia�Ƿ���������
    {
        negated_match = true;
    }

    /* If there are any matches here, then return the most exact one */
    // ��һ��ƥ����Ϊ��ƥ��
    if (positive_match != false || negated_match != false) return true;


    // HOME_NET�����˿���µ���������   // !HOME_NET


    return false;
}

bool Rule::MatchDstIp(Event event)
{
    bool isInet = true;
    bool isInetNot = true;
    bool positive_match = false;
    bool negated_match = false;
    //event.src_ia
    if (isInet) // ���������������������ж�event.src_ia�Ƿ���������
    {
        positive_match = true;
    }

    //Not����ƥ��
    if (isInetNot) // ���������������������ж�event.src_ia�Ƿ���������
    {
        negated_match = true;
    }

    /* If there are any matches here, then return the most exact one */
    // ��һ��ƥ����Ϊ��ƥ��
    if (positive_match != false || negated_match != false) return true;


    // HOME_NET�����˿���µ���������   // !HOME_NET


    return false;
}

bool Rule::MatchSrcHost(Event event)
{
    return false;
}

bool Rule::MatchSrcHostNot(Event event)
{
    return false;
}

void Rule::AddPluginId(int pluginId)
{
    this->mapPluginId.insert(pair<int, int>(pluginId, 1));
}

void Rule::AddPluginSid(int pluginSid)
{
    this->mapPluginSid.insert(pair<int, int>(pluginSid, 1));
}

bool Rule::MatchPlugin_id(Event event)
{
    map<int, int>::iterator it;
    it = this->mapPluginId.find(event.plugin_id);
    if(it == this->mapPluginId.end())
        return false;
    else
        return true;
}

bool Rule::MatchPlugin_sid(Event event)
{
    map<int, int>::iterator it;
    it = this->mapPluginSid.find(event.plugin_id);
    if(it == this->mapPluginSid.end())
        return false;
    else
        return true;
}


void Rule::SetRulePluginId(char* portstring)
{
    string ip(portstring);
    stringstream sip(ip);
    string temp;
    while (std::getline(sip,temp,','))
    {
        this->AddPluginId(atoi(temp.c_str()));
    }

}

void Rule::SetRulePluginSid(char* portstring)
{
    string ip(portstring);
    stringstream sip(ip);
    string temp;
    while (std::getline(sip,temp,','))
    {
        this->AddPluginSid(atoi(temp.c_str()));
    }

}


void Correlation::DoCorrelation(Event event)
{

    printf("DoCorrelation\n");
    //MatchBacklogs(event);
    MatchBacklogs(event);

    MatchDirective(event);

    return;

}

void Correlation::MatchBacklogs(Event event)
{
    vector<Backlogs*>::iterator it;
    TreeNode * currentnode;

    Backlogs  *pBacklogs;
    //for (it = vecBacklogs.begin(); it!=vecBacklogs.end(); it++)
    it = vecBacklogs.begin();
    while(it != vecBacklogs.end())
    {
        //cout <<*it <<" ";
        //if (!it)
        //Backlogs *backlog = (Backlogs*)it;
        //it->m_d = 0;
        //pBacklogs = (Backlogs*)it;
        pBacklogs = *it;

        if (pBacklogs->IsTimeout() || pBacklogs->IsMatched())
        {
          //ɾ��Backlogs
            pBacklogs->Clear();
        }

        //sim_directive_backlog_match_by_event
        bool isMatchBacklogs = pBacklogs->MatchEvent(event);

        if (isMatchBacklogs)
        {
            // L194 get current node
            currentnode = pBacklogs->GetCurrentRuleNode();

            // get backlogs_id  L204
            // set event backlog_id   //// �����¼���backlog_id

            ////if(event->backlog_id) g_object_unref (event->backlog_id);
            ////event->backlog_id = g_object_ref (backlog_id);

            //L212 ����backlog��firstevent �� lastevent��ʱ��
            pBacklogs->UpdateFirstLastTs(event);


            // L217 �����ǰ�ڵ���Ҷ�ӽڵ㣬sim_directive_backlog_set_deleted (backlog, TRUE);
            std::vector<TreeNode*> vecTreeNode2 = currentnode->GetChildren();
            if (vecTreeNode2.empty())
            {
                pBacklogs->Clear();
            }

        }
        else if (event.rule_matched)
        {
             /* When the ocurrence is > 1 in the rule, the first call to
         sim_directive_backlog_match_by_event (above) will return FALSE, and the event won't be
         inserted in db. So we have to insert it here. */

             // �¼�û��ƥ��ָ������¼��Ѿ�ƥ�䵽ĳ������
             event.backlog_id = pBacklogs->GetBacklogsId(); // ����ʱ��ƥ���backlog_id
             pBacklogs->UpdateFirstLastTs(event); // L265 ����backlog��firstevent �� lastevent��ʱ��
        }

        // ��¼��ǰƥ���backlog_id��list
        lstBacklogs.push_back(pBacklogs);


        // �����¼��Ĺ���ƥ��״̬��ָ��ƥ��״̬�� ������һѭ��
        //event->rule_matched = FALSE;
        //event->directive_matched = FALSE;

        it++;

    }
    return;
}


// L286
void Correlation::MatchDirective(Event event)
{
    //�������к��¼���plugin_idƥ�������ָ��
    std::list<Backlogs *> listBacklogs;
    std::map<int, std::list<Backlogs *>> thismap;
    std::map<int, std::list<Backlogs *>>::iterator  itr;
    std::list<Backlogs *> lstBacklogsPlugin;
    std::list<Backlogs *>::iterator it_plugin;
    std::list<Backlogs *>::iterator it;
    TreeNode *rootnode;
    Rule * rootrule;


    // ����plugin_id��ɸѡbacklogs
    listBacklogs = this->lstBacklogs;
    bool  isEventMatchRootRule = true;
    Backlogs * pBacklog = NULL;
    Backlogs * pBacklog_plugin = NULL;


	itr = thismap.find(event.plugin_id);
	if(itr != thismap.end())
	{
		//std::cout<< " first "<< itr->first << " second "<<itr->second<<std::endl;
		lstBacklogsPlugin = itr->second;
	}
	else
	{
	    /* û���ҵ� */
		std::cout<< "not found "<<std::endl;
		return;
	}

    for (it_plugin= lstBacklogsPlugin.begin(); it_plugin !=lstBacklogsPlugin.end(); it_plugin++)
    {
        pBacklog_plugin = *it;

        for (it = listBacklogs.begin(); it != listBacklogs.end(); it++)
        {
            //
            pBacklog = (Backlogs *)*it;

            /* �Ѿ�ƥ���,����Ҫ���� */
            if (pBacklog_plugin == pBacklog) return;

        }

        // һ���¼����ܲ鵽�����Ӧ��pBacklog_plugin,�Ӷ����ܵ��´������Backlog
        // û���ҵ�����Ҫ�½�Backlogs����

        //@event plugin_id in @event context L312


        // L336
        // ���event�¼��Ƿ�����ָ���ʱ�䷶Χ


        // ����¼��Ƿ�ƥ��ָ��ĸ��ڵ����
        isEventMatchRootRule = pBacklog_plugin->DirectiveRootRuleMatchEvent(event);


        /* �жϼ�ƥ����plugin����ƥ���˸�ָ���Ҫ�½�Backlogs���� */
        if (isEventMatchRootRule == true)
        {
            // ����ָ���� backlog �� backlog_id, backlogĬ��һֱ���ڣ�����ֻ�������
            pBacklog_plugin->SetClearAllMatchData();

            // ��ȡbacklog�ĸ��ڵ�͸�����
            rootnode = pBacklog->GetRootNode();
            rootrule = rootnode->GetRule();

            // ����rule_root��lasttime L362
            time_t        time_last = time (NULL);
            rootrule->SetTimeLast(time_last);

            // ����backlog�� first_last_ts  L363
            pBacklog_plugin->UpdateFirstLastTs(event);


            // L368 sim_rule_set_event_data (rule_root, event);
            // // ���¼��������ֶα��浽������
            rootrule->SetEventDataToRule(event);

            event.rule_matched = true;
            event.directive_matched = true;

            rootnode->GetChildren();

        }
    }


    //��Ҫ��������plugin_idΪANY(0x7FFFFFFF)������

    return;
}


TreeNode::TreeNode(TreeNode* parent)
{
    this->parent = parent;
    if (parent == NULL)
        this->SetLevel(1);  //���ڵ�levelΪ1
}

void TreeNode::SetLevel(size_t level)
{
    this->level = level;
}

void TreeNode::SetNumber(size_t number)
{
    this->number = number;
}

size_t TreeNode::GetLevel()
{
    return level;
}

size_t TreeNode::GetNumber()
{
    return number;
}

TreeNode* TreeNode::GetParent()
{
    return parent;
}

TreeNode* TreeNode::AddChild()
{
    TreeNode* child = new TreeNode(this);
    children.push_back(child);
    child->SetLevel(this->GetLevel() + 1);

    TreeNode* node = children.back();
    if (node == child)
    {
        node->SetNext(NULL);
    }
    else
    {
        node->SetNext(child);
    }



    return child;
}

TreeNode* TreeNode::GetNext()
{
    return this->next;
}

void TreeNode:: SetNext(TreeNode* nextnode)
{
    this->next = nextnode;
}


vector<TreeNode*> TreeNode::GetChildren()
{
    return children;
}

void TreeNode::SetRule(Rule * rule)
{
    this->rule = rule;
}

Rule * TreeNode::GetRule()
{
    return this->rule;
}

IpAddress::IpAddress()
{

}

IpAddress::IpAddress(IpAddress* ipa)
{
    //���ӳ�ʼ��
}

IpAddress::~IpAddress()
{

}


int IpAddress::GetOctetsIP(string ip, vector<int> &octetsIP) {     // Define vector<int> octets, using reference from main
    stringstream sip(ip);                               // use stringstream named ss and populate with ip
    string temp;
    octetsIP.clear();                                   // Clears the octetsMask vector, in case main function re-runs this function
    vector<bool> ipInRange;
    while (getline(sip,temp,'.'))                       // Every time getline recieves new stream element from ss, save to temp
        octetsIP.push_back(atoi(temp.c_str()));         //... until reaches '.' delimiter, then push_back octet with new element.
    if (octetsIP.size() == 4) {
        for(int i = 0; i < 4; i++){
            if (octetsIP[i] >= 0 && octetsIP[i] <= 255)
                ipInRange.push_back(true);
            else
                ipInRange.push_back(false);
        }
        if (ipInRange[0]==true&&ipInRange[1]==true&&ipInRange[2]==true&&ipInRange[3]==true){
            return 0;
        }else{
            cout << endl << "There are only 255 bits per octet. Please re-enter IP." << endl << endl;
            return 1;
        }
    }else{
        cout << endl << "Please enter four octets in dot notation." << endl << endl;
        return 1;
    }
}


