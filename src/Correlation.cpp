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


BacklogsList::BacklogsList()
{
    //ctor
}

BacklogsList::~BacklogsList()
{
    //dtor
}



Backlogs::Backlogs()
{
    /* ���ó�ʼֵ */
    matched = false;
    //this->SetEmpty(true);
    //ctor
}

Backlogs::~Backlogs()
{
    //dtor
}


/*
int Backlogs::GetBacklogsId()
{
    return this->backlog_id;
}
*/
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
// ˵��: (1) ������ǰ�ڵ�����к��ӽڵ��������ƥ��ĺ��ӽڵ�
//��2������ı�д�ص���ͬһ����ĺ��ӽڵ�����ǲ�ͬ�ģ�������ͬһ���¼�ƥ�䵽�������ӽڵ�
bool Backlogs::MatchEvent(Event event)
{
    //�Ƿ�ƥ�䵱ǰ�¼�
    //ȡ��ǰcurrent_rule
    Rule * pRule;
    //TreeNode * currentnode;
    bool  isMatchRule;
    Rule * currentRule = NULL;
    if (this->CurrentNode != NULL)
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
            pRule->SetEventMatchLastTime(time_last);
        }


        // L803 �����ǰ�ڵ���Ҷ�ӽڵ�
        vecTreeNode2 = node->GetChildren();
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
                pRule->SetEventMatchLastTime(time_last);

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
                ipa = pRuleUp->GetEventDataSrcIp();
                pRule->SetVarIp(ipa, ruleVar);
                break;
            case SIM_RULE_VAR_DST_IA:
                ipa = pRuleUp->GetEventDataDstIp();
                pRule->SetVarIp(ipa, ruleVar);
                break;
            case SIM_RULE_VAR_SRC_PORT:
                port = pRuleUp->GetEventDataSrcPort();
                switch (ruleVar->attr)
                {
                    case SIM_RULE_VAR_SRC_PORT:
                        if (ruleVar->negated)
                            pRule->AddRuleMatchSrcPortNot(port);
                        else
                            pRule->AddRuleMatchSrcPort(port);
                        break;
                    case SIM_RULE_VAR_DST_PORT:
                        if (ruleVar->negated)
                            pRule->AddRuleMatchDstPortNot(port);
                        else
                            pRule->AddRuleMatchDstPort(port);
                        break;
                    default:
                        break;
                }
                break;

            case SIM_RULE_VAR_DST_PORT:
                port = pRuleUp->GetEventDataDstPort();
                switch (ruleVar->attr)
                {
                    case SIM_RULE_VAR_SRC_PORT:
                        if (ruleVar->negated)
                            pRule->AddRuleMatchSrcPortNot(port);
                        else
                            pRule->AddRuleMatchSrcPort(port);
                        break;
                    case SIM_RULE_VAR_DST_PORT:
                        if (ruleVar->negated)
                            pRule->AddRuleMatchDstPortNot(port);
                        else
                            pRule->AddRuleMatchDstPort(port);
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

//void Backlogs::Clear()
//{
    //this->SetEmpty(false);
//}

//bool Backlogs::IsDataEmpty()
//{
//    return this->isEmpty;
//}

//void Backlogs::SetEmpty(bool isEmpty)
//{
//    this->isEmpty = isEmpty;
//}

TreeNode* Backlogs::GetRootNode()
{
    return this->Rootnode;
}

Backlogs * Backlogs::clone()
{
    Backlogs * pBacklogs = new Backlogs();
    pBacklogs->directive_id = this->directive_id;
    pBacklogs->name = this->name;
    pBacklogs->first_event = this->first_event;
    pBacklogs->priority = this->priority;

    //�������ڵ�
    TreeNode * rulenode = new TreeNode(NULL);
    pBacklogs->SetRootNode(rulenode);

    printf("Backlog::clone\n");
    /* �������� */
    this->RecurseNodeCopy(pBacklogs->GetRootNode(), this->GetRootNode());


    /* ˽�г�Ա������Ҫ */
    return pBacklogs;

}


void Backlogs::RecurseNodeCopy(TreeNode * dst_node, TreeNode * src_node)
{
    Rule * newrule;
    TreeNode * newnode;
    TreeNode* childnode;
	if (src_node!= NULL && dst_node != NULL)
	{
		//��ǰ�ڵ�
		newrule = new Rule();
        * newrule = *(src_node->GetRule()); //��ֵ������֧�����

        dst_node->SetRule(newrule);
        printf("level %d : node 0x%x   occurence:%d\n", dst_node->GetLevel() , dst_node, newrule->occurrence);

        //���ӽڵ�
        std::vector<TreeNode*> vecTreeNode = src_node->GetChildren();
        vector<TreeNode*>::iterator it;
        it = vecTreeNode.begin();
        printf("vector number=%d\n", vecTreeNode.size());
        while(it != vecTreeNode.end())
        {
            childnode = *it;
            newnode =  dst_node->AddChild();
            //RecurseTree(childnode);
            RecurseNodeCopy(newnode, childnode);
            it++;
        }
	}
}

Rule::Rule()
{
    this->mRuleTimeOut = 0;
    this->mEventMatchCount = 0;
    this->EventDataSrcIp = NULL;
    this->EventDataDstIp = NULL;

    this->EventDataSrcIpNot = NULL;
    this->EventDataDstIpNot = NULL;
}
Rule::~Rule()
{

}

bool Rule::MatchEvent(Event event)
{
    bool matched = true;
    //if (event.plugin_sid == this->plugin_sid)
    //{
    //    matched = true;
    //}

    //���ڸ�����from �� to �� any������Ҫ�ж�
    /*
    if (this->MatchSrcIp(event))
    {
        matched = true;
    }

    if (this->MatchDstIp(event))
    {
        matched = true;
    }
    */

    // L4985 occurrenceƥ��
    this->mEventMatchCount ++;
    if (this->occurrence>1)
    {
        if (this->occurrence != this->mEventMatchCount)
        {
            //this->mEventMatchCount ++;
            event.count = this->mEventMatchCount -1;
            matched = false;
            return false;
        }
        else
        {
            event.count = this->occurrence;
            //this->mEventMatchCount = 1;
            printf("rule occurence = %d  eventmatchcount=%d  matched\n", this->occurrence, this->mEventMatchCount);
        }
    }
    else
    {
        event.count = 1;
        printf("rule occurence = %d  eventmatchcount=%d  matched\n", this->occurrence, this->mEventMatchCount);
    }



    event.rule_matched = true;

    return matched;
}

bool Rule::MatchEventOccurence(Event event)
{

    if (this->occurrence >1)
    {
        if   (this->mRuleTimeOut && this->mEventLastMatchTime)
            this->SetEventMatchLastTime(time(NULL));
        if (this->occurrence != this->mEventMatchCount)
        {
            this->mEventMatchCount++;
        }
        else
        {
            this->mEventMatchCount = 1;
        }
    }
    else
    {
        //event.count = 1;  // ȱʡֵ
    }

    return false;
}

void Rule::SetEventDataToRule(Event event)
{

    /* L5046 */
    //this->Sets
    this->SetEventDataSrcIp(event.SrcIp);
    this->SetEventDataDstIp(event.DstIp);
    //5055

    return;
}


void Rule::SetEventMatchLastTime(time_t time)
{
    this->mEventLastMatchTime = time;
    return;
}


int Rule::GetEventDataSrcPort()
{
    return 0;//this->src_port;
}

int Rule::GetEventDataDstPort()
{
    return 0;//this->dst_port;
}

void Rule::AddRuleMatchSrcPort(int port)
{
    /* ����Hash���棬KeyΪsrcport��0-65535����ֵΪ1 */
    if ((port >=0) && (port <=65535))
    {
        this->mapSrcPort.insert(pair<int, int>(port, 1));
    }

    return;
}

void Rule::AddRuleMatchSrcPortNot(int port)
{
    /* ����Hash���棬KeyΪsrcport_not��0-65535����ֵΪ1 */
    /* ����Hash���棬KeyΪsrcport��0-65535����ֵΪ1 */
    if ((port >=0) && (port <=65535))
    {
        this->mapSrcPortNot.insert(pair<int, int>(port, 1));
    }
}


void Rule::AddRuleMatchDstPort(int port)
{
    if ((port >=0) && (port <=65535))
    {
        this->mapDstPortNot.insert(pair<int, int>(port, 1));
    }
}

void Rule::AddRuleMatchDstPortNot(int port)
{
    if ((port >=0) && (port <=65535))
    {
        this->mapDstPortNot.insert(pair<int, int>(port, 1));
    }
}

/* */
/*
OSSIM�����6������
��1��ANY
��2��x.x.x.x ָ��IP����
��3�����ú�����Э������ 1:SRC_IP , 1:SRC_IP:80
��4����������,��Ӧ���ζ��� 192.168.150.0/24 C������
��5���ض���ַ��ʹ�ö��ŷָ� 192.168.150.202, 192.168.150.201
��6������ʽ !192.168.150.200

Ŀǰֻʵ�����õķ�ʽ
 */
void Rule::SetVarIp(IpAddress *ipa, RuleVar * var)
{
    if (var->attr == SIM_RULE_VAR_SRC_IA)
    {
        if (var->negated)
        {
            this->SetEventDataSrcIpNot(ipa);
        }
        else
        {
            this->SetEventDataSrcIp(ipa);
        }
    }
    else if (var->attr == SIM_RULE_VAR_DST_IA)
    {
        if (var->negated)
        {
            this->SetEventDataDstIpNot(ipa);
        }
        else
        {
            this->SetEventDataDstIp(ipa);
        }
    }
}
/*
���򱣴���������ࣺ
��1�����õĹ������� sim_xml_directive_new_rule_from_node
     a. �������ͣ����浽 varslist
     b. ��������ݣ����浽 list
��2��ƥ����¼������ݣ�ֱ�ӱ��浽��Ӧ��sim_rule_set_event_data
��3��ƥ�����ĺ��ӽڵ㣬�����ø��µ�ʵ������list    sim_directive_set_rule_vars
 */
void Rule::SetEventDataSrcIpNot(IpAddress* ipaddress)
{
    if (this->EventDataSrcIpNot) delete this->EventDataSrcIpNot;
    this->EventDataSrcIpNot = NULL;
    if (ipaddress) this->EventDataSrcIpNot = new IpAddress(ipaddress);
}

void Rule::SetEventDataSrcIp(IpAddress* ipaddress)
{
    if (this->EventDataSrcIp) delete this->EventDataSrcIp;
    this->EventDataSrcIp = NULL;
    if (ipaddress) this->EventDataSrcIp = new IpAddress(ipaddress);
}

void Rule::SetEventDataDstIpNot(IpAddress* ipaddress)
{
    if (this->EventDataDstIpNot) delete this->EventDataDstIpNot;
    this->EventDataDstIpNot = NULL;
    if (ipaddress) this->EventDataDstIpNot = new IpAddress(ipaddress);
}

void Rule::SetEventDataDstIp(IpAddress* ipaddress)
{
    if (this->EventDataDstIp) delete this->EventDataDstIp;
    this->EventDataDstIp = NULL;
    if (ipaddress) this->EventDataDstIp = new IpAddress(ipaddress);
}

/*Rule& Rule::operator=(Rule& rule)
{
    //�ͷŶ��ڴ�

    //��ֵstack����ֵ

    //��ֵheap�ڴ�ֵ

    //ָ�봦��

    //list, vec, map����
    return *this;
}*/


IpAddress * Rule::GetEventDataSrcIp()
{
    return this->EventDataSrcIp;
}

IpAddress * Rule::GetEventDataSrcNotIp()
{
    return this->EventDataSrcIpNot;
}

IpAddress * Rule::GetEventDataDstIp()
{
    return this->EventDataDstIp;
}

IpAddress * Rule::GetEventDataDstNotIp()
{
    return this->EventDataDstIpNot;
}

/* ���涨���RefRuleVar��list */
void  Rule::SetRuleVarsToList(RuleVar *var)
{
    this->lstRuleVar.push_back(var);
    return;
}


/* static gboolean sim_xml_directive_set_rule_ports (SimRule * rule, gchar * value, gboolean are_src_ports)*/
void Rule::SetRuleMatchPort(char* portstring, bool is_srcport)
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
                            this->AddRuleMatchSrcPortNot(port);
                        else
                            this->AddRuleMatchDstPortNot(port);
                    }
                    else
                    {
                        if (is_srcport)
                            this->AddRuleMatchSrcPort(port);
                        else
                            this->AddRuleMatchDstPort(port);
                    }

                }
            }
            else //ֻ��һ�����ֶ˿�
            {
                int port = stoi(token_value.c_str(), 0, 10);
                if (port_neg)
                {
                    if (is_srcport)
                        this->AddRuleMatchSrcPortNot(port);
                    else
                        this->AddRuleMatchDstPortNot(port);
                }
                else
                {
                    if (is_srcport)
                        this->AddRuleMatchSrcPort(port);
                    else
                        this->AddRuleMatchDstPort(port);
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

        string::size_type  pos2, pos3, pos4, pos5;
        pos2 = token_value.find(":");
        pos3 = token_value.find(SIM_SRC_IP_CONST);
        pos4 = token_value.find(SIM_DST_IP_CONST);
        pos5 = token_value.find("/");

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
            // 1:DST_IP ��ð�ź�����ַ���ʼ
            var->type =sim_get_rule_var_from_char(token_value.substr(pos2+1, token_value.length()- pos2-1).c_str());
            this->lstRuleVar.push_back(var);
        }
        else if (token_value == "ANY")
        {
            // L1253
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

            // OSSIM�����ж����ض�IP������ !192.168.8.3 ,���� �ʲ����� �ݲ���Ҫ
            // �ж��Ƿ����� 192.168.2.1/24
            if ((pos5 !=  token_value.npos))
            {
                string ip         = token_value.substr(0, pos5);
                string maskstring = token_value.substr(pos5, token_value.size());
                int masknum = stoi(maskstring.c_str(), 0, 10); //У�飬�Ƿ�������
                INetwork network(maskstring, masknum);
                if (ip_neg)
                {
                    this->vecNetworknot.push_back(network);
                }
                else
                {
                    this->vecNetwork.push_back(network);
                }

            }

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
    if (this->EventDataSrcIp->vecIpNum[0]==event.SrcIp->vecIpNum[0] &&
        this->EventDataSrcIp->vecIpNum[1]==event.SrcIp->vecIpNum[1] &&
        this->EventDataSrcIp->vecIpNum[2]==event.SrcIp->vecIpNum[2] &&
        this->EventDataSrcIp->vecIpNum[3]==event.SrcIp->vecIpNum[3])
            return true;
    else
        return false;
    #if 0
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
    #endif
}

bool Rule::MatchDstIp(Event event)
{
    if (this->EventDataDstIp->vecIpNum[0]==event.DstIp->vecIpNum[0] &&
        this->EventDataDstIp->vecIpNum[1]==event.DstIp->vecIpNum[1] &&
        this->EventDataDstIp->vecIpNum[2]==event.DstIp->vecIpNum[2] &&
        this->EventDataDstIp->vecIpNum[3]==event.DstIp->vecIpNum[3])
            return true;
    else
        return false;
    #if 0
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
    #endif
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

Correlation::Correlation()
{
    //ctor
}

Correlation::~Correlation()
{
    //dtor
}

void Correlation::AddDirective(Backlogs* pBacklogs)
{
    if (pBacklogs == NULL) return;
    this->vecDirective.push_back(pBacklogs);
    /* ���뵱ǰbacklogs��MAP���� */
    this->AddDirectiveMapItem(pBacklogs);
}



void Correlation::DestoryDirective(Backlogs* pBacklogs)
{
    vector<Backlogs*>::iterator  it;
    Backlogs* backlogs;
    for (it=this->vecDirective.begin(); it!=this->vecDirective.end(); it++)
    {
        backlogs = *it;
        if (pBacklogs == backlogs)
        {
            this->vecDirective.erase(it);
            this->RemoveDirectiveMapItem(pBacklogs);
            //backlogs->Clear();
            delete backlogs;
            break;
        }
        it++;
    }
}

void Correlation::AddBacklogs(Backlogs* pBacklogs)
{
    if (pBacklogs == NULL) return;
    this->vecBacklogs.push_back(pBacklogs);
}

void Correlation::DestoryBacklogs(Backlogs* pBacklogs)
{
    vector<Backlogs*>::iterator  it;
    Backlogs* backlogs;
    for (it=this->vecBacklogs.begin(); it!=this->vecBacklogs.end(); it++)
    {
        backlogs = *it;
        if (pBacklogs == backlogs)
        {
            this->vecBacklogs.erase(it);
            //this->RemoveDirectiveMapItem(pBacklogs);
            //backlogs->Clear();
            delete backlogs;
            break;
        }
        it++;
    }
}


//���� blacklog_idκKeyֵ��map��
void Correlation::AddDirectiveMapItem(Backlogs* pBacklogs)
{
    BacklogsList  *blist;
    std::map<int, BacklogsList *> thismap;
    std::map<int, BacklogsList *>::iterator  itr;
    std::list<Backlogs *> lstBacklogsPlugin;
    std::list<Backlogs *>::iterator it_plugin;
    std::list<Backlogs *>::iterator it;
    TreeNode * rootnode;
    Rule * rootrule;
    int plugin_id;

    if (pBacklogs == NULL) return;

    rootnode = pBacklogs->GetRootNode();

    if (rootnode == NULL ) return;

    rootrule = rootnode->GetRule();
    plugin_id = rootrule->plugin_id;



	itr = mapDirective.find(plugin_id);
	if(itr != mapDirective.end())
	{
        /* ���ҽ����std::list */
		blist = itr->second;
		blist->lstBacklogs.push_back(pBacklogs);
	}
	else
	{
	    blist = new BacklogsList();
	    blist->lstBacklogs.push_back(pBacklogs);
	    mapDirective.insert(pair<int, BacklogsList*>(plugin_id, blist));
	}
}

void Correlation::RemoveDirectiveMapItem(Backlogs* pBacklogs)
{
    BacklogsList  *blist;
    std::map<int, BacklogsList *> thismap;
    std::map<int, BacklogsList *>::iterator  itr;
    std::list<Backlogs *> lstBacklogsPlugin;
    std::list<Backlogs *>::iterator it_plugin;
    std::list<Backlogs *>::iterator it;
    TreeNode * rootnode;
    Rule * rootrule;
    int plugin_id;

    if (pBacklogs == NULL) return;

    rootnode = pBacklogs->GetRootNode();

    if (rootnode == NULL ) return;

    rootrule = rootnode->GetRule();
    plugin_id = rootrule->plugin_id;



	itr = mapDirective.find(plugin_id);
	if(itr != mapDirective.end())
	{
        /* ���ҽ����std::list */
		blist = itr->second;
		blist->lstBacklogs.push_back(pBacklogs);
	}
	else
	{
        /* û�в��ҵ� */
	}
}

void Correlation::DoCorrelation(Event event)
{

    MatchBacklogs(event);

    MatchDirective(event);

    return;

}

void Correlation::MatchBacklogs(Event event)
{
    vector<Backlogs*>::iterator it;
    TreeNode * currentnode;

    Backlogs  *pBacklogs;

    /* ����б�Ԫ�� */
    this->lstMatchedBacklogs.clear();

    it = vecBacklogs.begin();
    while(it != vecBacklogs.end())
    {
        pBacklogs = *it;


        if (pBacklogs->IsTimeout() || pBacklogs->IsMatched())
        {

            this->vecBacklogs.erase(it);
            delete pBacklogs;
            printf("backlogs Timeout!\n");
            //it++;
            continue;
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


            // L375
            event.rule_matched = true;
            event.directive_matched = true;

            // L217 �����ǰ�ڵ���Ҷ�ӽڵ㣬sim_directive_backlog_set_deleted (backlog, TRUE);
            std::vector<TreeNode*> vecTreeNode2 = currentnode->GetChildren();
            if (vecTreeNode2.empty())
            {
                this->vecBacklogs.erase(it);
                delete pBacklogs;
                //���ﲻ��it++��vectorɾ��Ԫ�غ���Զ�����λ�úͳ���
                printf("backlogs Matched!\n");
                continue;
            }
        }
        else if (event.rule_matched)
        {
             /* When the ocurrence is > 1 in the rule, the first call to sim_directive_backlog_match_by_event (above)
                will return FALSE, and the event won't be inserted in db. So we have to insert it here. */

             // L253 �¼�û��ƥ��ָ������¼��Ѿ�ƥ�䵽ĳ������
             //event.backlog_id = pBacklogs->GetBacklogsId(); // ����ʱ��ƥ���backlog_id
             pBacklogs->UpdateFirstLastTs(event); // L265 ����backlog��firstevent �� lastevent��ʱ��
        }

        // ��¼��ǰƥ���backlog_id��list
        if (event.rule_matched)
        {
            this->lstMatchedBacklogs.push_back(pBacklogs);
        }

        // �����¼��Ĺ���ƥ��״̬��ָ��ƥ��״̬�� ������һѭ��
        event.rule_matched = false;
        event.directive_matched = false;

        it++;
    }

    return;
}


// L286
// ƥ��plugin_id�� = �Ѿ�ƥ�䵱ǰ�¼� + �� ƥ������� + ��ƥ�������
void Correlation::MatchDirective(Event event)
{
    std::list<Backlogs *> lstMatchedBacklogs; //�Ѿ�ƥ�䵱ǰ�¼�������ָ��
    BacklogsList *blist;                 //��ǰ�¼�plugin_id ��Ӧ������ָ��
    std::map<int, BacklogsList*> thismap;
    std::map<int, BacklogsList*>::iterator  itr;
    std::map<int, BacklogsList*>::iterator  itr_any;
    std::list<Backlogs *> lstBacklogsPlugin;
    std::list<Backlogs *>::iterator it_plugin;
    std::list<Backlogs *>::iterator it;
    TreeNode *rootnode;
    Rule * rootrule;

    bool  isEventMatchRootRule = true;
    Backlogs * pBacklog = NULL;
    Backlogs * pBacklog_plugin = NULL;


    thismap = this->mapDirective;
    lstMatchedBacklogs = this->lstMatchedBacklogs;
	itr = thismap.find(event.plugin_id);
	if(itr != thismap.end())
	{
        /* ���ҽ����std::list */
		blist = itr->second;


        for (it_plugin= blist->lstBacklogs.begin(); it_plugin !=blist->lstBacklogs.end(); it_plugin++)
        {
            pBacklog_plugin = *it_plugin;

            for (it = lstMatchedBacklogs.begin(); it != lstMatchedBacklogs.end(); it++)
            {
                //
                pBacklog = (Backlogs *)*it;

                /* �Ѿ�ƥ���,����Ҫ���� */
                if (pBacklog_plugin->directive_id == pBacklog->directive_id) return;
            }

            //@event plugin_id in @event context L312


            // L336  ���event�¼��Ƿ�����ָ���ʱ�䷶Χ


            // ����¼��Ƿ�ƥ��ָ��ĸ��ڵ����
            isEventMatchRootRule = pBacklog_plugin->DirectiveRootRuleMatchEvent(event);


            /* �жϼ�ƥ����plugin����ƥ���˸�ָ���Ҫ�½�Backlogs����

               ��������£����������Ϊsrc IPΪANY��������������1��SRC_IP, ��ô��ͬsrc IP���¼����������ͬ��backlogs
             */
            Backlogs * pNewBacklogs = pBacklog_plugin->clone();

            this->AddBacklogs(pNewBacklogs);

            if (isEventMatchRootRule == true)
            {
                // ����ָ���� backlog �� backlog_id, backlogĬ��һֱ���ڣ�����ֻ�������
                // pNewBacklogs->SetClearAllMatchData();

                // pNewBacklogs->SetEmpty(false);

                // ��ȡbacklog�ĸ��ڵ�͸�����
                rootnode = pNewBacklogs->GetRootNode();
                rootrule = rootnode->GetRule();

                pNewBacklogs->SetCurrentRuleNode(rootnode);

                // ����rule_root��lasttime L362
                //time_t        time_last = time (NULL);
                rootrule->SetEventMatchLastTime(time (NULL));

                // ����backlog�� first_last_ts  L363
                pNewBacklogs->UpdateFirstLastTs(event);


                // L368 sim_rule_set_event_data (rule_root, event);
                // // ���¼��������ֶα��浽������
                rootrule->SetEventDataToRule(event);

                event.rule_matched = true;
                event.directive_matched = true;
                /*  ������ӽڵ�Ϊ�գ���ƥ�䵱ǰָ�� */
                //rootnode->GetChildren();
            }
        }

	}

	//��Ҫ��������plugin_idΪANY(0x7FFFFFFF)������
    itr_any = thismap.find(0x7FFFFFFF); //ANY
	if(itr_any != thismap.end())
	{
        /* ���ҽ����std::list */
		blist = itr_any->second;
	}

    return;
}



/* ֻ���ڸ��ڵ㴴�� */
TreeNode::TreeNode(TreeNode* parent)
{
    this->parent = parent;
    if (parent == NULL)
        this->SetLevel(1);  //���ڵ�levelΪ1
    else
        this->SetLevel(parent->GetLevel()+1);
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

IpAddress::IpAddress(vector<int> &octetsIP)
{
    int num;
    vector<int>::iterator  itr;
    for (itr=octetsIP.begin(); itr!=octetsIP.end(); itr++)
    {
        num = *itr;
        this->vecIpNum.push_back(num&0xFF);
        //printf("%d.", num);
    }
}

IpAddress::IpAddress(IpAddress* ipa)
{
    //���ӳ�ʼ��
}

IpAddress::~IpAddress()
{

}

IpAddress::IpAddress(string ip)
{
    stringstream sip(ip);
    string temp;
    this->vecIpNum.clear();
    while (getline(sip,temp,'.'))
        this->vecIpNum.push_back(atoi(temp.c_str()));
}

string IpAddress::GetIpString()
{
    if (this->vecIpNum.size() == 4)
    {
        stringstream ss;
        ss.clear();
        ss<<vecIpNum[0]<<"."<<vecIpNum[1]<<"."<<vecIpNum[2]<<"."<<vecIpNum[3];
        string s=ss.str();
        return s;
    }
    else
    {
        string s = "";
        return s;
    }
}

int GetOctetsIP(string ip, vector<int> &octetsIP) {     // Define vector<int> octets, using reference from main
    stringstream sip(ip);
    string temp;
    octetsIP.clear();
    vector<bool> ipInRange;
    while (getline(sip,temp,'.'))
        octetsIP.push_back(atoi(temp.c_str()));
    if (octetsIP.size() == 4) {
        for(int i = 0; i < 4; i++)
        {
            if (octetsIP[i] >= 0 && octetsIP[i] <= 255)
                ipInRange.push_back(true);
            else
                ipInRange.push_back(false);
        }
        if (ipInRange[0]==true&&ipInRange[1]==true&&ipInRange[2]==true&&ipInRange[3]==true)
        {
            return 0;
        }
        else
        {
            cout << endl << "There are only 255 bits per octet. Please re-enter IP." << endl << endl;
            return 1;
        }
    }
    else
    {
        cout << endl << "Please enter four octets in dot notation." << endl << endl;
        return 1;
    }
}

INetwork::INetwork()
{

}

INetwork::INetwork(string network)
{

}

INetwork::INetwork(string networkip, int masknum)
{
    stringstream sip(networkip);
    string temp;
    this->vecIpNum.clear();

    while (getline(sip,temp,'.'))
        this->vecIpNum.push_back(0xFF & atoi(temp.c_str()));

    if (this->vecIpNum.size() == 4)
    {
    }
    else
    {
        this->vecIpNum.push_back(0);
        this->vecIpNum.push_back(0);
        this->vecIpNum.push_back(0);
        this->vecIpNum.push_back(0);
    }
}

bool INetwork::IsIpMatched(IpAddress ipa)
{
    return false;

}

INetwork::~INetwork()
{

}


