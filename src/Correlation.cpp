#include "Correlation.h"
#include <list>
#include <vector>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>


using namespace std;



/* 字符串分割函数 */
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
    /* 第一次进入，时间为0，不会失效 */
    if ((!this->time_out) || (!this->time_last))	//if directive hasn't got any time, this//is the 1st time it enteres here, so no timeout.
        return false;

    /* timeout判断 */
    if (time (NULL) > (this->time_last + this->time_out))
        return true;

    return false;
}


// sim_directive_backlog_match_by_event  L764
bool Backlogs::MatchEvent(Event event)
{
    //是否匹配当前事件
    //取当前current_rule
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


    //  遍历 current_rule 的所有孩子节点的规则

    vector<TreeNode*>::iterator it;

    std::vector<TreeNode*> vecTreeNode2;
    vector<TreeNode*>::iterator it2;


    it = vecTreeNode.begin();
    while(it != vecTreeNode.end())
    {
        node = *it;


        //L784 是否匹配节点规则
        pRule = node->GetRule();
        isMatchRule = pRule->MatchEvent(event);

        time_t time_last = time (NULL);

        // L344
        if (isMatchRule == true)
        {

            //L790
            SetCurrentRuleNode(node);


            // L793 设置时间
            SetTimeLastCurrentTime(time_last);

            //
            UpdateFirstLastTs(event);

            // L795
            UpdateTimeout();

            // L798 保存当前事件属性到规则匹配数据中， 满足ANY的情况 sim_rule_set_event_data
            pRule->SetEventDataToRule(event);

            // L801
            pRule->SetTimeLast(time_last);
        }


        // L803 如果当前节点是叶子节点
        std::vector<TreeNode*>  vecTreeNode2 = node->GetChildren();
        if (vecTreeNode2.empty())
        {
            // L821 已经搜索到叶子节点，说明已经匹配指令
            this->SetMatched(true);

        }
        else
        {
            //非叶子节点，把当前的事件匹配数据vars传递到当前节点的所有孩子节点
            it2 = vecTreeNode2.begin();
            int b = 0;
            while(it2 != vecTreeNode.end())
            {

                child_node = *it2;

                pRule = (Rule*)  child_node->GetRule();
                pRule->SetTimeLast(time_last);

                // L814 把当前匹配规则的所有引用数据Var传递到孩子节点
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
// (1)如果匹配了当前规则，把当前匹配规则的vars值设置到所有孩子节点。
// (2)查找所有孩子节点的引用level:vars值，是指到所有孩子节点
// 当前规则匹配，更新下一级规则的引用变量
void Backlogs::SetRuleRefVars(TreeNode * node)
{
    Rule * pRule;
    Rule * pRuleUp;
    TreeNode * node_up;
    RuleVar * ruleVar;
    int port;
    IpAddress* ipa;
    pRule = node->GetRule();

    /* L925 遍历规则的所有vars */
    std::list <RuleVar *>::iterator it;
    it = pRule->lstRuleVar.begin();
    while (it != pRule->lstRuleVar.end())
    {
        /// 查找当前节点的up节点，  1<=level<=current-level 节点
        ruleVar = *it;
        node_up = GetNodeBranchByLevel(node, ruleVar->level);// 根据vanr->level 找 祖辈节点

        if (!node_up)
        {
            it++;
            continue;
        }
        pRuleUp = (Rule*)node_up->GetRule();
        //获取引用规则的 level:vars的值， 设置到当前规则vars
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
            this->count_occu++; // 加1
            //event->count = rule->_priv->count_occu - 1; //减1
        }
        else
        {
            //event->count = rule->_priv->occurrence;
            this->count_occu = 1;   //
        }
    }
    else
    {
        event.count = 1;  // 缺省值
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
    /* 建立Hash表保存，Key为srcport（0-65535），值为1 */
    if ((port >=0) && (port <=65535))
    {
        this->mapSrcPort.insert(pair<int, int>(port, 1));
    }

    return;
}

void Rule::AddSrcPortNot(int port)
{
    /* 建立Hash表保存，Key为srcport_not（0-65535），值为1 */
    /* 建立Hash表保存，Key为srcport（0-65535），值为1 */
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

/* 保存定义的RefRuleVar到list */
void  Rule::SetRuleVarsToList(RuleVar *var)
{
    this->lstRuleVar.push_back(var);
    return;
}


/* static gboolean sim_xml_directive_set_rule_ports (SimRule * rule, gchar * value, gboolean are_src_ports)*/
void Rule::SetRulePort(char* portstring, bool is_srcport)
{
    /* 把portstring按照','分割成字符串数组 */
    //字符串分割测试
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
            //找到分隔符
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
            //没有找到
            //端口范围场景，比如"1-5"
            pos2 = token_value.find("-");
            if (pos2 !=  token_value.npos)
            {
                //找到分隔符
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
            else //只有一个数字端口
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

    /*对字符串数组进行遍历 */

}

void Rule::SetRuleIp(char* ipstring, bool is_sourceip)
{
    /* 把portstring按照','分割成字符串数组 */
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
            //找到分隔符
            string levelstr = token_value.substr(0, pos2);

            RuleVar *var = new RuleVar();
            var->level = stoi(levelstr.c_str(), 0, 10); //校验，是否是整数
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
            // OSSIM这里判断是特定IP，比如 !192.168.8.3 ,或者 资产名称
            // 暂不需要

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
    if (isInet) // 如果规则里面存着子网，判断event.src_ia是否在子网内
    {
        positive_match = true;
    }

    //Not子网匹配
    if (isInetNot) // 如果规则里面存着子网，判断event.src_ia是否在子网内
    {
        negated_match = true;
    }

    /* If there are any matches here, then return the most exact one */
    // 有一个匹配认为是匹配
    if (positive_match != false || negated_match != false) return true;


    // HOME_NET定义了框架下的所有网络   // !HOME_NET


    return false;
}

bool Rule::MatchDstIp(Event event)
{
    bool isInet = true;
    bool isInetNot = true;
    bool positive_match = false;
    bool negated_match = false;
    //event.src_ia
    if (isInet) // 如果规则里面存着子网，判断event.src_ia是否在子网内
    {
        positive_match = true;
    }

    //Not子网匹配
    if (isInetNot) // 如果规则里面存着子网，判断event.src_ia是否在子网内
    {
        negated_match = true;
    }

    /* If there are any matches here, then return the most exact one */
    // 有一个匹配认为是匹配
    if (positive_match != false || negated_match != false) return true;


    // HOME_NET定义了框架下的所有网络   // !HOME_NET


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
          //删除Backlogs
            pBacklogs->Clear();
        }

        //sim_directive_backlog_match_by_event
        bool isMatchBacklogs = pBacklogs->MatchEvent(event);

        if (isMatchBacklogs)
        {
            // L194 get current node
            currentnode = pBacklogs->GetCurrentRuleNode();

            // get backlogs_id  L204
            // set event backlog_id   //// 更新事件的backlog_id

            ////if(event->backlog_id) g_object_unref (event->backlog_id);
            ////event->backlog_id = g_object_ref (backlog_id);

            //L212 更新backlog的firstevent 和 lastevent的时间
            pBacklogs->UpdateFirstLastTs(event);


            // L217 如果当前节点是叶子节点，sim_directive_backlog_set_deleted (backlog, TRUE);
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

             // 事件没有匹配指令，但是事件已经匹配到某个规则
             event.backlog_id = pBacklogs->GetBacklogsId(); // 更新时间匹配的backlog_id
             pBacklogs->UpdateFirstLastTs(event); // L265 更新backlog的firstevent 和 lastevent的时间
        }

        // 记录当前匹配的backlog_id到list
        lstBacklogs.push_back(pBacklogs);


        // 重置事件的规则匹配状态和指令匹配状态， 进入下一循环
        //event->rule_matched = FALSE;
        //event->directive_matched = FALSE;

        it++;

    }
    return;
}


// L286
void Correlation::MatchDirective(Event event)
{
    //查找所有和事件的plugin_id匹配的所有指令
    std::list<Backlogs *> listBacklogs;
    std::map<int, std::list<Backlogs *>> thismap;
    std::map<int, std::list<Backlogs *>>::iterator  itr;
    std::list<Backlogs *> lstBacklogsPlugin;
    std::list<Backlogs *>::iterator it_plugin;
    std::list<Backlogs *>::iterator it;
    TreeNode *rootnode;
    Rule * rootrule;


    // 按照plugin_id来筛选backlogs
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
	    /* 没有找到 */
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

            /* 已经匹配过,不需要处理 */
            if (pBacklog_plugin == pBacklog) return;

        }

        // 一个事件可能查到多个对应的pBacklog_plugin,从而可能导致创建多个Backlog
        // 没有找到，需要新建Backlogs数据

        //@event plugin_id in @event context L312


        // L336
        // 检查event事件是否满足指令的时间范围


        // 检查事件是否匹配指令的根节点规则
        isEventMatchRootRule = pBacklog_plugin->DirectiveRootRuleMatchEvent(event);


        /* 判断既匹配了plugin，又匹配了根指令，需要新建Backlogs数据 */
        if (isEventMatchRootRule == true)
        {
            // 创建指定的 backlog 及 backlog_id, backlog默认一直存在，这里只情况数据
            pBacklog_plugin->SetClearAllMatchData();

            // 获取backlog的根节点和根规则
            rootnode = pBacklog->GetRootNode();
            rootrule = rootnode->GetRule();

            // 设置rule_root的lasttime L362
            time_t        time_last = time (NULL);
            rootrule->SetTimeLast(time_last);

            // 更新backlog的 first_last_ts  L363
            pBacklog_plugin->UpdateFirstLastTs(event);


            // L368 sim_rule_set_event_data (rule_root, event);
            // // 把事件的属性字段保存到根规则
            rootrule->SetEventDataToRule(event);

            event.rule_matched = true;
            event.directive_matched = true;

            rootnode->GetChildren();

        }
    }


    //需要查找所有plugin_id为ANY(0x7FFFFFFF)的情形

    return;
}


TreeNode::TreeNode(TreeNode* parent)
{
    this->parent = parent;
    if (parent == NULL)
        this->SetLevel(1);  //根节点level为1
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
    //增加初始化
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


