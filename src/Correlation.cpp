#include "Correlation.h"
#include <list>
#include <vector>
#include <iostream>
#include <stdio.h>

using namespace std;

//gchar     *version2 = "fadfa";

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

Backlogs::Backlogs()
{
    //ctor
}

Backlogs::~Backlogs()
{
    //dtor
}


bool Backlogs::IsMatched()
{
    return true;
}

bool Backlogs::IsTimeout()
{
    return true;
}


// sim_directive_backlog_match_by_event  L764
bool Backlogs::MatchEvent(Event event)
{


    //是否匹配当前事件
    //取当前current_rule
    Rule * pRule;
    Rule * currentRule = GetCurrentRule();
    bool  isMatchRule;


    TreeNode * node = NULL;// = currentRule->child;
    TreeNode * child_node = NULL;// = currentRule->child;

    //node = node ->GetChildren

    std::vector<TreeNode*> vecTreeNode = currentRule->child->GetChildren();

    //  遍历 current_rule 的所有孩子节点的规则

    vector<TreeNode*>::iterator it;

    std::vector<TreeNode*> vecTreeNode2;
    vector<TreeNode*>::iterator it2;


    it = vecTreeNode.begin();
    while(it != vecTreeNode.end())
    {
        node = *it;

        pRule = (Rule*)  node->GetNumber();

        isMatchRule = pRule->MatchEvent(event);

        time_t time_last = time (NULL);
        if (isMatchRule == true)
        {


            SetCurrentRule(pRule);


            //设置时间
            SetTimeLastCurrentTime(time_last);
            UpdateFirstLastTs(event);
            UpdateTimeout();

            //保存当前事件属性到规则匹配数据中， 满足ANY的情况
            pRule->SetDataToRule(event);

            pRule->SetTimeLast(time_last);
        }


        // 如果当前节点是叶子节点
        vecTreeNode2 = node->GetChildren();
        if (vecTreeNode2.empty())
        {
            //已经搜索到叶子节点，说明已经匹配指令

        }
        else
        {
            //非叶子节点，把当前的事件匹配数据传递到所有孩子节点

            it2 = vecTreeNode2.begin();
            while(it2 != vecTreeNode.end())
            {
                child_node = *it2;

                pRule = (Rule*)  child_node->GetNumber();
                pRule->SetTimeLast(time_last);
                SetRuleVars(child_node);

                it2++;
            }
        }

        it++;

    }

    return true;

}

void Backlogs::UpdateFirstLastTs(Event event)
{

}

void Backlogs::SetTimeLastCurrentTime(time_t time)
{

}

void Backlogs::UpdateTimeout()
{

}

Rule* Backlogs::GetCurrentRule()
{
    return NULL;
}

void Backlogs::SetCurrentRule(Rule *pRule)
{

}


Directive* Backlogs::GetDirective()
{
    return NULL;
}


void Backlogs::SetRuleVars(TreeNode * node)
{
    //
    Rule * pRule;
    Rule * pRuleUp;
    TreeNode * node_up;
    RuleVar * ruleVar;
    int port;
    pRule = (Rule*) node->GetNumber();

    vector<RuleVar *>::iterator it;


    it = pRule->vecVars.begin();
    while(it != pRule->vecVars.end())
    {
    /// 查找当前节点  level以上的节点
        ruleVar = *it;
        node_up = GetNodeBranchByLevel(node, ruleVar->level);

        if (!node_up)
        {
            it++;
            continue;
        }
        pRuleUp = (Rule*)node_up->GetNumber();
        switch (ruleVar->type)
        {
            case SIM_RULE_VAR_SRC_PORT:
                port = pRuleUp->GetSrcPort();
                switch (ruleVar->attr)
                {
                    case SIM_RULE_VAR_SRC_PORT:
                        if (ruleVar->negated)
                            pRuleUp->AddSrcPortNot(port);
                        else
                            pRuleUp->AddSrcPort(port);
                        break;
                    case SIM_RULE_VAR_DST_PORT:
                        if (ruleVar->negated)
                            pRuleUp->AddDstPortNot(port);
                        else
                            pRuleUp->AddDstPort(port);
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
                            pRuleUp->AddSrcPortNot(port);
                        else
                            pRuleUp->AddSrcPort(port);
                        break;
                    case SIM_RULE_VAR_DST_PORT:
                        if (ruleVar->negated)
                            pRuleUp->AddDstPortNot(port);
                        else
                            pRuleUp->AddDstPort(port);
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

bool Rule::MatchEvent(Event event)
{
    return true;
}

void Rule::SetDataToRule(Event event)
{
    return;
}


void Rule::SetTimeLast(time_t time)
{
    return;
}


int Rule::GetSrcPort()
{
    return 0;
}

int Rule::GetDstPort()
{
    return 0;
}

void Rule::AddSrcPort(int port)
{
    return;
}

void Rule::AddSrcPortNot(int port)
{

}

void Rule::AddDstPort(int port)
{

}

void Rule::AddDstPortNot(int port)
{

}


void Correlation::DoCorrelation(Event event)
{

    printf("DoCorrelation\n");
    MatchBacklogs(event);
    MatchBacklogs(event);

    vector<Backlogs>::iterator it;

    return;

}

void Correlation::MatchBacklogs(Event event)
{
    vector<Backlogs>::iterator it;
    Directive *pDirective;
    //Backlogs  *pBacklogs;
    //for (it = vecBacklogs.begin(); it!=vecBacklogs.end(); it++)
    it = vecBacklogs.begin();
    while(it != vecBacklogs.end())
    {
        //cout <<*it <<" ";
        //if (!it)
        //Backlogs *backlog = (Backlogs*)it;
        it->m_d = 0;
        //pBacklogs = (Backlogs*)it;
        pDirective = it->GetDirective();

        if (it->IsTimeout() || it->IsMatched())
        {
          //删除Backlogs
        }


        //sim_directive_backlog_match_by_event
        bool isMatchBacklogs = it->MatchEvent(event);

        if (isMatchBacklogs)
        {
            //Line194 sim_correlation.c
            //get current node

            // get backlogs_id  L204
            // set event backlog_id
            //// 更新事件的backlog_id
            ////if(event->backlog_id) g_object_unref (event->backlog_id);
            ////event->backlog_id = g_object_ref (backlog_id);
            //// 更新backlog的firstevent 和 lastevent的时间
            //// sim_directive_update_backlog_first_last_ts(backlog, event);
            it->UpdateFirstLastTs(event);


            // 如果当前规则节点时叶子节点，sim_directive_backlog_set_deleted (backlog, TRUE);


        }
        else
        {
             /* When the ocurrence is > 1 in the rule, the first call to
         sim_directive_backlog_match_by_event (above) will return FALSE, and the event won't be
         inserted in db. So we have to insert it here. */

            // 事件没有匹配指令，但是事件已经匹配到某个规则
            // 更新时间匹配的backlog_id
             // L265 更新backlog的firstevent 和 lastevent的时间
             it->UpdateFirstLastTs(event);
        }

        // 记录当前匹配的backlog_id到list
        lstBacklogs.push_back(pDirective);


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
    std::list<Directive *> lstDirective;
    // 
    Directive * pDirective;
    bool  isDataInList = false;
    bool  isEventMatchRootRule = true;
    Backlogs * pBacklog = NULL;

    std:list<Directive *>::iterator it;
    for (it = lstDirective.begin(); it != lstDirective.end(); it++)
    {
        //
        pDirective = (Directive *)*it;
        // 检查当前Directive 是否在匹配的backlogs列表lstBacklogs里
        if (isDataInList == true )
            continue; //如果已经匹配，则跳过不处理。

        // L336
        //检查event事件是否在指令的是否范围之内


        // 检查事件是否匹配指令的根节点规则
        if (isEventMatchRootRule == true)
        {
            // 创建指定的 backlog 及 backlog_id

            // 获取backlog的根节点和根规则

            // 设置rule_root的lasttime L362

            // 更新backlog的 first_last_ts  L363
            pBacklog->UpdateFirstLastTs(event);


            // L368 sim_rule_set_event_data (rule_root, event);
            // // 把事件的属性字段保存到根规则

        }


    }
    return;
}


TreeNode::TreeNode(TreeNode* parent)
{
    this->parent = parent;
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
    child->SetLevel(this->GetLevel() + 1);
    children.push_back(child);
    return child;
}

vector<TreeNode*> TreeNode::GetChildren()
{
    return children;
}
