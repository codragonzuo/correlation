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


    //�Ƿ�ƥ�䵱ǰ�¼�
    //ȡ��ǰcurrent_rule
    Rule * pRule;
    Rule * currentRule = GetCurrentRule();
    bool  isMatchRule;


    TreeNode * node = NULL;// = currentRule->child;
    TreeNode * child_node = NULL;// = currentRule->child;

    //node = node ->GetChildren

    std::vector<TreeNode*> vecTreeNode = currentRule->child->GetChildren();

    //  ���� current_rule �����к��ӽڵ�Ĺ���

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


            //����ʱ��
            SetTimeLastCurrentTime(time_last);
            UpdateFirstLastTs(event);
            UpdateTimeout();

            //���浱ǰ�¼����Ե�����ƥ�������У� ����ANY�����
            pRule->SetDataToRule(event);

            pRule->SetTimeLast(time_last);
        }


        // �����ǰ�ڵ���Ҷ�ӽڵ�
        vecTreeNode2 = node->GetChildren();
        if (vecTreeNode2.empty())
        {
            //�Ѿ�������Ҷ�ӽڵ㣬˵���Ѿ�ƥ��ָ��

        }
        else
        {
            //��Ҷ�ӽڵ㣬�ѵ�ǰ���¼�ƥ�����ݴ��ݵ����к��ӽڵ�

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
    /// ���ҵ�ǰ�ڵ�  level���ϵĽڵ�
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
          //ɾ��Backlogs
        }


        //sim_directive_backlog_match_by_event
        bool isMatchBacklogs = it->MatchEvent(event);

        if (isMatchBacklogs)
        {
            //Line194 sim_correlation.c
            //get current node

            // get backlogs_id  L204
            // set event backlog_id
            //// �����¼���backlog_id
            ////if(event->backlog_id) g_object_unref (event->backlog_id);
            ////event->backlog_id = g_object_ref (backlog_id);
            //// ����backlog��firstevent �� lastevent��ʱ��
            //// sim_directive_update_backlog_first_last_ts(backlog, event);
            it->UpdateFirstLastTs(event);


            // �����ǰ����ڵ�ʱҶ�ӽڵ㣬sim_directive_backlog_set_deleted (backlog, TRUE);


        }
        else
        {
             /* When the ocurrence is > 1 in the rule, the first call to
         sim_directive_backlog_match_by_event (above) will return FALSE, and the event won't be
         inserted in db. So we have to insert it here. */

            // �¼�û��ƥ��ָ������¼��Ѿ�ƥ�䵽ĳ������
            // ����ʱ��ƥ���backlog_id
             // L265 ����backlog��firstevent �� lastevent��ʱ��
             it->UpdateFirstLastTs(event);
        }

        // ��¼��ǰƥ���backlog_id��list
        lstBacklogs.push_back(pDirective);


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
        // ��鵱ǰDirective �Ƿ���ƥ���backlogs�б�lstBacklogs��
        if (isDataInList == true )
            continue; //����Ѿ�ƥ�䣬������������

        // L336
        //���event�¼��Ƿ���ָ����Ƿ�Χ֮��


        // ����¼��Ƿ�ƥ��ָ��ĸ��ڵ����
        if (isEventMatchRootRule == true)
        {
            // ����ָ���� backlog �� backlog_id

            // ��ȡbacklog�ĸ��ڵ�͸�����

            // ����rule_root��lasttime L362

            // ����backlog�� first_last_ts  L363
            pBacklog->UpdateFirstLastTs(event);


            // L368 sim_rule_set_event_data (rule_root, event);
            // // ���¼��������ֶα��浽������

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
