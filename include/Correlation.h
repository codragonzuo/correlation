#ifndef CORRELATION_H
#define CORRELATION_H
#include <cstdlib>
#include <vector>
#include <list>
#include <string>
#include <time.h>
//#include <glib.h>

using namespace std;

int xmltest();

class Directive;
class Rule;
class RuleVar;

/* N-way tree implementation
 */

// https://github.com/vkiz/n-ary-tree/
class TreeNode
{
public:
	TreeNode(TreeNode* parent);

	void SetLevel(size_t level);
	void SetNumber(size_t number);
	size_t GetLevel();
	size_t GetNumber();
	TreeNode* AddChild();
	TreeNode* GetParent();
	std::vector<TreeNode*> GetChildren();

private:
	size_t level;
	size_t number;
	TreeNode* parent;
	std::vector<TreeNode*> children;
};


class Event
{
    public:
        Event();
        virtual ~Event();


    protected:

    private:
};


// 类名： Directive
// 说明： 关联指令
class Directive
{
    public:
        Directive();
        virtual ~Directive();
        int m_d;
        Rule* GetCurrentRule();
        bool IsMatchEvent(Event event);


    protected:

    private:
};

class Backlogs
{
    public:
        Backlogs();
        virtual ~Backlogs();
        int m_d;
        Directive * GetDirective();
        bool IsMatched();
        bool IsTimeout();
        bool MatchEvent(Event event);
        Rule* GetCurrentRule();
        void SetCurrentRule(Rule *pRule);
        void GetCurrentNode();
        void UpdateFirstLastTs(Event event);
        void SetTimeLastCurrentTime(time_t time);
        void UpdateTimeout();
        void SetRuleVars(TreeNode * node);
        TreeNode* GetNodeBranchByLevel(TreeNode * node, int level);
        TreeNode* GetRootNode();

    public:
        int directive_id;
        string name;
        int priority;

    protected:

    private:
};


class Rule
{
    public:
        TreeNode * child;
        bool MatchEvent(Event event);
        void SetDataToRule(Event event);
        void SetTimeLast(time_t time);
        std::vector<RuleVar*> vecVars;
        int GetSrcPort();
        int GetDstPort();
        void AddSrcPort(int port);
        void AddSrcPortNot(int port);
        void AddDstPort(int port);
        void AddDstPortNot(int port);
    public:
        int src_port;
        int dst_port;
        string type;
        string name;
        int reliability;
        int occurrence;
        string from;
        string to;
        string port;
        string port_from;
        string port_to;
        int timeout;
        string plugin_id;
        string plugin_sid;


};


// Class:   Correlation
// 说明：   关联引擎管理类
class Correlation
{
    public:
        std::list<Directive *> lstBacklogs;
    public:
        Correlation();
        virtual ~Correlation();
        void DoCorrelation(Event event);
        void MatchBacklogs(Event event);
        void MatchDirective(Event event);
        std::vector<Backlogs> vecBacklogs;

    protected:

    private:
};


typedef enum {
  SIM_RULE_VAR_NONE,
  SIM_RULE_VAR_SRC_IA,
  SIM_RULE_VAR_DST_IA,
  SIM_RULE_VAR_SRC_PORT,
  SIM_RULE_VAR_DST_PORT,
  SIM_RULE_VAR_PROTOCOL,
  SIM_RULE_VAR_PLUGIN_ID,
  SIM_RULE_VAR_PLUGIN_SID,
  SIM_RULE_VAR_SENSOR,
  SIM_RULE_VAR_PRODUCT,
  SIM_RULE_VAR_ENTITY,
  SIM_RULE_VAR_CATEGORY,
  SIM_RULE_VAR_SUBCATEGORY,
  SIM_RULE_VAR_FILENAME,
  SIM_RULE_VAR_USERNAME,
  SIM_RULE_VAR_PASSWORD,
  SIM_RULE_VAR_USERDATA1,
  SIM_RULE_VAR_USERDATA2,
  SIM_RULE_VAR_USERDATA3,
  SIM_RULE_VAR_USERDATA4,
  SIM_RULE_VAR_USERDATA5,
  SIM_RULE_VAR_USERDATA6,
  SIM_RULE_VAR_USERDATA7,
  SIM_RULE_VAR_USERDATA8,
  SIM_RULE_VAR_USERDATA9,
  SIM_RULE_VAR_PULSE_ID
} SimRuleVarType;


class RuleVar {
  public:
      SimRuleVarType   type;  //ie.: in the "from" in directives, you can put n:SRC_IP or n:DST_IP. This variable stores wich one is the right
      SimRuleVarType   attr;  //this is used to know wich field is referenced in directives ("from", "to", "src_ip"...)
      int             level;
      bool          negated;  //if this is YES, then the field referenced will be stored in the negated fields (ie. src_ports_not, plugin_sids_not...)
};

#endif // CORRELATION_H
