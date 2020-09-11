#ifndef CORRELATION_H
#define CORRELATION_H
#include <cstdlib>
#include <vector>
#include <list>
#include <string>
#include <map>
#include <time.h>


#define SIM_PLUGIN_ID_ANY               0x7FFFFFFF


using namespace std;


void SplitString(const string& s, vector<string>& v, const string& c);
int xmltest();

class Directive;
class Rule;
class RuleVar;
class IpAddress;
class INetwork;

/* N-way tree implementation
 */

// https://github.com/vkiz/n-ary-tree/
class TreeNode
{
public:
	TreeNode(TreeNode* parent);

	void SetLevel(size_t level);
	void SetNumber(size_t number);
	void SetRule(Rule * rule);
	Rule * GetRule();
	size_t GetLevel();
	size_t GetNumber();
	TreeNode* AddChild();
	TreeNode* GetParent();
	TreeNode* GetNext();
	void SetNext(TreeNode* nextnode);

	std::vector<TreeNode*> GetChildren();

private:
	size_t level;
	size_t number;
	Rule * rule;
	TreeNode* parent;
	TreeNode* next;
	std::vector<TreeNode*> children;
};


class Event
{
    public:
        Event();
        virtual ~Event();
        int plugin_sid;
        int plugin_id;
        bool directive_matched;
        bool rule_matched;
        string src_ia; //源IP
        string dst_ia; //目的IP
        int count;
        time_t time;
        int backlog_id;
        IpAddress * SrcIp;
        IpAddress * DstIp;

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

        bool IsTimeout();
        bool MatchEvent(Event event);
        bool DirectiveRootRuleMatchEvent(Event event);
        Rule* GetCurrentRule();
        void SetCurrentRuleNode(TreeNode * node);
        TreeNode * GetCurrentRuleNode();
        void UpdateFirstLastTs(Event event);
        void SetTimeLastCurrentTime(time_t time);
        void UpdateTimeout();
        void SetRuleRefVars(TreeNode * node);
        TreeNode* GetNodeBranchByLevel(TreeNode * node, int level);
        TreeNode* GetRootNode();
        //void SetRootNode(TreeNode * node);
        void SetRootNode(TreeNode* rootnode);
        void SetClearAllMatchData();
        void Clear();
        bool IsDataEmpty();
        void SetEmpty(bool isEmpty);


        void SetMatched(bool matched);
        bool IsMatched();
        int backlog_id;
        int GetBacklogsId();

    public:
        int *a;
        int directive_id;
        string name;
        int priority;
        time_t first_event;
        time_t last_event;

    protected:
        TreeNode* Rootnode;
        TreeNode* CurrentNode;


    private:
        bool matched;
        time_t time_out;
        time_t time_last;
        bool isEmpty;
};

#define RULE_TYPE_PARENT    0
#define RULE_TYPE_CHILD     1
#define RULE_TYPE_BRO       2

class Rule
{
    public:
        Rule();
        virtual ~Rule();
    public:
        bool MatchEvent(Event event);
        void SetEventDataToRule(Event event);
        void SetEventMatchLastTime(time_t time);


    public:
        int GetEventDataSrcPort();
        int GetEventDataDstPort();

    public:
        /* 规则匹配端口 */
        std::map<int, int> mapSrcPort;
        std::map<int, int> mapSrcPortNot;
        std::map<int, int> mapDstPort;
        std::map<int, int> mapDstPortNot;
        std::map<string, int> mapRuleMatchSrcIpNot; //支持深拷贝
        std::map<string, int> mapRuleMatchSrcIp;    //支持深拷贝
        std::map<string, int> mapRuleMatchDstIpNot; //支持深拷贝
        std::map<string, int> mapRuleMatchDstIp;    //支持深拷贝
        //std::map<string, int> mapEventMatchSrcIpNot;//支持深拷贝
        //std::map<string, int> mapEventMatchSrcIp;   //支持深拷贝
        //std::map<string, int> mapEventMatchDstIpNot;//支持深拷贝
        //std::map<string, int> mapEventMatchDstIp;   //支持深拷贝
        // 关联字段引用定义
        std::list<RuleVar*> lstRuleVar;


        void AddRuleMatchSrcPort(int port);
        void AddRuleMatchSrcPortNot(int port);
        void AddRuleMatchDstPort(int port);
        void AddRuleMatchDstPortNot(int port);
        void SetRuleMatchPort(char* portstring, bool is_srcport);



        void SetRuleVarsToList(RuleVar *var);

    public:
        std::map<int, int> mapPluginId;
        std::map<int, int> mapPluginSid;
        void AddPluginId(int pluginId);
        void AddPluginSid(int pluginSid);
        void SetRulePluginId(char* portstring);
        void SetRulePluginSid(char* portstring);

    public:
        void SetRuleIp(char* ipstring, bool is_sourceip);
        void SetSrcHomeNet(bool isEnable);
        void SetDstHomeNet(bool isEnable);
        void SetSrcHomeNetNot(bool isEnable);
        void SetDstHomeNetNot(bool isEnable);
        void SetVarIp(IpAddress *ipaddress, RuleVar * var);
        void SetEventDataSrcIpNot(IpAddress* ipaddress);
        void SetEventDataSrcIp(IpAddress* ipaddress);
        void SetEventDataDstIpNot(IpAddress* ipaddress);
        void SetEventDataDstIp(IpAddress* ipaddress);
        IpAddress * GetEventDataSrcIp();
        IpAddress * GetEventDataSrcNotIp();
        IpAddress * GetEventDataDstIp();
        IpAddress * GetEventDataDstNotIp();
        IpAddress * EventDataSrcIp;
        IpAddress * EventDataDstIp;
        IpAddress * EventDataSrcIpNot;
        IpAddress * EventDataDstIpNot;
    public:
        std::vector<INetwork> vecNetwork;
        std::vector<INetwork> vecNetworknot;
    public:
        bool MatchSrcHost(Event event);
        bool MatchSrcHostNot(Event event);
        bool MatchSrcIp(Event event);
        bool MatchDstIp(Event event);
        bool MatchPlugin_id(Event event);
        bool MatchPlugin_sid(Event event);
        bool MatchEventOccurence(Event event);

    public:
        bool SrcHomeNetEn;
        bool DstHomeNetEn;
        bool SrcHomeNetNotEn;
        bool DstHomeNetNotEn;
    public:
        //保存规则定义字符
        string type;
        string name;
        int reliability;
        int occurrence;
        string from;
        string to;
        string port;
        string port_from;
        string port_to;
        int plugin_id;
        string protocol;
        int mRuleTimeOut;
    public:
        time_t  mEventLastMatchTime;
        int     mEventMatchCount;
    public:
        Rule& operator=(Rule& rule);

};

class BacklogsList
{
    public:
        BacklogsList();
        virtual ~BacklogsList();
        std::list<Backlogs *> lstBacklogs;
};

// Class:   Correlation
// 说明：   关联引擎管理类
class Correlation
{
    public:
        std::list<Backlogs *> lstMatchedBacklogs;
        std::map<int, BacklogsList*> mapBacklogs; /* 建立以plugin_id为Key索引，存储plugin_id的 listbacklogs */

    public:
        Correlation();
        void AddBacklogs(Backlogs* pBacklogs);
        void AddDirective(Backlogs* pBacklogs);
        virtual ~Correlation();
        void DoCorrelation(Event event);
        void MatchBacklogs(Event event);
        void MatchDirective(Event event);
        std::vector<Backlogs*> vecBacklogs;  //Backlogs数据
        std::vector<Backlogs*> vecDirective; //指令数据
    protected:

    private:
        void AddBacklogsMap(Backlogs* pBacklogs);
};





#define SIM_HOME_NET_CONST          "HOME_NET"

#define SIM_WILDCARD_ANY            "ANY"    // Match anything but empty fields.
#define SIM_WILDCARD_ANY_LOWER      "any"
#define SIM_WILDCARD_EMPTY          "EMPTY"  // Match only fields.
#define SIM_SRC_IP_CONST            "SRC_IP"
#define SIM_DST_IP_CONST            "DST_IP"
#define SIM_SRC_PORT_CONST          "SRC_PORT"
#define SIM_DST_PORT_CONST          "DST_PORT"
#define SIM_PROTOCOL_CONST          "PROTOCOL"
#define SIM_PLUGIN_ID_CONST         "PLUGIN_ID"
#define SIM_PLUGIN_SID_CONST        "PLUGIN_SID"
#define SIM_SENSOR_CONST			      "SENSOR"
#define SIM_PRODUCT_CONST			      "PRODUCT"
#define SIM_ENTITY_CONST            "ENTITY"
#define SIM_CATEGORY_CONST		      "CATEGORY"
#define SIM_SUBCATEGORY_CONST		    "SUBCATEGORY"
#define SIM_FILENAME_CONST			    "FILENAME"
#define SIM_USERNAME_CONST			    "USERNAME"
#define SIM_PASSWORD_CONST			    "PASSWORD"
#define SIM_USERDATA1_CONST			    "USERDATA1"
#define SIM_USERDATA2_CONST			    "USERDATA2"
#define SIM_USERDATA3_CONST			    "USERDATA3"
#define SIM_USERDATA4_CONST			    "USERDATA4"
#define SIM_USERDATA5_CONST			    "USERDATA5"
#define SIM_USERDATA6_CONST			    "USERDATA6"
#define SIM_USERDATA7_CONST			    "USERDATA7"
#define SIM_USERDATA8_CONST			    "USERDATA8"
#define SIM_USERDATA9_CONST			    "USERDATA9"

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

int GetOctetsIP(string ip, vector<int> &octetsIP);


/* 特定IP地址 */
class IpAddress {
    public:
        IpAddress();
        IpAddress(vector<int> &octetsIP);
        IpAddress(IpAddress* ipa);
        IpAddress(string ip);
        virtual ~IpAddress();
        vector<int> vecIpNum;
        bool isAnyMatch;
        map<string, int> mapRuleMatchSrcIp; //for test
        string GetIpString();
};

class INetwork {
    public:
        INetwork();
        INetwork(string network);
        INetwork(string networkip, int masknum);
        virtual ~INetwork();
        string  network;
        vector<int> vecIpNum;
        int   masknum;
        bool IsIpMatched(IpAddress ipa);
};

#endif // CORRELATION_H
