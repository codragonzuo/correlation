- sim_rule_get_vars

```C++
GList* sim_rule_get_vars (SimRule     *rule)
```

Inside var there is the kind of event (src_ip, protocol, plugin_sid or whatever) and the level to which is
referencing. i.e. if in a directive appears 1:SRC_IP that info is inside the var


从directive中提取vars，保存到当前rule的vars list


sim_xml_directive_set_rule_ips
-> sim_xml_directive_set_rule_ips


 * Updates time and vars in all rules in @node_root children nodes
 * and checks if any rule has type MONITOR

sim_correlation_update_children_nodes
->sim_directive_set_rule_vars


sim_xml_directive_set_rule_generic_text

是否包含!
是否包含:
...


### 遗留问题
1. rule的NOT功能




## 设计需要主要的问题：

1. 规则数据包括：规则匹配数据（多个list或变量），规则引用定义。其中规则匹配数据随着上层事件匹配和规则引用会增加数据。
2. 当前规则的事件匹配数据：如果匹配了事件，把事件的数据保存到规则。
