- sim_rule_get_vars

```C++
GList* sim_rule_get_vars (SimRule     *rule)
```

Inside var there is the kind of event (src_ip, protocol, plugin_sid or whatever) and the level to which is
referencing. i.e. if in a directive appears 1:SRC_IP that info is inside the var


��directive����ȡvars�����浽��ǰrule��vars list


sim_xml_directive_set_rule_ips
-> sim_xml_directive_set_rule_ips


 * Updates time and vars in all rules in @node_root children nodes
 * and checks if any rule has type MONITOR

sim_correlation_update_children_nodes
->sim_directive_set_rule_vars


sim_xml_directive_set_rule_generic_text

�Ƿ����!
�Ƿ����:
...


### ��������
1. rule��NOT����




## �����Ҫ��Ҫ�����⣺

1. �������ݰ���������ƥ�����ݣ����list����������������ö��塣���й���ƥ�����������ϲ��¼�ƥ��͹������û��������ݡ�
2. ��ǰ������¼�ƥ�����ݣ����ƥ�����¼������¼������ݱ��浽����
