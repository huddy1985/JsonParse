import json
from pprint import pprint

IpsInfoJson = "./ips.rule.json"
MetaJson = "./meta.json"
MetaEnJson = "./meta_en.json"

ipsRuleJson_obj = {}
metaJson_obj = {}

ruleTemplate = {}
tmpobj = {}

if __name__ == "__main__":
    global ipsRuleJson_obj
    global metaJson_obj
    newJson = {}

    with open(MetaJson, "r") as json_fp:
        metaJson_obj = json.load(json_fp)

    with open(IpsInfoJson, 'r') as json_fp:
        ipsRuleJson_obj = json.load(json_fp)

    for ruleid in ipsRuleJson_obj.keys():
        if ruleid == u'new':
            continue
        hasFine = False
        for item in metaJson_obj["RuleInfo"]:
            if long(item["i_rule_ID"]) == long(ruleid):
                hasFine = True
                ipsRuleJson_obj[ruleid]["Affected_OS"] = item["i_affected_platform"]
                ipsRuleJson_obj[ruleid]["Severity"] = item["i_severity"]
                ipsRuleJson_obj[ruleid]["Category"] = item["i_ips_cat_ID"]
                ipsRuleJson_obj[ruleid]["Name"] = item["s_name"]
                ipsRuleJson_obj[ruleid]["Release_Date"] = item["i_update_date"]
                tmpobj[ruleid] = dict(ipsRuleJson_obj[ruleid])
                ruleTemplate = dict(ruleTemplate.items() + tmpobj.items())

    print "ruletemplate"
    with open("D:\\source\\remote\\JsonParse\\new.json", "w+") as newjson:
        newjson.write(ruleTemplate)

    print "merge finish"