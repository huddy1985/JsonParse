import json
import sys
from pprint import pprint

IpsInfoJson = "./ips.rule.json"
MetaJson = "./meta.json"
MetaEnJson = "./meta_en.json"

ruleCatory = {}

def catConv(metaCat):
    if ruleCatory.has_key(str(metaCat)):
        return ruleCatory[str(metaCat)]
    else:
        return metaCat

def mergeIpsRule(ipsRuleJsonFile, metaJsonFile):
    ipsRuleJsonObj = {}
    metaJsonObj = {}

    try:
        with open(ipsRuleJsonFile) as ipsFp:
            ipsRuleJsonObj = json.load(ipsFp)

        with open(metaJsonFile) as metaFp:
            metaJsonObj = json.load(metaFp)
    except IOError as err:
        print('File Error:' + str(err))
        return {}

    listOjb = metaJsonObj['RuleInfo']
    for obj in listOjb:
        ruleID = obj["i_rule_ID"]
        if ipsRuleJsonObj.has_key(str(ruleID)):
            ipsObj = ipsRuleJsonObj[str(ruleID)]
            ipsObj["Affected_OS"] = obj["i_affected_platform"]
            ipsObj["Severity"] = obj["i_severity"]
            ipsObj["Name"] = obj["s_name"]
            ipsObj["Release_Date"] = obj["i_update_date"]
        else:
            ruleTemplate = {}
            tmpobj = {
                "Rule_ID": ruleID,
                "Affected_OS": obj["i_affected_platform"],
                "Severity": obj["i_severity"],
                # have no idea for this default value
                "Enable": 1,
                "Name": obj["s_name"],
                "Release_Date": obj["i_update_date"],
                # have no idea for this value
                "Category": catConv(obj["i_ips_cat_ID"])
            }
            ruleTemplate[str(ruleID)] = tmpobj
            ipsRuleJsonObj.update(ruleTemplate)

    return ipsRuleJsonObj

def preprocessMetaJson(metaJsonObj):
    jsonObjs = metaJsonObj["RuleInfo"]
    processedJsonObjs = {}
    for obj in jsonObjs:
        tmpObj = {}
        tmpObj[str(obj["i_rule_ID"])] = obj
        processedJsonObjs.update(tmpObj)
    return processedJsonObjs

def mergeIpsInfo(ipsInfoJsonFile, metaXJsonFile, metaJsonFile):
    ipsInfoJsonObj = {}
    metaXJsonObj = {}
    metaJsonObj = {}

    try:
        with open(ipsInfoJsonFile) as ipsFp:
            ipsInfoJsonObjOrin = json.load(ipsFp)

        with open(metaXJsonFile) as metaXFp:
            metaXJsonObj = json.load(metaXFp)

        with open(metaJsonFile) as metaFp:
            metaJsonObj = json.load(metaFp)
    except IOError as err:
        print('File Error:' + str(err))
        return {}

    listObj = metaXJsonObj["IPSInfo"]
    ipsInfoJsonObj = ipsInfoJsonObjOrin["IPSRuleConf"]
    ipsInfoJsonCatObj = ipsInfoJsonObjOrin["IPSRuleCate"]
    processedMetaJsonObjs = preprocessMetaJson(metaJsonObj)
    for obj in listObj:
        ruleID = obj["i_rule_ID"]
        if ipsInfoJsonObj.has_key(str(ruleID)):
            ipsObj = ipsInfoJsonObj[str(ruleID)]
            metaObj = processedMetaJsonObjs[str(ruleID)]
            ipsObj["Affected_OS"] = metaObj["i_affected_platform"]
            # ipsObj["Category"] = catConv(metaObj["i_ips_cat_ID"])
            ipsObj["Desc"] = obj["s_description"]
            ipsObj["Desc_Length"] = len(ipsObj["Desc"])
            ipsObj["Impact"] = obj["s_impact"]
            ipsObj["Impact_Length"] = len(ipsObj["Impact"])
            ipsObj["Name"] = obj["s_name"]
            ipsObj["Name_Length"] = len(ipsObj["Name"])
            ipsObj["Recommend"] = obj["s_recommend"]
            ipsObj["Recommend_Length"] = len(ipsObj["Recommend"])
            ipsObj["Reference"] = obj["s_reference"]
            ipsObj["Release_Date"] = metaObj["i_update_date"]
            ipsObj["Severity"] = metaObj["i_severity"]
            # what is RuleInfo_Length ?
            ipsObj["RuleInfo_Length"] = len(ipsObj["Desc"]) \
                                      + len(ipsObj["Impact"])\
                                      + len(ipsObj["Name"]) \
                                      + len(ipsObj["Recommend"]) \
                                      + len(ipsObj["Reference"]) \
                                      + 10

        else:
            metaObj = processedMetaJsonObjs[str(ruleID)]
            # if a new rule id not in the old rule list, how to fix?
            if not ipsInfoJsonCatObj.has_key(str(metaObj["i_ips_cat_ID"])):
                continue
            ipsCatList = ipsInfoJsonCatObj[str(metaObj["i_ips_cat_ID"])]
            ipsCatList.append(ruleID)
            ruleTemplate = {}
            tmpobj = {
                "Affected_OS": metaObj["i_affected_platform"],
                "Category": catConv(metaObj["i_ips_cat_ID"]),
                "Default_Action": -2147483631,
                "Desc": obj["s_description"],
                "Desc_Length": len(obj["s_description"]),
                "Impact": obj["s_impact"],
                "Impact_Length": len(obj["s_impact"]),
                "Name": obj["s_name"],
                "Name_Length": len(obj["s_name"]),
                "Recommend": obj["s_recommend"],
                "Recommend_Length": len(obj["s_recommend"]),
                "Reference": obj["s_reference"],
                "Release_Date": metaObj["i_update_date"],
                "Rule_ID": ruleID,
                "Severity": metaObj["i_severity"],
                "RuleInfo_Length": len(ipsObj["Desc"]) \
                                      + len(ipsObj["Impact"])\
                                      + len(ipsObj["Name"]) \
                                      + len(ipsObj["Recommend"]) \
                                      + len(ipsObj["Reference"]) \
                                      + 10,
            }
            ruleTemplate[str(ruleID)] = tmpobj
            ipsInfoJsonObj.update(ruleTemplate)

    return ipsInfoJsonObjOrin

if __name__ == "__main__":
    ipsRuleJson_obj = mergeIpsInfo("./ips.jp.info.json", "./meta_ja.json", "./meta.json")

    with open("./new.jp.json","w+") as infojson:
        infojson.write(json.dumps(ipsRuleJson_obj))

    print "merge finish"