import json
from pprint import pprint

IpsInfoJson = "./ips.info.json"

class JSONObject:
    def __init__(self, d):
        self.__dict__ = d

if __name__ == "__main__":
    print IpsInfoJson
    with open(IpsInfoJson, 'r') as json_fp:
        data = json.load(json_fp)
        print data["IPSRuleCate"]
        for item in data.items():
            print item