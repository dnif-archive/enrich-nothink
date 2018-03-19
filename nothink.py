import requests
import yaml
import os


inteltype = ['INTEL_ADDR']
path = os.environ["WORKDIR"]
with open(path + "/enrichment_plugins/nothink/dnifconfig.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)


def import_ssh_intel():
    try:
        source = cfg['enrichment_plugin']['NOTHINK_IP_SSH_SOURCE']
        response = requests.get(source)
    except Exception, e:
        print 'Api Request Error %s' % e
    try:
        lines = []
        for line in response.iter_lines():
            line = line.strip()
            s = str(line)
            s = s.strip()
            if not s.startswith("#") and s != '':
                tmp_dict = {}
                tmp_dict["EvtType"] = "IPv4"
                tmp_dict["EvtName"] =s
                tmp_dict2 = {}
                tmp_dict2["IntelRef"] = ["NOTHINK"]
                tmp_dict2["IntelRefURL"] = [source]
                b_lst = []
                b_lst.append("SSH blacklist")
                tmp_dict2["ThreatType"] = b_lst
                tmp_dict["AddFields"] = tmp_dict2
                lines.append(tmp_dict)
    except:
        lines = []
    return lines, 'INTEL_ADDR'


def import_snmp_intel():
    try:
        source = cfg['enrichment_plugin']['NOTHINK_IP_SNMP_SOURCE']
        response = requests.get(source)
    except Exception, e:
        print 'Api Request Error %s' % e
    try:
        lines = []
        for line in response.iter_lines():
            line = line.strip()
            s = str(line)
            s = s.strip()
            if not s.startswith("#") and s != '':
                tmp_dict = {}
                tmp_dict["EvtType"] = "IPv4"
                tmp_dict["EvtName"] =s
                tmp_dict2 = {}
                tmp_dict2["IntelRef"] = ["NOTHINK"]
                tmp_dict2["IntelRefURL"] = [source]
                b_lst = []
                b_lst.append("SNMP blacklist")
                tmp_dict2["ThreatType"] = b_lst
                tmp_dict["AddFields"] = tmp_dict2
                lines.append(tmp_dict)
    except:
        lines = []
    return lines, 'INTEL_ADDR'


def import_telnet_intel():
    try:
        source = cfg['enrichment_plugin']['NOTHINK_IP_TELNET_SOURCE']
        response = requests.get(source)
    except Exception, e:
        print 'Api Request Error %s' % e
    try:
        lines = []
        for line in response.iter_lines():
            line = line.strip()
            s = str(line)
            s = s.strip()
            if not s.startswith("#") and s != '':
                tmp_dict = {}
                tmp_dict["EvtType"] = "IPv4"
                tmp_dict["EvtName"] =s
                tmp_dict2 = {}
                tmp_dict2["IntelRef"] = ["NOTHINK"]
                tmp_dict2["IntelRefURL"] = [source]
                b_lst = []
                b_lst.append("Telnet blacklist")
                tmp_dict2["ThreatType"] = b_lst
                tmp_dict["AddFields"] = tmp_dict2
                lines.append(tmp_dict)
    except:
        lines = []
    return lines, 'INTEL_ADDR'
