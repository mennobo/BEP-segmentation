#!/usr/bin/env python
# coding: utf-8

# In[1]:


from netaddr import *
import json
import pandas as pd
import numpy as np
from datetime import datetime
# import maxminddb
import time
import matplotlib.pyplot as plt
import dateutil.parser as dp
# import matplotlib.patches as patches
import sys
# import gzip
import math
from difflib import SequenceMatcher
# from scipy import spatial
from collections import Counter
from ast import literal_eval
from subprocess import check_output
# from publicsuffix import PublicSuffixList
# from publicsuffix import fetch
import ipdb
import random
_CACHE = {}


# In[28]:


pdns_2018_9_10 = pdns_2018_9_10.drop(['ip'], axis=1)
pdns_2018_9_10.to_csv('serverius_2018_09_10_notype.csv', index=False)


# In[56]:


def evalstr(x):
    if pd.isnull(x):
        return np.nan
    else:
        return literal_eval(x)
    
parse_dates = ['fromtime', 'totime']
pdns_2018_9_10 = pd.read_csv('serverius_2018_09_10_notype.csv', parse_dates=parse_dates,  dtype={"ip": object, "domain": object,
                                                                                                "Type": object, "count": int,"isp": object,
                                                                                                "is_hosting_provider": object,
                                                                                                "is_public_proxy": object, "ip_int": int,
                                                                                                "is_ns": object, "dhe": bool,
                                                                                                "domains_ass":object, "ns_ass": object, 
                                                                                                 "age": float, "ttl": float})
pdns_2018_9_10['ip'] = pdns_2018_9_10['ip_int'].apply(lambda x: IPAddress(x))
pdns_2018_9_10['ns_ass'] = pdns_2018_9_10.ns_ass.apply(lambda x: evalstr(x))
# pdns_2018_9_10['doains_ass'] = pdns_2018_9_10.domains_ass.apply(lambda x: evalstr(x))
# pdns_2018_9_10['age'] = pdns_2018_9_10.apply(getAge, axis = 1 )
# pdns_2018_9_10['tld'] = pdns_2018_9_10.apply(checknantld, axis = 1)
# pdns_2018_9_10['2ld'] = pdns_2018_9_10.apply(checknan2ld, axis = 1)
pdns_2018_9_10.index = pdns_2018_9_10.ip_int
pdns_2018_9_10 = pdns_2018_9_10.sort_index()
pdns_no_dates_count = pdns_2018_9_10.drop(['fromtime', 'count', 'totime', 'dhe'], axis = 1)

with open('./merged_net_list.csv', 'r')as f:
    readlist = (f.read()).split(';')
    readlist = readlist[0:-1]
    merged_net_list = [IPNetwork(x) for x in readlist]
    print(merged_net_list)
    
net_dic = {}
counter = 0
for i in range(0, len(merged_net_list)):
    value = pdns_no_dates_count.loc[(pdns_no_dates_count['ip'] <= merged_net_list[i][-1]) & (pdns_no_dates_count['ip'] >= merged_net_list[i][0])]
    if len(value) > 20:
        key = 'block' + str(counter)
        print(('net: {0}, entries: {1}, {2}').format(merged_net_list[i], len(value), key))
#         value = value.reset_index()
        net_dic[key] = value
        counter += 1
if not isinstance((net_dic['block0'].iloc[1,:].ns_ass), list):
    print('[parse error]')


# In[3]:


with open('serverius-mnt.json') as json_file: 
    data = json.load(json_file)
    raw_net_list = []
    for p in data['objects']['object']:
#         print(p['type'])
        if p['type'] == 'inetnum':
            ip_range = p['attributes']['attribute'][0]['value'].split(' - ')
            ip_net = iprange_to_cidrs(ip_range[0], ip_range[1])
            raw_net_list.extend(ip_net)
unmerged_total = 0
for network in raw_net_list:
    unmerged_total += len(network)
merged_net_list = cidr_merge(raw_net_list)
merged_total = 0
for network in merged_net_list:
    merged_total += len(network)
merged_net_list
with open('./merged_net_list.csv', 'w+')as f:
    for net in merged_net_list:
        line = str(net) + ';'
        print(line)
        f.write(line)


# In[4]:


def equal_el(el1, el2):
    if not isinstance(el1, list):
        el1 = [el1]
    if not isinstance(el2, list):
        el2 = [el2]
    return not set(el1).isdisjoint(el2)


# In[5]:


def combine_categories(propnew, propold):
    #if there is no or a single element return that element
    if isinstance(propnew, type(np.nan)):
        if isinstance(propold, type(np.nan)):
            return np.nan
        else:
            return propold
    if isinstance(propold, type(np.nan)):
            return propnew
    #add both elements to list if they are not in a list already
    if not isinstance(propnew, list):
        propnew = [propnew]
    if not isinstance(propold, list):
        propold = [propold]
    return propnew + propold

def combine_bool(new, old):
    if isinstance(old, list):
        return old
    elif isinstance(new, list):
        return new
    elif old == new:
        return old
    else:
        return [old, new]

def combine_numerical(new, old):
    if pd.isnull(new):
        if pd.isnull(old):
            return np.nan
        else:
            return old
    elif pd.isnull(old):
        return new
    else:
        return (new + old) / 2

def calc_tld(net):
    if not isinstance(net.tld, list):
        net[str(net.tld)] = 1
        return net
    tld_occurrences = Counter(net.tld)
#     print(tld_occurrences)
    for key in tld_occurrences:
        value = tld_occurrences[key]
        net[str(key)] = float(value/len(net.tld))
    return net


def setify(item):
    if (not isinstance(item, float)) and (not isinstance(item, str)):
        item = set(item)
        return [x for x in item]
    else:
        return item

def combine_networks(netnew, netold, rand = False):
    if rand:
        if netnew.ip != netold.ip:
            if pd.notnull(netold.last_ip):
                netnew.last_ip = netold.last_ip
            else:
                netnew.last_ip = netold.ip
        return netnew
    #'domain', 'isp', 'is_hosting_provider', 'is_public_proxy', 'ip_int', 'is_ns', 'domains_ass', 'ns_ass', 'age', 'tld', '2ld', 'ttl', 'smtp','ip'
    netnew.domain = combine_categories(netnew.domain, netold.domain)
    netnew.domain = setify(netnew.domain)
    netnew.ns_ass = combine_categories(netnew.ns_ass, netold.ns_ass)
    netnew.ns_ass = setify(netnew.ns_ass)
    
    netnew.is_ns = combine_categories(netnew.is_ns, netold.is_ns)
    netnew.is_ns = setify(netnew.is_ns)
    netnew.domains_ass = combine_categories(netnew.domains_ass, netold.domains_ass)
    netnew.domains_ass = setify(netnew.domains_ass)
    
    netnew.tld = combine_categories(netnew.tld, netold.tld)
    netnew = calc_tld(netnew)
    
    secondld = (combine_categories(netnew['2ld'], netold['2ld']))
    netnew['2ld'] = setify(secondld)
        
    netnew.ttl = combine_numerical(netnew.ttl, netold.ttl)
    netnew.age = combine_numerical(netnew.age, netold.age)
    
    if netnew.isp != netold.isp:
        netnew.isp = [netnew.isp, netold.isp]
    netnew.is_public_proxy = combine_bool(netnew.is_public_proxy, netold.is_public_proxy)
    netnew.is_hosting_provider = combine_bool(netnew.is_hosting_provider, netold.is_hosting_provider)
    netnew.smtp = combine_bool(netnew.smtp, netold.smtp)
    
    if netnew.ip != netold.ip:
#         print('netnewip: ' + str(netnew.ip) + ', netoldip: ' + str(netold.ip))
        if pd.notnull(netold.last_ip):
            netnew.last_ip = netold.last_ip
        else:
            netnew.last_ip = netold.ip
#     print(str(netnew.ip) + ' lastIP: ' + str(netnew.last_ip))
    return netnew


# In[6]:


def merge_network(network, itemnumber):
    start = time.time()
    result = {}
    _UNIQUE_TLD = [str(x) for x in network.tld.unique()]
    if 'nan' in _UNIQUE_TLD:
        _UNIQUE_TLD.remove('nan')

    counter = 0
    for index, row in network.iterrows():
        #for the first row, 
        if counter <= 0:
            prev_entry = row.copy()
            prev_ip = prev_entry.ip_int
            result[prev_ip] = prev_entry
            if isinstance(prev_entry.tld, str):
                result[prev_ip][str(prev_entry.tld)] = 1
            counter += 1
            continue
        new_entry = row.copy()
        new_ip = new_entry.ip_int
        if prev_ip == new_ip:
            prev_entry = combine_networks(prev_entry, new_entry)
            result[prev_ip] = prev_entry
        else:
            result[new_ip] = new_entry
            if isinstance(new_entry.tld, str):
                result[new_ip][str(new_entry.tld)] = 1
            prev_entry = new_entry
            prev_ip = new_ip
    ans = pd.DataFrame(result).T 
    ans[_UNIQUE_TLD] = ans[_UNIQUE_TLD].fillna(0)
    print(('Block: {0}, time taken: {1}').format(itemnumber, time.time() - start))
    return ans 

def initialize_dist(dataframe, threshold, _FACTORS, itemnumber, add_null):
    start = time.time()
    ans = dataframe.copy()
    remove = {'2ld', 'age','domain', 'domains_ass',
       'ip', 'ip_int', 'is_hosting_provider', 'is_ns', 'is_public_proxy',
       'isp', 'nan', 'ns_ass', 'smtp', 'tld', 'ttl', 'distance'}
    _UNIQUE_TLD = [e for e in ans.columns if e not in remove]
    ans = ans.reset_index()
    ttl_min = ans.ttl.min()
    ttl_max = ans.ttl.max()
    age_min = ans.age.min()
    age_max = ans.age.max()
    for index, row in ans.iterrows():
        if index <= ans.index[0]:
            continue
        elif index == ans.index[-1]:
            break
        else:
            ans.at[index - 1, 'distance'] = calculate_distance(ans.loc[index -1,:].copy(), row.copy(),
                                                               _UNIQUE_TLD, threshold, _FACTORS,
                                                              ttl_min, ttl_max, age_min, age_max, add_null)
    ans.index = ans.ip_int
#     print(('Block: {0} distances initialized, time taken: {1}').format(itemnumber, time.time() - start))
    return ans


# In[ ]:


_FACTORS = {"domain": 0, "ns_ass": 1, "tld": 0, "2ld": 0, "ttl": 0, "age":0}
test = merge_network(net_dic['block2'], 2, 0, _FACTORS)
test2 = initialize_dist(test, threshold = 0, _FACTORS = _FACTORS, itemnumber= 2)


# In[114]:


info = pdns_no_dates_count.drop(['smtp', 'is_ns', 'domains_ass', 'ip_int', 'domain'], axis=1)
info.info()


# In[98]:


def is_nan(el):
    if isinstance(el, list):
        return False
    else:
        return pd.isnull(el)
    
#Compare sequences based on an adaptation of the Ratcliff-Obershelp algorithm
def compare_word_list(element1, element2, threshold, nullans):
    if isinstance(element1, list):
        True
    elif isinstance(element1, str):
        element1 = [element1]
    else:
        return nullans
    if isinstance(element2, list):
        True
    elif isinstance(element2, str):
        element2 = [element2]
    else:
        return nullans
        
    set_b = {el for el in element1}
    set_a = {el for el in element2}
    common = set_a.intersection(set_b)
    if common:
        return 0.0
    
    element_a = list(set_a)
    element_b = list(set_b)
    
    i = len(element_a)
    j = len(element_b)
    if i >= 500 or j >= 500:
        print(i)
        print(j)
    matrix = np.empty((i,j,))
    matrix[:] = np.nan
    for row in range(0, i):
        for col in range(0,j):
            if element_a[row] == element_b[col]:
                matrix[row][col] = 0.0
                continue
            if not np.isnan(matrix[row][col]):
                continue
            match = 1 - SequenceMatcher(None, element_a[row], element_b[col]).ratio()
            if match <= threshold:
#                 print(('el1: {0}, el2: {1}, dist: {2}').format(element_a[row], element_b[col], match))
                return match
            else:                                        
                matrix[row][col] = match
    return matrix.min()

def tld_dist(ip1, ip2, _UNIQUE_TLD, nullans):
    total = 0
    divider = 0    
    for element in ip1[_UNIQUE_TLD].index:
        el1 = ip1[element]
        el2 = ip2[element]
        if el1 == 0 and el2 == 0:
            continue
        else:
            divider += 1
            total += math.fabs(el1 - el2)
    if divider == 0:
        return nullans
    else:
        return (total / divider)
    
def numeric_dist(att1, att2, mini, maxi, nullans):
    if pd.isnull(att1) or pd.isnull(att2):
        return nullans
    else:
        att1 = att1 /( maxi - mini)
        att2 = att2 /( maxi - mini)
    return (math.fabs(att1 - att2))

def calculate_distance(ip1, ip2, _UNIQUE_TLD, threshold, _FACTORS, ttl_min, ttl_max, age_min, age_max, add_null):
    #'domain', 'isp', 'is_hosting_provider', 'is_public_proxy', 'ip_int', 'is_ns', 'domains_ass', 
    #'ns_ass', 'age', 'tld', '2ld', 'ttl', 'smtp','ip'
    if add_null:
        nullans = 0.0
    else:
        nullans = math.inf
    #dont add if one of the 2 is a nameserver, by increasing distance to infinity
    if is_nan(ip1.domain) or is_nan(ip2.domain):
        return nullans
    
    distances = {"domain": np.nan, "ns_ass":np.nan, "tld":np.nan, "2ld":np.nan, "ttl":np.nan, "age":np.nan}
    if _FACTORS['domain'] != 0:
        distances["domain"] = compare_word_list(ip1.domain, ip2.domain, threshold, nullans)
    
    if _FACTORS['ns_ass'] != 0:
        distances["ns_ass"] = compare_word_list(ip1.ns_ass, ip2.ns_ass, threshold, nullans)
        
    if _FACTORS['tld'] != 0:
        distances["tld"] = tld_dist(ip1, ip2, _UNIQUE_TLD, nullans)
        
    if _FACTORS['2ld'] != 0:
        distances["2ld"] = compare_word_list(ip1['2ld'], ip2['2ld'], threshold, nullans)
        
    if _FACTORS['ttl'] != 0:
        distances["ttl"] = numeric_dist(ip1.ttl, ip2.ttl, ttl_min, ttl_max, nullans)
        
    if _FACTORS['age'] != 0:
        distances["age"] = numeric_dist(ip1.age, ip2.age, age_min, age_max, nullans)
        
    if all(pd.isnull(value) for value in distances.values()):
        return nullans
    
    #add weights to distances
    final_distance = 0
    divider = 0
    for k in distances:
        v = distances[k]
        if pd.notnull(v):
            final_distance += v * _FACTORS[k]
            divider += _FACTORS[k]
    return final_distance / divider


# In[87]:


def cluster(df, threshold, clusters, _FACTORS, min_dist, add_null, rand = False):
    frame = df.copy()
    frame['last_ip'] = np.nan
    frame = frame.reset_index(drop = True)
    
    remove = {'2ld', 'age','domain', 'domains_ass',
       'ip', 'ip_int', 'is_hosting_provider', 'is_ns', 'is_public_proxy',
       'isp', 'nan', 'ns_ass', 'smtp', 'tld', 'ttl', 'distance', 'index'}
    _UNIQUE_TLD = [e for e in df.columns if e not in remove]
    
    n = len(frame)
    
    if rand:
        frame = frame[['distance', 'ip']]
        for index in range(len(frame)):
            while frame.loc[index,'distance'] <= min_dist:
                frame.at[index, 'distance'] = frame.loc[index + 1,'distance']
                frame.at[index, 'last_ip'] = frame.loc[index + 1].ip
                index += 1     
    else:
        while n > clusters and frame.distance.min() <= min_dist:
            ttl_min = frame.ttl.min()
            ttl_max = frame.ttl.max()
            age_min = frame.age.min()
            age_max = frame.age.max()
            index = frame.distance.idxmin()
            min_row = frame.loc[index,:].copy()
            next_row = frame.loc[index + 1,:].copy()

            new_el = combine_networks(min_row, next_row)
            
            try:
                frame.at[index] = new_el
            except:
                for i in frame.columns:
                    try:
                        frame.at[index, i] = new_el[i]
                    except:
                        print(frame[i])
                        print(new_el[i])
                        frame[index, i] = frame[index,i].astype(object)
                        frame.at[index,i] = new_el[i]
                
                
            if index == len(frame) - 2:
                frame.at[index, 'distance'] = math.inf
            else:
                next_next_row = frame.loc[index + 2,:].copy()
                frame.at[index, 'distance'] = calculate_distance(min_row, next_next_row, _UNIQUE_TLD,
                                                                 threshold, _FACTORS, ttl_min, ttl_max, age_min, age_max, add_null)
            if index != 0:
                prev_row = frame.loc[index - 1,:].copy()
                frame.at[index - 1,'distance'] = calculate_distance(prev_row, min_row, _UNIQUE_TLD,
                                                                    threshold, _FACTORS, ttl_min, ttl_max, age_min, age_max, add_null )

            frame = frame.drop(index + 1)
            frame = frame.reset_index(drop = True)
            n -= 1
    return frame


# In[88]:


def get_validation(raw_net_list):
    printlist = '5.178.64.0/21, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24,  91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 93.158.200.0/21, 93.158.208.0/20, 178.21.16.0/21, 185.8.176.0/22, 185.12.12.0/22, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.247.30.0/23, 194.247.38.0/24'
    printlist = printlist.split(', ')
    check_list = {IPNetwork(x):[] for x in printlist}
    subnet_list = sorted(raw_net_list)
    for index in range(0, len(subnet_list) -2):
        net1 = IPNetwork(subnet_list[index])
        net2 = IPNetwork(subnet_list[index + 1])
        if index == len(subnet_list) - 2:
            net1 = net2
        if net1[-1] > net2[0]:
            continue
        else:
            for checknet in check_list:
                if net1 in checknet:
                    check_list[checknet].append(IPNetwork(net1))
    return check_list

def cal_error(clustering, expected):
    my_net = []
    total_net_length = 0
    nets_amount = 0
    for i, row in clustering.iterrows():
        if pd.notnull(row.last_ip):
            my_net.append((IPAddress(row.ip), IPAddress(row.last_ip)))
            nets_amount += 1
            nets_found = iprange_to_cidrs(IPAddress(row.ip), IPAddress(row.last_ip))
            for net in nets_found:
                total_net_length += len(net)            
    
    misallocation = 0
    for expected_net in expected:
        expected1 = expected_net[0]
        expected2 = expected_net[-1]
        for actualnet in my_net:
            actual1 = actualnet[0]
            actual2 = actualnet[-1]
            if expected1 > actual1 and expected1 < actual2:
                misallocation += 1
            elif expected2 > actual1 and expected2 < actual2:
                misallocation += 1
    average_per_net = 0
    if nets_amount != 0:
        average_per_net = (total_net_length / nets_amount)
    return [total_net_length, misallocation, average_per_net]

def read_exp(filename):
    with open('./' + filename, 'r')as f:
        ans = []
        start = 0
        for line in f:
#             print(line)
            line = line.replace(',', '.')
            design = line.split(';')[0:9]
            if start < 2: 
                start += 1
                continue  
            if not design[0]: break
#             print(design)
            ans.append([float(x) for x in design])
    return ans

def get_expected_coverage(expected):
    expected = sorted(expected)
    result = 0
    counter = 0
    for counter in range(0, len(expected) - 1):
        net1 = expected[counter]
        nextnet = expected[counter + 1]
        if net1[0] <= nextnet [0] and net1[-1] <= nextnet[-1]:
            result += len(net1)
    return result

def run_tests(network, block_nr, dictionary, exp_filename, _EXP_TOGO, _RESULTS):
    
    exp_design = read_exp(exp_filename)
    _EXP_TOGO = exp_design
    if not network in _CACHE:
        merged_block = merge_network(network = dictionary['block' + str(block_nr)], itemnumber= block_nr)
        _CACHE[network] = merged_block
    else:
        print(str(network) + ' in cache!')
        merged_block = _CACHE[network]
    merged_block = merged_block[pd.notnull(merged_block.domain)]   
    val_set = get_validation(raw_net_list)
    expected = val_set[IPNetwork(network)]
    total_net_length = len(IPNetwork(network))
    
    results = []
    for exp in exp_design:
        _EXP_TOGO = _EXP_TOGO[1:]
        start = time.time()
        
        #read out design
        exp_num = exp[0]
        threshold = exp[1]
        min_dist = exp[2]
        add_null = exp[3]
        _FACTORS = {"domain": 0, "ns_ass": exp[4], "tld": exp[5], "2ld": exp[6], "ttl": exp[7], "age":exp[8]}
        
        #initialize block
        distance_block = initialize_dist(dataframe= merged_block, threshold = threshold,
                                         _FACTORS = _FACTORS, itemnumber= block_nr, add_null = add_null)
        
        #cluster block
        clustering = cluster(df= distance_block, threshold = threshold,
                             clusters= 1 ,_FACTORS= _FACTORS, min_dist= min_dist, add_null= add_null)
        
        #calc metrics
        metric = cal_error(clustering, expected)
        print(exp)
        print('Experiment: ' + str(int(exp_num)) + ', Missallocated: ' + str(metric[1])
               + ', coverage of net: ' + str(metric[0] / total_net_length)
              + ', average IP per net: ' + str(metric[2]) + ', time taken: '
              + str(time.time() - start))
        _RESULTS.append([exp_num, metric[0], metric[1], metric[2]])
        if int(exp_num + 1) % 500 == 0:
            write_output(_RESULTS, 'results_' + str(network) + '_' + str(exp_num))
            del(_RESULTS)
    return _RESULTS    


# In[99]:


_RESULTS = []
_EXP_TOGO = []
exp1 = run_tests('93.158.208.0/20', 12, net_dic, 'Experimenteel_ontwerp.csv', _EXP_TOGO, _RESULTS)


# In[11]:


def write_output(out_list, filename):
    with open('./' + str(filename) + '.csv', 'w+')as f:
        for i in out_list:
            line = str(i[0]) + '; ' + str(i[1]) + ';' + str(i[2]) + ';' + str(i[3]) + '\n'
            print(line)
            f.write(line)


# In[84]:


write_output(_RESULTS, 'results')


# In[93]:


design = []
count = 0
for b in range(4, 9, 4):
    for c in range(0, 2):
        for d in range(0, 11, 5):
            for e in range(0, 11,5):
                for f in range(0, 11,5):
                    for g in range(0, 11,5):
                        for h in range(0, 11,5):
                            design.append([0.1,b/10,c/10,d/10,e/10,f/10,g/10,h/10])
                            print(design[count])
                            count += 1


# In[ ]:





# In[94]:


len(design)


# In[69]:


#0.3, 0.4, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0
exp_num = 0
threshold = 0
min_dist = 1
add_null = 0
_FACTORS = {"domain": 0, "ns_ass": 0, "tld": 1, "2ld": 0,
            "ttl": 0, "age": 1}


distance_block = initialize_dist(dataframe= _CACHE['93.158.208.0/20'], threshold = threshold,
                                         _FACTORS = _FACTORS, itemnumber= 12, add_null = add_null)     

#cluster block
clustering = cluster(df= distance_block, threshold = threshold,
                     clusters= 1 ,_FACTORS= _FACTORS, min_dist= min_dist, add_null= add_null)

#calc metrics
val_set = get_validation(raw_net_list)
actual = val_set[IPNetwork('93.158.208.0/20')]
metric = cal_error(clustering, actua
print('Experiment: ' + str(int(exp_num)) + ', IP_per_net: ' + str(metric[0]) +
              ', Missallocated: ' + str(metric[1]) + ', score: ' + str(math.fabs(metric[0] - 66) + (metric[1])))


# In[237]:


#generate random clusterings
distance_block = _CACHE['46.249.32.0/19']
val_set = get_validation(raw_net_list)
actual = val_set[IPNetwork('46.249.32.0/19')]

threshold_range = [0, 0.1, 0.3]
min_dist_range = [0, 0.4, 0.8]
add_null_range = [0,1]

#cluster block
start = time.time()
for c in add_null_range:
    for b in min_dist_range:
        average_ip_net = 0
        average_misall = 0
        for i in range(150):
            distance_block['distance'] = np.random.randint(0, 101, distance_block.shape[0])
            distance_block['distance'] = distance_block['distance'].apply(lambda x: x/100)
            distance_block.at[len(distance_block) - 1, 'distance'] = math.inf
            clustering = cluster(df= distance_block, threshold = a,
                clusters= 1 ,_FACTORS= _FACTORS, min_dist= b, add_null= c, rand = True)

            #calc metrics
            metric = cal_error(clustering, actual)
#                 print('Experiment: ' + str(int(exp_num)) + ', IP_per_net: ' + str(metric[0]) +
#                               ', Mis sallocated: ' + str(metric[1]) + ', score: ' + str(math.fabs(metric[0] - 66) + (metric[1])))
            average_ip_net += metric[0]
            average_misall += metric[1]
            if i % 25 == 0:
                print('At:', str(i), 'time: ', str(time.time() - start)) 
                start = time.time()
        print('min_dist: ', str(b), ', add_null: ', str(c), ' ip_per_net: ', str(average_ip_net/50),
              ', misallocated: ', str(average_misall/50))


# In[27]:


val_set = get_validation(raw_net_list)
actual = val_set[IPNetwork('46.249.32.0/19')]
expected = sorted(actual)
my_net = []
total_net_length = 0
nets_amount = 0
for i, row in clustering.iterrows():
    if pd.notnull(row.last_ip):
        my_net.append((IPAddress(row.ip), IPAddress(row.last_ip)))
        nets_amount += 1
        nets_found = iprange_to_cidrs(IPAddress(row.ip), IPAddress(row.last_ip))
        for net in nets_found:
            total_net_length += len(net)            

misallocation = 0
for expected_net in expected:
    expected1 = expected_net[0]
    expected2 = expected_net[-1]
    for actualnet in my_net:
        actual1 = actualnet[0]
        actual2 = actualnet[-1]
        if expected1 > actual1 and expected1 < actual2:
            print('1', str(expected1), ' is between ', str(actual1), ' and ', str(actual2))
            misallocation += 1
        if expected2 > actual1 and expected2 < actual2:
            print('2', str(expected2), ' is between ', str(actual1), ' and ', str(actual2))
            misallocation += 1
print(misallocation)


# In[78]:


test1 = get_validation(raw_net_list)
for net in printlist:
    
    expected = test1[IPNetwork('46.249.32.0/19')]
    for net in expected:
        if net[0] in net_dic['block2'].ip:
            print(net)
        if net[-1] in net_dic['block2'].ip:
            print(net)
print(net_dic['block12'].ip)


# In[57]:


actual = [(0, 5), (0, 10), (5, 10)]
my_net = [(1,2), (3, 6), (7, 9), (9, 16)]
for network in actual:
    check1 = network[0]
    check2 = network[-1]
    for tup in my_net:
        print('explower: ' + str(int(check1)) + ', expupper: ' + str(int(check2)) + ', actlower: ' 
              + str(int(tup[0])) + ', actupper: ' + str(int(tup[1])))
        if check1 < tup[0] and (check2 > tup[0] and check2 < tup[1]):
            print('error1 first')
            error1 += 1
        elif (check1 > tup[0] and check1 < tup[1]) and check2 > tup[1]:
            print('error1 second')
            error1 += 1
print(error1)
print(error)


# In[38]:


#ttl gemiddelde per netwerk
printlist = '5.178.64.0/21, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24,  91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 93.158.200.0/21, 93.158.208.0/20, 178.21.16.0/21, 185.8.176.0/22, 185.12.12.0/22, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.247.30.0/23, 194.247.38.0/24'
printlist = printlist.split(', ')
ttl = []
for item in net_dic:
    test = net_dic[item].ttl.mean()
    print(test)
    ttl.append(float(test))
plt.bar(printlist, ttl)
plt.xticks(rotation=90)
plt.grid(b=True)
# plt.tight_layout()
plt.xlabel('IP-netwerken')
plt.ylabel('Gemiddelde ttl [s]')
plt.savefig('ttl_bar.png', bbox_inches = "tight")


# In[35]:


net_dic['block7'][pd.notnull(net_dic['block7'].ttl)]


# In[670]:



merged_dic = {}
for i, item in enumerate(net_dic):
    merged_dic[item] = merge_network(net_dic[item], i, 0.8)


# In[686]:





# In[ ]:


printlist = '5.178.64.0/21, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24,  91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 93.158.200.0/21, 93.158.208.0/20, 178.21.16.0/21, 185.8.176.0/22, 185.12.12.0/22, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.247.30.0/23, 194.247.38.0/24'
printlist = printlist.split(', ')
printlist = [IPNetwork(x) for x in printlist]
print(printlist)
counter = 0
res = []
for i in printlist:
    lookup = 'block' + str(counter)
#     prinlookupup)
    print(int(merged_dic[lookup].ttl.mean()))
    counter += 1


# In[240]:


def tld_dist(ip1, ip2):
    total = 0
    for count in range(0, len(ip1)):
        total += math.fabs(ip1[count] - ip2[count]) #/1 max = 1 min = 0 max-min
        print(('ip1: {0}, ip2: {1}, total: {2}').format(ip1[count], ip2[count], total))
    logans = 1 - ((1/len(ip1)) * total)
    print(logans)
    if logans == 0:
        return 1.0
    return - math.log(logans, 10)
# tld_dist([0.1, 0.5, 0.8], [0.3, 0.14, 0.9])
tld_dist([1, 0.512098], [0.22388, 1])


# In[231]:


pdns_2018_9_10.index


# In[500]:


def combine_ip(new, old):
    ip_add = type(IPAddress('0.0.0.0'))
    ip_net = type(IPNetwork('0.0.0.0/21'))
    if isinstance(new, str):
        new = IPAddress(new)
    if isinstance(old, str):
        old = IPAddress(old)
        
    if isinstance(new, list):
        new = sorted(new)[0]
    if isinstance(old, list):
        new = sorted(old)[-1]
        
    if isinstance(new, ip_add):
        if isinstance(old, ip_add):
            return iprange_to_cidrs(new, old)
        elif isinstance(old, ip_net):
            return iprange_to_cidrs(new, old[-1])
        else:
            print('weird ip type3, new: ' + str(new) + ', old:' + str(old) )
    elif isinstance(new, ip_net):
        if isinstance(old, ip_add):
            return iprange_to_cidrs(new[0], old)
        elif isinstance(old, ip_net):
            return iprange_to_cidrs(new[0], old[-1])
        else:
            print('weird ip type2, new: ' + str(new) + ', old:' + str(old) )
    else:
        print('weird ip type1, new: ' + str(new) + ', old:' + str(old) ) 
combine_ip([IPNetwork('0.0.0.0/15'), IPNetwork('0.3.0.0/24'), IPNetwork('12.2.0.0/16')], '44.0.0.0')


# In[84]:


printlist = '5.178.64.0/21, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24,  91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 93.158.200.0/21, 93.158.208.0/20, 178.21.16.0/21, 185.8.176.0/22, 185.12.12.0/22, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.247.30.0/23, 194.247.38.0/24'
printlist = printlist.split(', ')
check_list = {IPNetwork(x):0 for x in printlist}
ans = 0
for network in raw_net_list:
    address = IPNetwork(network)[0]
    for checknet in check_list:
        if address in checknet:
            if IPNetwork(network)[-1] == IPNetwork(checknet)[-1]:
                continue
            else:
#                 print(str(address) + ' in ' + str(checknet) + ' len: ' + str(len(network)) + ' old len: ' + str(check_list[checknet]))
                check_list[checknet] += len(network)
#     if address in IPNetwork('46.249.32.0/19'):
#         print('first: ' + str(network[0]))
#         print('last: ' + str(network[-1]))
#         print('length: ' + str(len(network)))
#         ans += len(network)
# print(ans)       
for i in check_list:
    print(check_list[i])
#     print('net: ' + str(i) + ' len: ' + str(check_list[i]))


# In[30]:


len(pdns_2018_9_10[pd.notnull(pdns_2018_9_10.ttl)])


# In[496]:


#   for index, row in test.iterrows():
#         print(test.loc[index, :])
#       ifor_val = something
#       if <condition>:
#         ifor_val = something_else
#       df.at[i,'ifor'] = ifor_val


# In[24]:



from publicsuffix import PublicSuffixList
from publicsuffix import fetch
psl_file = fetch()
psl = PublicSuffixList(psl_file)



# net_dic['block12'].tld = net_dic['block12'].domain.apply


# In[81]:


info2 = info_merge[[ 'domain', 'ns_ass', 'age', 'tld', '2ld', 'ttl', 'ip']]
info2 = info2.reset_index(drop=True)
info2.info()


# In[73]:


info = net_dic['block12'][pd.notnull(net_dic['block12'].domain)]
info = info.drop(['smtp', 'isp', 'is_hosting_provider', 'is_public_proxy', 'is_ns' ,'domains_ass', 'ip_int'], axis=1)
info = info.reset_index(drop=True)
info.info()


# In[85]:


#verdeling subnetwerken per netwerk
printlist = '5.178.64.0/21, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24,  91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 93.158.200.0/21, 93.158.208.0/20, 178.21.16.0/21, 185.8.176.0/22, 185.12.12.0/22, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.247.30.0/23, 194.247.38.0/24'
printlist = printlist.split(', ')
check_list = {IPNetwork(x):0 for x in printlist}
for network in raw_net_list:
    address = IPNetwork(network)[0]
    for checknet in check_list:
        if address in checknet:
            check_list[checknet] += 1
plt.bar(printlist, check_list.values())
plt.xticks(rotation=90)
plt.grid(b=True)
plt.tight_layout()
plt.xlabel('IP-netwerken')
plt.ylabel('Aantal subnetwerken')
plt.savefig('subnetwerk_verdeling.png')


# In[97]:


values = [0, 0.5,0.9,0.7,0.9]
weights = [1,5,100,3,8]
final_dist = 0
for v in range(len(values)):
    final_dist += values[v] * weights[v]
final_dist = final_dist / sum(weights)
final_dist

