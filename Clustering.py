#Menno Bezema, Bachelor eind project, clustering van IP-adressen


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
import bottleneck as bn
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
# psl_file = fetch()
# psl = PublicSuffixList(psl_file)
_CACHE = {}

def evalstr(x):
    if pd.isnull(x):
        return np.nan
    else:
        return literal_eval(x)

#read out the dataset    
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
pdns_2018_9_10.index = pdns_2018_9_10.ip_int
pdns_2018_9_10 = pdns_2018_9_10.sort_index()
pdns_no_dates_count = pdns_2018_9_10.drop(['fromtime', 'count', 'totime', 'dhe'], axis = 1)

#get the list of networks, to split up the dataset into smaller network blocks
with open('./merged_net_list.csv', 'r')as f:
    readlist = (f.read()).split(';')
    readlist = readlist[0:-1]
    merged_net_list = [IPNetwork(x) for x in readlist]
    print(merged_net_list)

#create a network dictionary with a pandas dataframe containing a specific networks information for every entry
net_dic = {}
counter = 0
for i in range(0, len(merged_net_list)):
    value = pdns_no_dates_count.loc[(pdns_no_dates_count['ip'] <= merged_net_list[i][-1]) & (pdns_no_dates_count['ip'] >= merged_net_list[i][0])]
    if len(value) > 20:
        key = 'block' + str(counter)
        print(('net: {0}, entries: {1}, {2}').format(merged_net_list[i], len(value), key))
        net_dic[key] = value
        counter += 1

#########################################################################
            #Functions for combining IP-addresses/networks#
#########################################################################
#function for combining properties containing strings
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

#function for combining booleans returns [True,False] on not equal bolleans
def combine_bool(new, old):
    if isinstance(old, list):
        return old
    elif isinstance(new, list):
        return new
    elif old == new:
        return old
    else:
        return [old, new]

#function for combining numeric properties (returns average if both elements are not nan)
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

#function for calcing the distribution of each TLD
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

#function for turning a list into a list with only unique elements
def setify(item):
    if (not isinstance(item, float)) and (not isinstance(item, str)):
        item = set(item)
        return sorted([x for x in item])
    else:
        return item

#function for combining IP-addresses or IP-networks
#combines elements with equal IP tot that single IP
#combines different IP-addresses or IP-networks to an IP-network starting at the first found IP and ending at last found IP
def combine_networks(netnew, netold):

    
    netnew.ns_ass = combine_categories(netnew.ns_ass, netold.ns_ass)
    netnew.ns_ass = setify(netnew.ns_ass)

    netnew.tld = combine_categories(netnew.tld, netold.tld)
    netnew = calc_tld(netnew)
    
    secondld = (combine_categories(netnew['2ld'], netold['2ld']))
    netnew['2ld'] = setify(secondld)
        
    netnew.ttl = combine_numerical(netnew.ttl, netold.ttl)
    netnew.age = combine_numerical(netnew.age, netold.age)

#unused functions, useful for combining other properties
#     netnew.domain = combine_categories(netnew.domain, netold.domain)
#     netnew.domain = setify(netnew.domain)
#     netnew.is_ns = combine_categories(netnew.is_ns, netold.is_ns)
#     netnew.is_ns = setify(netnew.is_ns)
#     netnew.domains_ass = combine_categories(netnew.domains_ass, netold.domains_ass)
#     netne.wdomains_ass = setify(netnew.domains_ass)
#     if netnew.isp != netold.isp:
#         netnew.isp = [netnew.isp, netold.isp]
#     netnew.is_public_proxy = combine_bool(netnew.is_public_proxy, netold.is_public_proxy)
#     netnew.is_hosting_provider = combine_bool(netnew.is_hosting_provider, netold.is_hosting_provider)
#     netnew.smtp = combine_bool(netnew.smtp, netold.smtp)
    
    #if elements are the same IP then retur
    if netnew.ip != netold.ip:
        if pd.notnull(netold.last_ip):
            netnew.last_ip = netold.last_ip
        else:
            netnew.last_ip = netold.ip
    return netnew

#function that takes in a dataframe and merges every entry in the dataframe onto IP-addresses
def merge_network(network, itemnumber):
    if itemnumber in _CACHE:
        return _CACHE[itemnumber]

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
        else:
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
    ans = ans[pd.notnull(ans.domain)] #remove nameservers
    _CACHE[itemnumber] = ans

    return ans 



#########################################################################
    #Functions for calculating distances between IP-addresses#
#########################################################################

#Compare sequences based on an adaptation of the Ratcliff-Obershelp algorithm
def compare_word_list(element1, element2, threshold):
    if isinstance(element1, list):
        True
    elif isinstance(element1, str):
        element1 = [element1]
    else:
        return 0
    if isinstance(element2, list):
        True
    elif isinstance(element2, str):
        element2 = [element2]
    else:
        return 0
        
    set_b = {el for el in element1}
    set_a = {el for el in element2}
    common = set_a.intersection(set_b)
    if common:
        return 0.0
    
    element_a = list(set_a)
    element_b = list(set_b)
    
    i = len(element_a)
    j = len(element_b)
#     if i >= 500 or j >= 500:
#         print(i)
#         print(j)
    matrix = np.empty((i,j,))
    matrix[:] = np.nan
    for row in range(0, i):
        for col in range(0,j):
            if element_a[row] == element_b[col]:
                matrix[row][col] = 0.0
                continue
            if np.isnan(matrix[row][col]):
                match = 1 - SequenceMatcher(None, element_a[row], element_b[col]).ratio()                            
                matrix[row][col] = match
#     top_average = 0
#     for i in range(10):
#         ind = np.unravel_index(np.argmin(matrix, axis=None), matrix.shape)
#         top_average += matrix[ind]
#         matrix[ind] = math.inf
    
    return matrix.mean()

#function for calculating the distance per TLD for 2 IP-addresses
def tld_dist(ip1, ip2, _UNIQUE_TLD):
    total = 0
    for element in ip1[_UNIQUE_TLD].index:
        el1 = ip1[element]
        el2 = ip2[element]
#         print(element)
        if pd.isnull(el1) :el1 = 0
        if pd.isnull(el2): el2 = 0
        if el1 == 0 and el2 == 0:
            continue
        else:
            total += math.fabs(el1 - el2)
    return (total / 2)
 
 #function for determining z-scores
def getz(att, column):
    mean = column.mean()
    std = column.std()
    att = (att - mean) / std
    if att > 2:
        att = 2
    elif att < -2:
        att = 2
    att = att / 5
    return att + 0.5

#function for determining the distance between 2 numeric data points
def numeric_dist(att1, att2, column):
    if pd.isnull(att1) or pd.isnull(att2):
        return np.nan
    else:
        att1 = getz(att1, column)
        att2 = getz(att2, column)
        return (math.fabs(att1 - att2))

#function that takes in a dataframe and an index and calculates the distance between the index element and the index + 1 element
def calculate_distance(df, index, _UNIQUE_TLD, threshold, _FACTORS):

    dataframe = df.copy()
    next_index = index + 1
    
    distances = {"domain": np.nan, "ns_ass":np.nan, "tld":np.nan, "2ld":np.nan, "ttl":np.nan, "age":np.nan}
    if _FACTORS['domain'] != 0:
        column = dataframe['domain']
        distances["domain"] = compare_word_list(column[index], column[next_index], threshold)
    
    if _FACTORS['ns_ass'] != 0:
        column = dataframe['ns_ass']
        distances["ns_ass"] = compare_word_list(column[index], column[next_index], threshold)
        
    if _FACTORS['tld'] != 0:
        distances["tld"] = tld_dist(dataframe.loc[index], dataframe.loc[next_index], _UNIQUE_TLD)
        
    if _FACTORS['2ld'] != 0:
        column = dataframe['2ld']
        distances["2ld"] = compare_word_list(column[index], column[next_index], threshold)
        
    if _FACTORS['ttl'] != 0:
        column = dataframe['ttl']
        distances["ttl"] = numeric_dist(column[index], column[next_index], dataframe.ttl)
        
    if _FACTORS['age'] != 0:
        column = dataframe['age']
        distances["age"] = numeric_dist(column[index], column[next_index], dataframe.age)
    if all(pd.isnull(value) for value in distances.values()):
        return math.inf
    
    #add weights to distances
    final_distance = 0
    divider = 0
    for k in distances:
        v = distances[k]
        if pd.notnull(v):
            final_distance += v * _FACTORS[k]
            divider += _FACTORS[k]
    return final_distance / divider

#function for removing not used rows
def remove_nused_rows(dataframe, _FACTORS):
    df = dataframe.copy()
    
    if _FACTORS['age'] != 0:
        return df
    elif _FACTORS['2ld'] != 0:
        return df
    elif _FACTORS['tld'] != 0:
        return df
    else:
        if _FACTORS['ttl'] != 0 and _FACTORS['ns_ass'] == 0:
            return df[pd.notnull(df.ttl)]
        elif _FACTORS['ns_ass'] != 0 and _FACTORS['ttl'] == 0:
            return df[pd.notnull(df.ns_ass)]
        else:
            return df[pd.notnull(df.ns_ass)]

#function that iterates over a dataframe and calculates the distance to each consecutive row
def initialize_dist(dataframe, threshold, _FACTORS, itemnumber):
    ans = remove_nused_rows(dataframe.copy(), _FACTORS)
    ans = ans.reset_index(drop = True)

    remove = {'2ld', 'age','domain', 'domains_ass',
       'ip', 'ip_int', 'is_hosting_provider', 'is_ns', 'is_public_proxy',
       'isp', 'nan', 'ns_ass', 'smtp', 'tld', 'ttl', 'distance'}
    _UNIQUE_TLD = [e for e in ans.columns if e not in remove]
    
    for index, row in ans.iterrows():
        if index <= ans.index[0]:
            continue
        elif index == ans.index[-1]:
            break
        else:
            ans.at[index - 1, 'distance'] = calculate_distance(ans.copy(), index - 1, _UNIQUE_TLD, threshold, _FACTORS)
    ans.index = ans.ip_int
    return ans



#########################################################################
            #Functions for clustering#
#########################################################################

#function for finding the minimum distance in a dataframe and combining the elements with that distance
#iterates by combining elements, recalculating distances and finding a new element
def cluster(df, threshold, clusters, _FACTORS, max_dist):
    frame = df.copy()
    if all(x == 0 for x in _FACTORS):
        return df
    frame['last_ip'] = np.nan
    frame = frame.reset_index(drop = True)
    
    remove = {'2ld', 'age','domain', 'domains_ass',
       'ip', 'ip_int', 'is_hosting_provider', 'is_ns', 'is_public_proxy',
       'isp', 'nan', 'ns_ass', 'smtp', 'tld', 'ttl', 'distance', 'last_ip'}
    _UNIQUE_TLD = [e for e in frame.columns if e not in remove]
    
    n = len(frame) 
    while n > clusters and frame.distance.min() <= max_dist:
        index = frame.distance.idxmin()
        min_row = frame.loc[index,:].copy()
        next_row = frame.loc[index + 1,:].copy()

        new_el = combine_networks(min_row, next_row)
        frame = frame.drop(index + 1)
        frame = frame.reset_index(drop = True)

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
            frame.at[index, 'distance'] = calculate_distance(frame, index, _UNIQUE_TLD,
                                                             threshold, _FACTORS)
        if index != 0:
            frame.at[index - 1,'distance'] = calculate_distance(frame, index - 1, _UNIQUE_TLD,
                                                                threshold, _FACTORS)
        n -= 1
    return frame

#function that produces a dictionary of all known subnetworks in a super network
#These subnetworks are used to find borders, to validate with
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

#Function for calculating the score of a clustering from a validation set
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
    result = {str(x):0 for x in expected}
    for expected_net in expected:
        expected1 = expected_net[0]
        expected2 = expected_net[-1]
        for actualnet in my_net:
            actual1 = actualnet[0]
            actual2 = actualnet[-1]
            if expected1 > actual1 and expected1 < actual2:
                result[str(expected_net)] += 1
                misallocation += 1
            if expected2 > actual1 and expected2 < actual2:
                result[str(expected_net)] += 1
                misallocation += 1

    average_per_net = 0
    if nets_amount != 0:
        average_per_net = (total_net_length / nets_amount)
    return [total_net_length, misallocation, nets_amount]

#function for reading out a .csv file containing experiments
def read_exp(filename):
    with open('./' + filename, 'r')as f:
        ans = []
        start = 0
        for line in f:
#             print(line + 'line')
            line = line.replace(',', '.')
            design = line.split(';')[0:7]
            if start == 0: 
                start += 1
                continue
            if not design[0]: break
#             print(design)
            ans.append([float(x) for x in design])
    return ans

#function that takes in a network, an experimental design and parameters and runs all the experiments
def run_tests(network, block_nr, dictionary, exp_filename, _EXP_TOGO, _RESULTS):

    exp_design = read_exp(exp_filename)
    _EXP_TOGO = exp_design
    merged_block = merge_network(network = dictionary['block' + str(block_nr)], itemnumber= block_nr)
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
        threshold = 0.0
        max_dist = exp[1]
        _FACTORS = {"domain": 0, "ttl": exp[2], "age":exp[3] , "2ld": exp[4], "tld": exp[5], "ns_ass": exp[6]}
        
        
        #initialize block
        distance_block = initialize_dist(dataframe= merged_block, threshold = threshold,
                                         _FACTORS = _FACTORS, itemnumber= block_nr)
        
        #cluster block
        clustering = cluster(df= distance_block, threshold = threshold,
                             clusters= 1 ,_FACTORS= _FACTORS, max_dist= max_dist)
        
        #calc metrics
        metric = cal_error(clustering, expected)
        _RESULTS.append([exp_num, metric[0], metric[1], metric[2]])

    return _RESULTS    

#Function for adding validation borders to a dataframe
def add_val_ips(network):
    info = network
    info.ip_int = info.ip_int.apply(lambda x: int(x))
    info.index = info.ip_int
    new_df = []
    for i in raw_net_list:
        if i in IPNetwork('93.158.208.0/20'):
            new_df.append((int(i[0])))
            new_df.append((int(i[-1])))
    new_df = pd.DataFrame(new_df)
    new_df.columns = ['ip_int']
    new_df.index = new_df.ip_int
    new_df['2ld'] = '-----Validatie grens-----'
    new_df['tld'] = '-----Validatie grens-----'
    new_df['age'] = '-----Validatie grens-----'
    new_df['ttl'] = '-----Validatie grens-----'
    new_df['ns_ass'] = '-----Validatie grens-----'
    new_df['ip'] = new_df.ip_int.apply(lambda x: IPAddress(x))
    new_df
    info = info.append(new_df, sort= True)
    return info.sort_index()

# Function for running a single experiment and adding the validation set borders to the dataframe
# Useful for evaluating a given clustering 
def single_test(blocknr, network, max_dist,ttl,  age, secld, tld, ns_ass):
    _FACTORS = {"domain": 0, "ns_ass": ns_ass, "tld": tld, "2ld": secld,
            "ttl": ttl, "age": age}
    
    merged_block = merge_network(net_dic['block' + str(blocknr)], blocknr)
    merged_block = merged_block[pd.notnull(merged_block.domain)] 
    
    distance_block = initialize_dist(dataframe= merged_block, threshold = 0,
                                             _FACTORS = _FACTORS, itemnumber= blocknr)     
    info_distances = add_val_ips(distance_block)
    #cluster block
    clustering = cluster(df= distance_block, threshold = 0,
                         clusters= 1 ,_FACTORS= _FACTORS, max_dist= max_dist)
    info_clustering = add_val_ips(clustering)
    #calc metrics
    val_set = get_validation(raw_net_list)
    actual = val_set[IPNetwork(network)]
    metric = cal_error(clustering, actual)
#     print('max_afstand: ' + str(max_dist) + ', grensoverschrijdingen: ' + str(metric[1])
#                    + ', IPs in segmenten: ' + str(metric[0])
#                   + ', aantal segmenten: ' + str(metric[2]))
    print( str(metric[1])
                   + ';' + str(metric[0]))
    return [distance_block, info_distances, clustering, info_clustering]

#function for writing results to csv file
def write_output(out_list, filename):
    with open('./' + str(filename) + '.csv', 'w+')as f:
        for i in out_list:
            line = str(i[1]).replace('.', ',') + ';' + str(i[2]) + '\n'
            print(line)
            f.write(line)

#run experiments from a file
_RESULTS = []
_EXP_TOGO = []
_CACHE = {}
exp1 = run_tests('93.158.208.0/20', 12, net_dic, 'Experimenteel_ontwerp.csv', _EXP_TOGO, _RESULTS)
write_output(_RESULTS, 'results')
