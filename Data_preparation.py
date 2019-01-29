#Data preparation
#Collect initial data
#{'attribute': [{'name': 'inetnum', 'value': '160.20.152.0 - 160.20.155.255'}, {'name': 'netname', 'value': 'NL-SERVERIUS5-20180831'}, {'name': 'country', 'value': 'NL'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/organisation/ORG-SB539-RIPE'}, 'name': 'org', 'value': 'ORG-SB539-RIPE', 'referenced-type': 'organisation'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/person/GVG126-RIPE'}, 'name': 'admin-c', 'value': 'GVG126-RIPE', 'referenced-type': 'person'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/person/SP17499-RIPE'}, 'name': 'tech-c', 'value': 'SP17499-RIPE', 'referenced-type': 'person'}, {'name': 'status', 'value': 'ALLOCATED PA'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/mntner/RIPE-NCC-HM-MNT'}, 'name': 'mnt-by', 'value': 'RIPE-NCC-HM-MNT', 'referenced-type': 'mntner'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/mntner/serverius-mnt'}, 'name': 'mnt-by', 'value': 'serverius-mnt', 'referenced-type': 'mntner'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/mntner/serverius-mnt'}, 'name': 'mnt-lower', 'value': 'serverius-mnt', 'referenced-type': 'mntner'}, {'link': {'type': 'locator', 'href': 'http://rest.db.ripe.net/ripe/mntner/serverius-mnt'}, 'name': 'mnt-routes', 'value': 'serverius-mnt', 'referenced-type': 'mntner'}, {'name': 'created', 'value': '2018-08-31T11:21:24Z'}, {'name': 'last-modified', 'value': '2018-08-31T11:21:24Z'}, {'name': 'source', 'value': 'RIPE'}]}

#Read out JSON files found by searching RIPE for IP-networks mnt-by: serverius-mnt
#Gives a list of all cidrs found by ripe query, there is a lot of overlap. unmerged: 64455 addresses (417 networks), merged: 40448 addresses (30 networks). Difference: 24007. 
with open('serverius-mnt.json') as json_file: 
    data = json.load(json_file)
    raw_net_list = []
    for p in data['objects']['object']:
        if p['type'] == 'inetnum':
            ip_range = p['attributes']['attribute'][0]['value'].split(' - ')
            ip_net = iprange_to_cidrs(ip_range[0], ip_range[1])
            raw_net_list.extend(ip_net)

#We need to combine all the found networks so we do not query data multiple times for a single IP-address
merged_net_list = cidr_merge(raw_net_list)
#merged_net_list: 5.178.64.0/21, 5.188.12.0/22, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24, 91.217.191.0/24, 91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 91.243.44.0/22, 93.158.200.0/21, 93.158.208.0/20, 160.20.152.0/22, 178.21.16.0/21, 185.1.95.0/24, 185.8.176.0/22, 185.12.12.0/22, 185.42.59.0/24, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.48.92.0/22, 194.107.76.0/22, 194.247.30.0/23, 194.247.38.0/24

#we now need to gather PDNS information from all the found networks.
#We do that by adding the networks to the 'ips' file. 
#we then execute the isc_pdns2.py program via the command line app and it queries the DNSDB for the IP-addresses.
#Note: only 5000 queries can be done every day, with 120k IP-addresses for this research, this takes a long time.
#That is why we used the DNSDB info provided by the Economics of Cybersecurity group at the TU Delft 

#read out all domain name information found for the IP-addresses into a pandas data frame:
_PDNS = pd.read_csv('Serverius_domains.csv')
_PDNS = line1_pdns['result'].str.split("\t", n = 5, expand = True)
_PDNS.columns = ['domain', 'type', 'ip', 'count', 'fromtime', 'totime']
#convert the dates to utc time
_PDNS['fromtime'] = _PDNS['fromtime'].apply(lambda x: datetime.utcfromtimestamp(int(x)).strftime('%Y-%m-%d %H:%M:%S'))
_PDNS['totime'] = _PDNS['totime'].apply(lambda x: datetime.utcfromtimestamp(int(x)).strftime('%Y-%m-%d %H:%M:%S'))


#use PDNS information on nameservers provided by the econsec group to filter out records which are nameservers
domain_names = _PDNS
gzip_set1 = set()
with gzip.open('./NS/dns.201810.NS_U.gz', 'rt') as f:
    for line in f:
        gzip_set1.add(line.split('\n')[0] + '.')
gzip_set2 = set()
with gzip.open('./NS/dns.201810.NS_U.gz', 'rt') as f:
    for line in f:
        gzip_set2.add(line.split('\n')[0] + '.')
cont_domains = {x for x in domain_set if x in gzip_set1 or x in gzip_set2}
def change_type(element):
    if element in cont_domains:
        return 'NS'
    else:
        return 'A'
_PDNS.type = _PDNS.domain.apply(lambda x: change_type(x))

#From domainnames find out their TTL and their associated nameservers:
def dig_ttl(ns, domain):
    ans = ''
    try:
        ans = check_output(["dig", "+nocmd", "+noall", "+answer", ns, domain])
        return ans
    except:   
        print(('ns: {0}, failed with domain: {1}').format(ns, domain))
        return ans
            
def get_ns(domain):
    if pd.isnull(domain):
        return np.nan
    ans = check_output(["dig", "-t", "NS", domain, '+short'])
    ans = ans.decode()
    if ans:
        ans = ans.split()
        return ans
    else:
        return np.nan  
    
def get_ttl(row):
    ns = []
    ans = ''
    if not isinstance(row.ns_ass, list):
        if pd.isnull(row.ns_ass):
            return np.nan
        else:
            temp = get_ns(row.domain)
            if isinstance(temp, list):
                for i in temp:
                    ns.append('@' + i)
            else:
                ns.append('@' + temp)
    else:
        for nameserver in row.ns_ass:
            ns.append('@' + nameserver)
    ns = set(ns)
    for i in ns:
        ans = dig_ttl(i, row.domain)
        if ans:
            break
    if ans:
        ans = ans.decode()
        ans = ans.split()[1]
        print(('ans: {0}, domain: {1}').format(ans, row.domain))
        return ans
    else:
        print(('nothing found, ns: {0}, domain: {1}').format(ns, row.domain))
        return np.nan
_PDNS.ttl = _PDNS.apply(get_ttl, axis=1)

#Read out DNSDB Gzip files containing historical NS records
gzip_dic1 = {}
with gzip.open('./DOMAIN_NS/dns.201809.M.mtbl.NS.gz_DI_U.gz', 'rt') as f:
    counter = 1
    for line in f:
        if counter % 100000 == 0:
            print(counter)
        ans = line.split('|')
        ans[0] = ans[0] + '.'
        if ans[0] in domain_set:
            check_dict(gzip_dic1, ans[0], ans[1].strip() + '.')
            print(gzip_dic1[ans[0]])
        counter += 1
with gzip.open('./DOMAIN_NS/dns.201810.M.mtbl.NS.gz_DI_U.gz', 'rt') as f:
    counter = 1
    for line in f:
        if counter % (989700000/10) == 0:
            print((time.time() - start))
        ans = line.split('|')
        ans[0] = ans[0] + '.'
        if ans[0] in domain_set:
            check_dict(gzip_dic1, ans[0], ans[1].strip() + '.')
        counter += 1

#add ns info to dataset
def check_dom(domain):
    if domain in gzip_dic1:
        return gzip_dic1[domain]
    else:
        return np.nan
_PDNS['ns_ass'] = _PDNS['domain'].apply(check_dom)

#get missing nameservers from domains
start = time.time()
def get_ns(row):
    if pd.isnull(row.domain):
        return np.nan
    if isinstance(row.ns_ass, list) or pd.notnull(row.ns_ass):
        return row.ns_ass
    ans = check_output(["dig", "-t", "NS", row.domain[0:-1], '+short'])
    ans = ans.decode()
    if ans != '':
        ans = ans.split()
        print(time.time() - start)
        return ans
    else:
        return np.nan

_PDNS.ns_ass = _PDNS.apply(get_ns, axis=1)

#add dhe information  (not used in final clustering)
import lz4.frame
serverius_set = set()
for net in merged_net_list:
    print(net)
    for ip in net:
        serverius_set.add(str(ip))
        
start = time.time()
output_data = set()
with lz4.frame.open('./full_ipv4_https_dhe.lz4', mode='rt') as fp:
    for line in fp:
        ip = line.split('\n')
        if ip[0] in serverius_set:
            output_data.add(ip[0])
pdns_2018_9_10['dhe'] = pdns_2018_9_10.ip.apply(lambda x: str(x) in output_data)

#add smtp information
import lz4.frame
start = time.time()
output_data = set()
with lz4.frame.open('./3u6c1qhlzifqqub8-25-smtp-starttls-full_ipv4-20181112T023657-zmap-results.csv.lz4', mode='rt') as fp:
    for line in fp:
        line = line.split()[0]
        if line in serverius_set:
            output_data.add(line)
print(time.time() - start)

#########################################################################
						#Visualizing data#
#########################################################################
#build a list of researched networks, useful as axis label
printlist = '5.178.64.0/21, 5.255.64.0/19, 46.249.32.0/19, 89.47.1.0/24, 91.142.132.0/24, 91.198.106.0/24, 91.205.192.0/23, 91.216.34.0/24,  91.220.37.0/24, 91.220.53.0/24, 91.221.69.0/24, 93.158.200.0/21, 93.158.208.0/20, 178.21.16.0/21, 185.8.176.0/22, 185.12.12.0/22, 185.53.160.0/22, 185.79.112.0/22, 185.116.166.0/23, 193.23.143.0/24, 194.247.30.0/23, 194.247.38.0/24'
printlist = printlist.split(', ')

# plot2 = plot2.drop('count', axis=1)
print(merged_net_list)
max_val = 3270977204
ans = plot2.hist(bins = 300)[0][0]
# rect = patches.Rectangle(xy = (x1,0), width = 10000 * (x2 - x1), height = 10)
# ans.add_patch(rect)
for i, net in enumerate(merged_net_list):
    ip1_end = int(net[-1])
    ip2_start = int(merged_net_list[i+1][0])
    if ip1_end + 1000000 >= ip2_start:
        print(('ip1 end: {0}, ip2 start: {1}, diff: {2}').format(ip1_end, ip2_start, ip2_start - ip1_end))
        print('add!')
print(ans)

#change IP into IPaddress object
_PDNS['ip_int'] = _PDNS['ip'].apply(lambda x: int(IPAddress(x)))

#select dates after 01-09-2018
pdns_2018_9_10 = _PDNS.loc[_PDNS['totime'] >= dp.parse('2018-09-01').date()]
pdns_2018_9_10 = pdns_2018_9_10.reset_index()
   

#plotting monstrosity (plot distributies van domeinnamen per netwerk)
def describe_block(block_df, blocknumber):
    for item in block_df.columns:
        top_list = block_df[item].value_counts().nlargest(10)
        print(('columns: {0}, values: {1}').format(item, top_list))
def make_graph(block, blocknumber):
    plot_df = pd.DataFrame(block['ip'].value_counts())
    plot_df = plot_df.sort_values(by = ['ip'])
    plot_df['new'] = plot_df.index
    plot_df['new'] = plot_df['new'].apply(lambda x: int(IPAddress(x)))
    plot_df.columns = ['count', 'ip']
    plot_df = plot_df.sort_values(by = ['ip'])
    first_ip = int(plot_df['ip'].iloc[0])
    plot_df['ip'] = plot_df['ip'].apply(lambda x: x - first_ip)
    plot_df.index = plot_df['ip']
    width = plot_df['ip'].max() / len(plot_df)
    threshold = int(plot_df['count'].mean())
    plot_extreme = plot_df.loc[plot_df['count'] > threshold]
    plot_extreme['count'] = plot_extreme['count'].apply(lambda x: threshold)
    plot_df = plot_df.loc[plot_df['count'] <= threshold]
    plt.bar(plot_df['ip'], plot_df['count'], label='count', width = width)
    plt.bar(plot_extreme['ip'], plot_extreme['count'], label='count', width = width / 4, color = 'r')
    plt.xlabel('IP-addressen als getallen')
    plt.ylabel('Aantal domeinnamen')
    filename = './Figures/ip_dom_block_' + str(blocknumber) + '.png'
    print(filename)
    plt.savefig(filename)
    plt.close()

plt.close()
for i, item in enumerate(net_dic):
    describe_block(net_dic[item], i + 1)
# make_graph(net_dic['block20'], 99)

#verdeling top 100 ip-adressen:
top = 100
test = pd.DataFrame(pdns_2018_9_10['ip'].value_counts().nlargest(top))
x = np.linspace(0, top, top)
plt.plot(x, test['ip'])
plt.xlabel('top 100 IP-adressen')
plt.ylabel('aantal domeinnamen per IP-adres')
plt.savefig('ip_domain_total.png')

#verdeling subnetwerken per netwerk

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

#find all nameservers and SOA associated with an ip address 
import csv
with open('./ip_output.csv', 'r') as f:
    reader = csv.reader(f)
    your_list = list(reader)   
counter = 1
domain_dictionary = {}
for line in your_list:
    info = line[0].split('\t')
    if info[1] == 'NS':
        check_dict(domain_dictionary, info[2], info[0])
    elif info[1] == 'SOA':
        soa_line = info[2].split()
        check_dict(domain_dictionary, soa_line[0], info[0])
        check_dict(domain_dictionary, soa_line[1], info[0])
    counter +=1
domain_dictionary[np.nan] = np.nan
pdns_2018_9_10['domains_ass'] = pdns_2018_9_10.is_ns.apply(lambda x: domain_dictionary[x])

#per netwerk de TLD informatie:
result = pd.DataFrame(index = pdns_2018_9_10['tld'].value_counts(normalize = True).nlargest(20).index, columns = ['A'])
for item in net_dic:
    block = net_dic[item]
    test = block['tld'].value_counts(normalize = True).nlargest(20)
#     print(test)
    result = pd.concat([result, test], axis = 1, sort=False)
result = result.drop('A', axis=1)
result.columns = printlist
result = result.fillna(0)
result = result.head(10)
result = result * 100
result = result.astype(int)
result.iloc[:,:11]

#Per netwerk de 2LD informatie:
index = list(range(1,21))
result = pd.DataFrame(index = index, columns = ['A'])
for item in net_dic:
    block = net_dic[item]
    test = block['2ld'].value_counts(normalize = True).nlargest(20)
    test = test.reset_index()
#     print(test)
    result = pd.concat([result, test], axis = 1, sort=False)
result = result.drop('A', axis=1)
columnlist = []
blocksize = []
for block in net_dic:
    blocksize.append(len(net_dic[block]))
for i, item in enumerate(printlist):
    columnlist.append(str(item) + ' size: '+str(blocksize[i]))
    columnlist.append('%')
result.columns = columnlist
result['%'] = result['%'].apply(lambda x: (x * 100))
result = result.head(10)
result.iloc[:,:14]

#ISP tables
result = pd.DataFrame(index = pdns_2018_9_10['isp'].unique(), columns = ['A'])
for item in net_dic:
    block = net_dic[item]
    test = block['isp'].value_counts(normalize = True)
    result = pd.concat([result, test], axis = 1, sort=False)
result = result.drop('A', axis=1)
result = result.drop(result.index[1], axis=0)
result = result.fillna(0)
result = result * 100
result.columns = printlist
result.index = ['Serverius Holding B.V.','Onbekend', 'GetHost V.o.F.']
result = result.round(2)
# result = result.astype(int) 
result.iloc[:,0:11]

#is_anonymous info
result = pd.DataFrame(index = [True, False], columns = ['A'])
for item in net_dic:
    block = net_dic[item]
    test = block['is_anonymous'].value_counts(normalize = True)
    result = pd.concat([result, test], axis = 1, sort=False)
result = result.drop('A', axis=1)
result = result.drop([0,1], axis=0)
result = result.fillna(0)
result = result * 100
result.columns = printlist
# result = result.astype(int) 
result.iloc[:,0:11]

#to exit node info
result = pd.DataFrame(index = [True, False], columns = ['A'])
for item in net_dic:
    block = net_dic[item]
    test = block['is_tor_exit_node'].value_counts(normalize = True)
    result = pd.concat([result, test], axis = 1, sort=False)
result = result.drop('A', axis=1)
result = result.drop([0,1], axis=0)
result = result.fillna(0)
result = result * 100
result.columns = printlist
# result = result.astype(int) 
result.iloc[:,0:11]

#fromdate info
result = pd.DataFrame(index = ['min', 'max'], columns = ['A'])
for item in net_dic:
    block = net_dic[item]
    min_time = block['fromtime'].min()
    max_time =  block['fromtime'].max()
    test = pd.DataFrame({'X': [min_time , max_time]}, index = ['min', 'max'])
    result = pd.concat([result, test], axis = 1, sort=False)
result = result.drop('A', axis=1)
result.columns = printlist
# result = result.astype(int) 
result.iloc[:,:11]

#printen van subfiguren
print(printlist)
for i in range(1, 23):
    print("\\begin{subfigure}{.5\\textwidth}")
    print("\centering")
    print('\includegraphics[width=.8\linewidth]{Figures/domains_net/ip_dom_block_'+ str(i) +'.png}')
    print('\caption{' + printlist[i-1] + '}')
    print('\label{fig:sfig' + str(i) +'}')
    print('\end{subfigure}')

#TTL percentage per netwerk
ttl = []
for i in merged_dic:
    ttl_true = len(merged_dic[i][pd.notnull(merged_dic[i].ttl)])
    print(ttl_true)
    ttl.append(int(ttl_true / len(merged_dic[i]) * 100))
plt.bar(printlist, ttl)
plt.xticks(rotation=90)
plt.grid(b=True)
plt.xlabel('IP-netwerken')
plt.ylabel('Percentage datapunten met ttl')
plt.savefig('ttl_merged_percentage.png')

#ttl gemiddelde per netwerk
ttl = []
for item in net_dic:
    test = net_dic[item].ttl.mean()
    ttl.append(float(test))
plt.bar(printlist, ttl)
plt.xticks(rotation=90)
plt.grid(b=True)
plt.xlabel('IP-netwerken')
plt.ylabel('Gemiddelde ttl')
plt.savefig('ttl_bar.png')

#gemiddelde leeftijd per netwerk
age = []
for item in net_dic:
    block = net_dic[item]
    test = block['age'].mean()
    age.append((test))
plt.bar(printlist, age)
plt.xticks(rotation=90)
plt.grid(b=True)
plt.xlabel('IP-netwerken')
plt.ylabel('Gemiddelde leeftijd')
plt.savefig('age_graph.png')

#read out data storage
# _PDNS.to_csv('serverius_pdns.csv', index=False)
parse_dates = ['fromtime', 'totime']
_PDNS = pd.read_csv('serverius_pdns.csv', parse_dates=parse_dates,  dtype={"ip": object, "domain": object,
                                                                           "Type": object, "count": int,
                                                                          "isp": object, "is_anonymous": object,
                                                                          "is_hosting_provider": object, "is_public_proxy": object,
                                                                          "is_anonymous_vpn": object, "is_tor_exit_node": object,
                                                                          "tld": object, "2ld": object, "ip_int": int})
_PDNS

#convert columns of data into new columns using these functions
def getAge(row):
    difference = (row.totime - row.fromtime).total_seconds()
    if difference == 0.0:
        return 0
    else:
        return difference / (3600 * 24) #age in days

def checknan2ld(row):
    if pd.notnull(row.domain):
        ans = (getSuffix(row.domain))
        if '.' not in ans:
            return row.domain.split('.')[-2]
        else:
            return ans.split('.', 1)[0]
    else:
        return np.nan
    
def checknantld(row):
    if pd.notnull(row.domain):
        ans = (getSuffix(row.domain))
        if '.' not in ans:
            return ans
        else:
            return ans.split('.', 1)[1]
    else:
        return np.nan
    
def evalstr(x):
    if pd.isnull(x):
        return np.nan
    else:
        return literal_eval(x)
    
def getSuffix(domain):
    return psl.get_public_suffix(domain)



#Helper functions:
def check_dict(dicti, key, new_val):
    if key in dicti:
            value = dicti[key]
#             print(('key: {0}, new_val: {1}, old_val:{2}').format(key, new_val, value))
            if isinstance(value, list):
                value.append(new_val)
                dicti[key] = value
            else:
                dicti[key] = [value, new_val]
    else:
        dicti[key] = new_val
#     print(dicti[key])
    return dicti
