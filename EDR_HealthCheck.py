import csv
import pandas
from ms_active_directory import ADDomain
import getpass

domain = ADDomain('###DOMAIN NAME###')
sam = input('Username: ')
psswd = getpass.getpass('Password (Input Censored): ')
executed_user = getpass.getuser()
sentinel_export_path = input('What is the full path of the sentinel export: ').removeprefix("\"").removesuffix("\"")
device_list = []
sentinel_df = pandas.read_csv(sentinel_export_path)
session = domain.create_session_as_user(f'{sam}###DOMAIN NAME###', psswd)
device_dic = {}
fields = ['cn', 'lastLogon', 'logoncount', 'operatingSystem', 'whenCreated']

with open(f'C:/users/{executed_user}/Documents/VulnerableDevices.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(fields)

devices = session.find_computers_by_attribute('objectCategory', 'CN=Computer,CN=Schema,CN=Configuration,DC=nlplogix,DC=lan', ['distinguishedName', 'cn'])

for device in devices:
    device_dn = device.get('distinguishedName')
    device_cn = device.get('cn')
    device_dic[device_cn] = device_dn
    if 'OU=###DISABLED COMPUTERS OU###' not in device_dn:
        device_list.append(device_cn)

protected_ep_df = sentinel_df.loc[:, 'Endpoint Name']
protected_ep = []

for data in protected_ep_df:
    protected_ep.append(data)

for ep in device_list:
    if ep not in protected_ep:
        vul_ep = session.find_computer_by_distinguished_name(device_dic[ep], ['lastLogon', 'logoncount', 'operatingSystem', 'whenCreated'])
        vul_ep_list = []
        vul_ep_list.append(vul_ep.get('cn'))
        vul_ep_list.append(vul_ep.get('lastLogon'))
        vul_ep_list.append(vul_ep.get('logoncount'))
        vul_ep_list.append(vul_ep.get('operatingSystem'))
        vul_ep_list.append(vul_ep.get('whenCreated'))
        
        with open(f'C:/users/{executed_user}/Documents/VulnerableDevices.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(vul_ep_list)

with open(f'C:/users/{executed_user}/Documents/VulnerableDevices.csv', 'r', newline='') as f:
    vul_len = sum(1 for row in f) - 1

print(f'\nThere are a total of {len(device_list)} enabled domain joint devices.')
print(f'{vul_len} of those devices are vulnerable due to lack of EDR.')
print('A report of the vulnerable devices has been generated in your "Documents" folder.')
