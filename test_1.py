#!/usr/bin/env python
# """Module docstring."""

# Imports
from netmiko import ConnectHandler
import csv
import logging
import datetime
import multiprocessing as mp
import difflib
import filecmp
import sys
import io
import os
import textfsm
import re


# Module 'Global' variables
DEVICE_FILE_PATH = 'test_2.csv'  # file should contain a list of devices in format: ip,username,password,device_type
BACKUP_DIR_PATH = 'test1_backups'  # complete path to backup directory



def enable_logging():
    # This function enables netmiko logging for reference

    logging.basicConfig(filename='test.log', level=logging.DEBUG)
    logger = logging.getLogger("netmiko")


def get_devices_from_file(device_file):
    # This function takes a CSV file with inventory and creates a python list of dictionaries out of it
    # Each disctionary contains information about a single device

    # creating empty structures
    device_list = list()
    device = dict()

    # reading a CSV file with ',' as a delimeter
    with open(device_file, 'r') as f:
        reader = csv.DictReader(f, delimiter=',')

        # every device represented by single row which is a dictionary object with keys equal to column names.
        for row in reader:
            device_list.append(row)

    print("Got the device list from inventory")
    print('-*-' * 10)
    print()

    # returning a list of dictionaries
    return device_list


def get_current_date_and_time():
    # This function returns the current date and time
    now = datetime.datetime.now()

    print("Got a timestamp")
    print('-*-' * 10)
    print()

    # Returning a formatted date string
    # Format: yyyy_mm_dd-hh_mm_ss
    return now.strftime("%Y_%m_%d-%H_%M_%S")


def connect_to_device(device):
    # This function opens a connection to the device using Netmiko
    # Requires a device dictionary as an input

    # Since there is a 'hostname' key, this dictionary can't be used as is
    connection = ConnectHandler(
        host=device['ip'],
        username=device['username'],
        password=device['password'],
        device_type=device['device_type'],
        secret=device['secret']
    )

    print('Opened connection to ' + device['ip'])
    print('-*-' * 10)
    print()

    # returns a "connection" object
    return connection


def disconnect_from_device(connection, hostname):
    # This function terminates the connection to the device

    connection.disconnect()
    print('Connection to device {} terminated'.format(hostname))


def get_backup_file_path(hostname, timestamp):
    # This function creates a backup file name (a string)
    # backup file path structure is hostname/hostname-yyyy_mm_dd-hh_mm

    # checking if backup directory exists for the device, creating it if not present
    if not os.path.exists(os.path.join(BACKUP_DIR_PATH, hostname)):
        os.mkdir(os.path.join(BACKUP_DIR_PATH, hostname))

    # Merging a string to form a full backup file name
    backup_file_path = os.path.join(BACKUP_DIR_PATH, hostname, '{}-{}.txt'.format(hostname, timestamp))
    print('Backup file path will be ' + backup_file_path)
    print('-*-' * 10)
    print()

    # returning backup file path
    return backup_file_path


def create_backup(connection, backup_file_path, hostname):
    # This function pulls running configuration from a device and writes it to the backup file
    # Requires connection object, backup file path and a device hostname as an input

    try:
        # sending a CLI command using Netmiko and printing an output
        connection.enable()
        output = connection.send_command('sh run')

        # creating a backup file and writing command output to it
        with open(backup_file_path, 'w') as file:
            file.write(output)
        print("Backup of " + hostname + " is complete!")
        print('-*-' * 10)
        print()

        # if successfully done
        return True

    except Error:
        # if there was an error
        print('Error! Unable to backup device ' + hostname)
        return False

def parse_show_cdp_neighbors(cli_return):
    template = io.StringIO("""\
Value Numofneighbor (\d+)

Start
  ^Total.*\s:\s${Numofneighbor} -> Record
    """)
    fsm = textfsm.TextFSM(template)
    result = fsm.ParseText(cli_return)
    ret = result[0][0]
    return ret



def check_cdp(connection, hostname):
    # This function check cdp

    try:
        # sending a CLI command using Netmiko and printing an output
        # connection.enable() already had
        output = connection.send_command('show cdp neighbors')

        # parse output

        if re.search('CDP is not enabled', output):
            ret = "CDP is OFF"
        else:
            cdp_parse_out = parse_show_cdp_neighbors(output)
            ret = "CDP is ON, " + cdp_parse_out + " peers"

        print("check cdp on " + hostname + " is complete!")
        print('-*-' * 10)
        print()

        # if successfully done
        return [True, ret]

    except Error:
        # if there was an error
        print('Error! Unable to check cdp on device ' + hostname)
        return [False,"Unable to check cdp"]


def parse_show_verion(cli_return):
    template = io.StringIO("""\
Value IOS_MODEL_VER ([\w]+)
Value IOS_NAME ([\w\.-]+)
Value IOS_VER ([\w\.\(\)]+)
Value MODEL_VER ([\w-]+)
Value HOST_NAME ([\w-]+)

Start
  ^Cisco\sIOS\sSoftware,\s${IOS_MODEL_VER}\sSoftware\s\(${IOS_NAME}\),\sVersion\s${IOS_VER},.*$$ -> Record
  ^Cisco\s${MODEL_VER}\s.* -> Record
  ^${HOST_NAME}\suptime\sis\s.* -> Record
    """)
    fsm = textfsm.TextFSM(template)
    result = fsm.ParseText(cli_return)
    ret = {}
    ret['ios_model'] = result[0][0]
    ret['ios_name'] = result[0][1]
    ret['ios_ver'] = result[0][2]
    ret['model'] = result[2][3]
    ret['hostname'] = result[1][4]
    return ret

def check_ver(connection, hostname):
    # This function check version

    try:
        # sending a CLI command using Netmiko and printing an output
        # connection.enable() already had
        output = connection.send_command('show version')

        # parse output

        ver_parse_out = parse_show_verion(output)
        ret = f"{ver_parse_out['hostname']:<10} | {ver_parse_out['model']:<7} | {ver_parse_out['ios_ver']:<15}"

        if re.search('_NPE', ver_parse_out['ios_name']):
            ret += " | NPE   "
        else:
            ret += " | PE    "

        print("check version on " + hostname + " is complete!")
        print('-*-' * 10)
        print()

        # if successfully done
        return [True, ret]

    except Error:
        # if there was an error
        print('Error! Unable to check version on device ' + hostname)
        return [False, "Unable to check version"]



def check_timezone(connection, hostname, ntp_addr):
    # This function check timezone

    try:
        # sending a CLI command using Netmiko and printing an output
        # connection.enable() already had
        output = connection.send_command('show clock detail')

        need_to_setup_timezone = True
        need_to_setup_NTP = True
        # parse output
        if re.search('GMT', output):
            need_to_setup_timezone = False
        if re.search('Time source is NTP', output):
            need_to_setup_NTP = False

        if need_to_setup_timezone:
            connection.send_config_set('clock timezone GMT + 0')
        if need_to_setup_NTP:
            output = connection.send_command(f'ping {ntp_addr}')
            if re.search('Success rate is 0 percent', output):
                print (f'NTP {ntp_addr} is unreachable. No reason to setup it.')
            else:
                connection.send_config_set(f'ntp server {ntp_addr}')

        print("check timezone and clock source on " + hostname + " is complete!")
        print('-*-' * 10)
        print()

        # if successfully done
        return [True, "timezone and ntp ok"]

    except Error:
        # if there was an error
        print('Error! Unable to check ntp on device ' + hostname)
        return [False,"Unable to check ntp"]


def check_ntp(connection, hostname):
    # This function check ntp

    try:
        # sending a CLI command using Netmiko and printing an output
        # connection.enable() already had
        output = connection.send_command('show ntp status')

        # parse output
        if re.search('Clock is synchronized', output):
            ret = "Clock in Sync"
        elif re.search('Clock is unsynchronized', output):
            ret = "Clock in Unsync"
        elif re.search('NTP is not enabled', output):
            ret = "NTP is not enabled."
        else:
            ret = "Clock state is UNKNOWN"

        print("check ntp on " + hostname + " is complete!")
        print('-*-' * 10)
        print()

        # if successfully done
        return [True, ret]

    except Error:
        # if there was an error
        print('Error! Unable to check ntp on device ' + hostname)
        return [False,"Unable to check ntp"]



def get_previous_backup_file_path(hostname, curent_backup_file_path):
    # This function looks for the previous backup file in a directory
    # Requires a hostname and the latest backup file name as an input

    # removing the full path
    current_backup_filename = curent_backup_file_path.split('/')[-1]

    # creatting an empty dictionary to keep backup file names
    backup_files = {}

    # looking for previous backup files
    for file_name in os.listdir(os.path.join(BACKUP_DIR_PATH, hostname)):

        # select files with correct extension and names
        if file_name.endswith('.txt') and file_name != current_backup_filename:
            # getting backup date and time from filename
            filename_datetime = datetime.datetime.strptime(file_name.strip('.txt')[len(hostname) + 1:],
                                                           '%Y_%m_%d-%H_%M_%S')

            # adding backup files to dict with key equal to datetime in unix format
            backup_files[filename_datetime.strftime('%Y%m%d%H%M%S')] = file_name

    if len(backup_files) > 1:

        # getting the previous backup filename
        previous_backup_key = sorted(backup_files.keys(), reverse=True)[1]
        previous_backup_file_path = os.path.join(BACKUP_DIR_PATH, hostname, backup_files[previous_backup_key])

        print("Found a previous backup ", previous_backup_file_path)
        print('-*-' * 10)
        print()

        # returning the previous backup file
        return previous_backup_file_path
    else:
        return False


def compare_backup_with_previous_config(previous_backup_file_path, backup_file_path):
    # This function compares created backup with the previous one and writes delta to the changelog file
    # Requires a path to last backup file and a path to the previous backup file as an input

    # creating a name for changelog file
    changes_file_path = backup_file_path.rstrip(".txt") + ".changes"

    # checking if files differ from each other
    if not filecmp.cmp(previous_backup_file_path, backup_file_path):
        print('Comparing configs:')
        print('\tCurrent backup: {}'.format(backup_file_path))
        print('\tPrevious backup: {}'.format(previous_backup_file_path))
        print('\tChanges: {}'.format(changes_file_path))
        print('-*-' * 10)
        print()

        # if they do differ, open files in read mode and open changelog in write mode
        with open(previous_backup_file_path, 'r') as f1, open(backup_file_path, 'r') as f2, open(changes_file_path,'w') as f3:
            # looking for delta
            delta = difflib.unified_diff(f1.read().splitlines(), f2.read().splitlines())
            # writing discovered delta to the changelog file
            f3.write('\n'.join(delta))
        print('\tConfig state: changed')
        print('-*-' * 10)
        print()

    else:
        print('Config was not changed since the latest version.')
        print('-*-' * 10)
        print()


def process_target(device, timestamp):
    # This function will be run by each of the processes in parallel
    # This function implements a logic for a single device using other functions defined above:
    #  - connects to the device,
    #  - gets a backup file name and a hostname for this device,
    #  - creates a backup for this device
    #  - terminates connection
    #  - compares a backup to the golden configuration and logs the delta
    # Requires connection object and a timestamp string as an input


    connection = connect_to_device(device)

    backup_file_path = get_backup_file_path(device['hostname'], timestamp)
    backup_result = create_backup(connection, backup_file_path, device['hostname'])

    # получим hostname, тип устройства, версию ПО, NPE/PE
    ver_result = check_ver(connection, device['hostname'])
    if not ver_result[0]:
        disconnect_from_device(connection, device['hostname'])
        print(ver_result[1])
        return
    # получим количество CDP соседей
    cdp_result = check_cdp(connection, device['hostname'])
    if not cdp_result[0]:
        disconnect_from_device(connection, device['hostname'])
        print(cdp_result[1])
        return

    # Проверим Timezone и установим GMT+0
    timezone_result = check_timezone(connection, device['hostname'], device['ntp_addr'])
    if not timezone_result[0]:
        disconnect_from_device(connection, device['hostname'])
        print(timezone_result[1])
        return

    # получим NTP статус
    ntp_result = check_ntp(connection, device['hostname'])
    if not ntp_result[0]:
        disconnect_from_device(connection, device['hostname'])
        print(ntp_result[1])
        return



    disconnect_from_device(connection, device['hostname'])

    # if the script managed to create a backup, then look for a previous one
    if backup_result:
        previous_backup_file_path = get_previous_backup_file_path(device['hostname'], backup_file_path)

        # if the previous one exists, compare
        if previous_backup_file_path:
            compare_backup_with_previous_config(previous_backup_file_path, backup_file_path)
        else:
            print('Unable to find previos backup file to find changes.')
            print('-*-' * 10)
            print()

    # Формируем вывод в виде:
    # Имя  устройства - тип устройства - версия ПО - NPE / PE - CDP  on / off, X peers - NTP in  sync / not sync.
    # Пример:
    # ms-gw-01 | ISR4451 / K9 | BLD_V154_3_S_XE313_THROTTLE_LATEST | PE | CDP is ON, 5    peers | Clock in Sync
    # ms-gw-02 | ISR4451 / K9 | BLD_V154_3_S_XE313_THROTTLE_LATEST | NPE | CDP is ON, 0    peers | Clock in Sync

    # формируем вывод
    # return str(ver_result[1] + " | " + cdp_result[1] + " | " + ntp_result[1])
    return f"{ver_result[1]} | {cdp_result[1]:<10} | {ntp_result[1]:<22} |"

def main(*args):
    # This is a main function

    # Enable logs
    enable_logging()

    # getting the timestamp string
    timestamp = get_current_date_and_time()

    # getting a device list from the file in a python format
    device_list = get_devices_from_file(DEVICE_FILE_PATH)

    # creating a empty list
    processes = list()

    # Running workers to manage connections
    with mp.Pool(5) as pool:
        # Starting several processes...
        for device in device_list:
            processes.append(pool.apply_async(process_target, args=(device, timestamp)))
        # Waiting for results...
        ret_test = {}
        for process in processes:
            ret_test[process] = process.get()
        # Выведем результаты
        print("-" * 95)
        print("Hostname   | Type    | IOS version     | PE/NPE | CDP Neighbors      | NTP state              |")
        print("-" * 95)
        for process in processes:
            print(ret_test[process])
        print("-" * 95)

if __name__ == '__main__':
    # checking if we run independently
    _, *script_args = sys.argv

    # the execution starts here
    main(*script_args)


