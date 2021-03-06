#!/usr/bin/env python

import subprocess
import time

import mysql.connector
from mysql.connector import Error

import logmanager
import portmanagerlib
import os, re, threading
import Queue
import multiprocessing
import esc_queue

port_manager = portmanagerlib.PortManager()
log_m = logmanager.LogManager()
log = log_m.logger()

HOST_IP = '34.215.95.184'
count = 0
ip_list=[]
ip_status={}


#ip class, concurrent pings for all active sessions
class ip_check(threading.Thread):
    def __init__ (self,ip, ip_dict):
        threading.Thread.__init__(self)
        self.ip = ip
        self.__successful_pings = -1
        self.ip_data = ip_dict

    def run(self):
        ping_out = os.popen("ping -q -c2 "+self.ip,"r")
        while True:
            line = ping_out.readline()
            if not line: break
            n_received = re.findall(received_packages,line)
            if n_received:
                self.__successful_pings = int(n_received[0])
                self.ip_data[self.ip] = "UP" 
                if self.__successful_pings == 0:
      #Temp fix
                    if "100.61.0.6" == str(self.ip):
                      self.ip_data[self.ip] = "DOWN"
                    else:
                      self.ip_data[self.ip] = "UP"

    def status(self):
        if self.__successful_pings == 0:
            return "no response"
        elif self.__successful_pings == 1:
            return "alive, but 50 % package loss"
        elif self.__successful_pings == 2:
            return "alive"
        else:
            return "shouldn't occur"

received_packages = re.compile(r"(\d) received")

def ping_response(ip_list, ip_dict):
    check_results = []
    for ip in ip_list:
        current = ip_check(ip, ip_dict)
        check_results.append(current)
        current.start()

    for el in check_results:
        el.join()

# connect to MySql server
def connect():
    try:
        conn = mysql.connector.connect(host=HOST_IP, database='escdb', user='escmonit', password='passcode')
        if conn.is_connected():
            return conn
        else:
            log.warn("Error in connection")

    except Error as e:
        print(e)


# MySQL update query esc_tbl;
def mysql_query_update_esc_tbl(status, count1, esc_name):
    log.info("Update esc_tbl %s, %s" %(status, esc_name))
    conn = connect()
    cursor = conn.cursor()
    sql = "UPDATE esc_tbl SET CommStatus='%s', HeartBeatCount=%d WHERE esc_name='%s'" %(status, count1, esc_name)
    cursor.execute(sql)
    conn.commit()
    conn.close()
    cursor.close()

def mysql_query_update_like_esc_tbl(status, count1, local_ip):
    conn = connect()
    cursor = conn.cursor()
    sql = "UPDATE esc_tbl SET CommStatus='%s', HeartBeatCount=%d WHERE LocalIp='%s'" %(status, count1, local_ip)
    cursor.execute(sql)
    conn.commit()
    conn.close()
    cursor.close()


# MySQL select * from esc_tbl
def mysql_query_select_esc_tbl_with_ping(q):
    del ip_list[:]
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM esc_tbl")
    row = cursor.fetchone()
    while row is not None:
        # [u'esc_sn01', 36149, 39122, u'100.61.0.26', u'174.228.132.14', datetime.datetime(2017, 11, 8, 19, 35, 24), u'UP',
        # u'6']
        address = (list(row)[3])
        ip_list.append(address)
        ip_status[str(address)]="UP"
        row = cursor.fetchone()

    ping_response(ip_list, ip_status)
    #q.put(ip_status)
    #print(q.qsize())
    cursor.close()
    conn.close()
    return ip_status


# MySql select query to fetch the esc table information
def mysql_query_select_esc_tbl():
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM esc_tbl")
    row = cursor.fetchone()
    while row is not None:
        row = cursor.fetchone()
    row_count = cursor.rowcount
    cursor.close()
    conn.close()

    return row_count


#update ssh ports after application initialization
def mysql_update_ssh_ports(sessions):
    log.debug("invoke mysql_update_ssh_ports")
    conn = connect()
    cursor = conn.cursor()
    for item in sessions:
      session = sessions[item]
      esc_name = (str(session['username']))
      log.debug(esc_name)
    sql = "UPDATE ESC_DEPLOY_INFO SET sshPort=%d WHERE escName='%s'" % (0, esc_name)
    cursor.execute(sql)
    conn.commit()
    conn.close()
    cursor.close()

# MySQL select query the esc deploy table to return port number
def mysql_query_port_no(esc_name):
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * from ESC_DEPLOY_INFO WHERE escName='%s'" % esc_name
    cursor.execute(query)
    row = cursor.fetchone()
    # decode the row and assign ssh port
    # [8, u'esc_sn015', u'FL005', 1, 72900015, 10000]
    ssh_port = (list(row)[5])
    if ssh_port == 0:
        # assign SSH port number
        ssh_port = port_manager.getNextAvailablePort()
    else:
        ssh_port = port_manager.getNextAvailablePort()

    sql = "UPDATE ESC_DEPLOY_INFO SET sshPort=%d WHERE escName='%s'" % (ssh_port, esc_name)
    cursor.execute(sql)
    conn.commit()

    conn.close()
    cursor.close()
    return ssh_port

def mysql_fetch_query_port_no(esc_name):
    log.info("[%s] invoke mysql_fetch_query_port_no" %(esc_name))
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * from ESC_DEPLOY_INFO WHERE escName='%s'" % esc_name
    cursor.execute(query)
    row = cursor.fetchone()
    # decode the row and assign ssh port
    # [8, u'esc_sn015', u'FL005', 1, 72900015, 10000]
    ssh_port = (list(row)[5])
    conn.close()
    cursor.close()
    return ssh_port


def mysql_query_reset_port_no(esc_name):
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * from ESC_DEPLOY_INFO WHERE escName='%s'" % esc_name
    cursor.execute(query)
    row = cursor.fetchone()
    # decode the row and assign ssh port
    # [8, u'esc_sn015', u'FL005', 1, 72900015, 10000]
    ssh_port = (list(row)[5])
    if ssh_port != 0:
      sql = "UPDATE ESC_DEPLOY_INFO SET sshPort=%d WHERE escName='%s'" % (0, esc_name)
      cursor.execute(sql)
      conn.commit()

    conn.close()
    cursor.close()
    return ssh_port

def mysql_query_local_ip(esc_name):
    log.info("[%s] invoke mysql_query_local_ip" %(esc_name))
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * from esc_tbl WHERE esc_name='%s'" % esc_name
    cursor.execute(query)
    row = cursor.fetchone()
    local_ip = (list(row)[3])
    log.info("[%s] retrieve ip %s" %(esc_name, local_ip))
    conn.close()
    cursor.close()
    return local_ip 




# MySQL query to update the esc table
def mysql_update_query(sessions, hbeat_count):
    conn = connect()
    cursor = conn.cursor()
    for item in sessions:
        session = sessions[item]
        if session is None:
            continue
        sql = "UPDATE esc_tbl SET LocalIp='%s', TxBytes=%d, RxBytes=%d, lastConnection='%s', HeartBeatCount=%d WHERE esc_name='%s'" % (
            str(session['local_ip']), int(session['bytes_sent']), int(session['bytes_recv']), session['connected_since'], hbeat_count,
            session['username'])
        cursor.execute(sql)
        conn.commit()
    conn.close()
    cursor.close()


# MySQL insert esc table
def mysql_insert_query(sessions, flag):
    conn = connect()
    cursor = conn.cursor()
    for item in sessions:
        session = sessions[item]
        if flag:
            esc_queue.esc_thread_handler(session['username'], session['city'])
        sql = "INSERT INTO esc_tbl VALUES('%s', '%d', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s')" % ( session['username'], int(session['bytes_sent']), int(session['bytes_recv']), session['local_ip'], session['remote_ip'], session['connected_since'], "UP", 0,'v1.0', 'v1.0')
        cursor.execute(sql)
        conn.commit()
    conn.close()
    cursor.close()

def mysql_new_insert_query(session):
    conn = connect()
    cursor = conn.cursor()
    esc_queue.esc_thread_handler(session['username'], session['city'])
    sql = "INSERT INTO esc_tbl VALUES('%s', '%d', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s')" % ( session['username'], int(session['bytes_sent']), int(session['bytes_recv']), session['local_ip'], session['remote_ip'], session['connected_since'], "UP", 0,'v1.0', 'v1.0')
    cursor.execute(sql)
    conn.commit()
    conn.close()
    cursor.close()



# MySQL update status in deploy table
def mysql_update_deploy_status(status, esc_i_d):
    conn = connect()
    cursor = conn.cursor()
    sql = "UPDATE ESC_DEPLOY_INFO SET deployStatus=%d WHERE esc_name='%s'" % (status, esc_i_d)
    cursor.execute(sql)
    conn.commit()
    conn.close()
    cursor.close()


# MySQL query to fetch the siteId and Label no from Deploy table
def mysql_select_deploy_list(esc_name):
    deploy_list = []

    conn = connect()
    cursor = conn.cursor()
    sql = "SELECT * FROM ESC_DEPLOY_INFO WHERE escName LIKE '%s'" % (esc_name)
    cursor.execute(sql)
    row = cursor.fetchone()
    while row is not None:
        deploy_list.append(list(row)[2])
        deploy_list.append(list(row)[4])
        break
    cursor.close()
    conn.close()

    log.debug(deploy_list)
    return deploy_list


def mysql_query_esc_tbl(sessions):
    print("Invoke mysql_query_esc_tbl()")
    new_list=[]
    conn = connect()
    cursor = conn.cursor()
    for item in sessions:
      print(item)
      session = sessions[item] 
      esc_name = str(session['username'])
      sql = "SELECT * FROM esc_tbl WHERE esc_name LIKE '%s'" % (esc_name)
      cursor.execute(sql)
      row = cursor.fetchone()
      while row is None:
          print(list(row))
          new_list.append()
          row = cursor.fetchone()

      cursor.close()
      conn.close()
      return new_list


# MySQL get deploy status
def mysql_get_deploy_status(esc_i_d):
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * from ESC_DEPLOY_INFO WHERE escName='%s'" % (esc_i_d)
    cursor.execute(query)
    row = cursor.fetchone()
    # [8, u'esc_sn015', u'FL005', 1, 72900015, 10000]
    deploy_status = (list(row)[3])
    conn.close()
    cursor.close()
    return deploy_status


# insert query into heart beat table
def insert_query_to_hbeat_tbl(esc_name, heart_beat, hb_count, op_state, admin_state, flag):
    if flag == 1:
        conn = connect()
        cursor = conn.cursor()
        datecmd = time.strftime('%Y-%m-%d %H:%M:%S')
        sql = "INSERT INTO esc_hbeat_tbl VALUES('%s', '%s', '%d', '%s', '%s', '%s')" % (
            esc_name, heart_beat, hb_count, op_state, admin_state, datecmd)
        cursor.execute(sql)
        conn.commit()
        conn.close()
        cursor.close()
