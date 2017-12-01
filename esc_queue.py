#!/usr/bin/env python

import Queue
import threading
import time

import logmanager
import snmp_stat as snmp
import mysql_queries as mysql
import trap_v2c as snmp_trap

log_m = logmanager.LogManager()
log = log_m.logger()
heart_beat_counter = 0
heart_beat_dict = {'esc_sn030': 0, 'esc_sn01':0,'esc_sn015':0,'esc_sn023':0,'esc_sn026':0,'esc_sn029':0,'esc_sn08':0,'esc_sn014':0, 'esc_sn024':0}

esc_sn01_Q = Queue.Queue(100)
esc_sn015_Q = Queue.Queue(100)
esc_sn023_Q = Queue.Queue(100)
esc_sn026_Q = Queue.Queue(100)
esc_sn029_Q = Queue.Queue(100)
esc_sn08_Q = Queue.Queue(100)
esc_sn014_Q = Queue.Queue(100)
esc_sn024_Q = Queue.Queue(100)
esc_sn030_Q = Queue.Queue(100)

thread_list = []


# sensor id is different because it is coming from ESC, where as
# other id is from openvpn
#=====o======o=====o======o=====o======o=====o======o=====
def put_data_into_queue(username, data):
    get_idx = username[8:12]
    esc_q = 'esc_sn' + get_idx + '_Q'
    eval(esc_q).put(data)


#=====o======o=====o======o=====o======o=====o======o=====
def esc_thread_handler(username, city):
    q_thread = username + "__q_thread"
    esc_worker = threading.Thread(name=username, target=eval(q_thread), args=(username,))
    esc_worker.setDaemon = True
    esc_worker.start()


# o==================================o====================================o================================
# ESC SN 029
# o==================================o====================================o================================
def esc_sn029_handler(username):
    count = 0
    long(count)
    log.debug("Timer invoked esc_sn029_handler every 15sec")
    if esc_sn029_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn029, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(29, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        count = count + 1
        log.debug('Fetch data from esc_sn029_Q')
        esc_sn029_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        mysql.mysql_query_update_esc_tbl("UP", count, username)
        snmp.snmp_set_operations(29, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn029_Q.task_done()

def esc_sn029__q_thread(username):
    log.info("Created esc_sn029__q_thread")
    thread_list.append(username)
    while True:
        t = threading.Timer(15.0, esc_sn029_handler, args=(username,))
        log.debug("Starting esc_sn029__q_thread timer")
        t.setName("esc_sn029__q_thread")
        t.start() #after 15 seconds, trigger esc_sn029_handler
        time.sleep(15)
        t.cancel()

# o==================================o====================================o================================
# ESC SN 026
# o==================================o====================================o================================
def esc_sn026_handler(username):
    count = 0
    long(count)
    log.debug("Timer invoked esc_sn026_handler every 15sec")
    if esc_sn026_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn026, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(26, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        count = count + 1
        log.debug('Fetch data from esc_sn026_Q')
        esc_sn026_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        snmp.snmp_set_operations(26, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        mysql.mysql_query_update_esc_tbl("UP", count, username)
        esc_sn026_Q.task_done()

def esc_sn026__q_thread(username):
    log.debug("Created esc_sn026__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn026_handler, args=(username,))
        t2.setName("esc_sn026__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn029_handler
        time.sleep(15)
        t2.cancel()

# o==================================o====================================o================================
# ESC SN 024
# o==================================o====================================o================================
def esc_sn024_handler(username):
    count = 0
    log.debug("Timer invoked esc_sn024_handler every 15sec")
    if esc_sn024_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn024, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(24, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        log.debug('Fetch data from esc_sn024_Q')
        esc_sn024_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        snmp.snmp_set_operations(24, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn024_Q.task_done()

def esc_sn024__q_thread(username):
    log.debug("Created esc_sn024__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn024_handler, args=(username,))
        t2.setName("esc_sn024__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn024_handler
        time.sleep(15)
        t2.cancel()


# o==================================o====================================o================================
# ESC SN 023
# o==================================o====================================o================================
def esc_sn023_handler(username):
    count = 0
    log.debug("Timer invoked esc_sn023_handler every 15sec")
    if esc_sn023_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn023, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(23, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        log.debug('Fetch data from esc_sn023_Q')
        esc_sn023_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        snmp.snmp_set_operations(23, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn023_Q.task_done()

#
def esc_sn023__q_thread(username):
    log.debug("Created esc_sn023__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn023_handler, args=(username,))
        t2.setName("esc_sn023__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn023_handler
        time.sleep(15)
        t2.cancel()

# o==================================o====================================o================================
# ESC SN 015
# o==================================o====================================o================================
def esc_sn015_handler(username):
    count = 0
    log.debug("Timer invoked esc_sn015_handler every 15sec")
    if esc_sn015_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn015, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(15, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        log.debug('Fetch data from esc_sn015_Q')
        esc_sn015_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        snmp.snmp_set_operations(15, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn015_Q.task_done()

#
def esc_sn015__q_thread(username):
    log.debug("Created esc_sn015__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn015_handler, args=(username,))
        t2.setName("esc_sn015__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn015_handler
        time.sleep(15)
        t2.cancel()


# o==================================o====================================o================================
# ESC SN 014
# o==================================o====================================o================================
def esc_sn014_handler(username):
    count = 0
    long(count)
    log.debug("Timer invoked esc_sn014_handler every 15sec")
    if esc_sn014_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn014, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(14, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        count = count + 1
        log.debug('Fetch data from esc_sn015_Q')
        esc_sn014_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        mysql.mysql_query_update_esc_tbl("UP", count, username)
        snmp.snmp_set_operations(14, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn014_Q.task_done()

#
def esc_sn014__q_thread(username):
    log.debug("Created esc_sn014__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn014_handler, args=(username,))
        t2.setName("esc_sn014__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn014_handler
        time.sleep(15)
        t2.cancel()



# o==================================o====================================o================================
# ESC SN 08
# o==================================o====================================o================================
def esc_sn08_handler(username):
    count = 0
    log.debug("Timer invoked esc_sn08_handler every 15sec")
    if esc_sn08_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn08, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(8, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        log.debug('Fetch data from esc_sn08_Q')
        esc_sn08_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        snmp.snmp_set_operations(8, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn08_Q.task_done()

#
def esc_sn08__q_thread(username):
    log.debug("Created esc_sn08__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn08_handler, args=(username,))
        t2.setName("esc_sn08__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn08_handler
        time.sleep(15)
        t2.cancel()


# o==================================o====================================o================================
# ESC SN 01
# o==================================o====================================o================================
def esc_sn01_handler(username):
    count = 0
    long(count)
    log.debug("Timer invoked esc_sn01_handler every 15sec")
    if esc_sn01_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn01, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(1, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        count = count + 1
        log.debug('Fetch data from esc_sn01_Q')
        esc_sn01_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        mysql.mysql_query_update_esc_tbl("UP", count, username)
        snmp.snmp_set_operations(1, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn01_Q.task_done()

#
def esc_sn01__q_thread(username):
    log.debug("Created esc_sn01__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn01_handler, args=(username,))
        t2.setName("esc_sn01__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn01_handler
        time.sleep(15)
        t2.cancel()
# o==================================o====================================o================================
# ESC SN 30
# o==================================o====================================o================================
def esc_sn030_handler(username):
    count = 0
    long(count)
    log.debug("Timer invoked esc_sn030_handler every 15sec")
    if esc_sn030_Q.empty():
        heart_beat_counter = heart_beat_dict[username]
        if heart_beat_counter == 3:
            log.warn("No heart beat detected for esc_sn030, raise a trap")
            #insert_query_to_hbeat_tbl(username, "DOWN", count, "IN-ACTIVE", "DISABLE", 1)
            snmp.snmp_set_operations(1, "IN-ACTIVE", "ARLINGTON", 1, "DISABLE")
            snmp_trap.trigger_trap("No heartbeat detected")
            heart_beat_dict[username] = 0
        else:
            heart_beat_counter = heart_beat_counter + 1
            heart_beat_dict[username] = heart_beat_counter
    else:
        count = count + 1
        log.debug('Fetch data from esc_sn030_Q')
        esc_sn030_Q.get(True, 15)
        #insert_query_to_hbeat_tbl(username, "UP", count, "ACTIVE", "ENABLE", 1)
        mysql.mysql_query_update_esc_tbl("UP", count, username)
        snmp.snmp_set_operations(1, "ACTIVE", "ARLINGTON", 1, "ENABLE")
        esc_sn030_Q.task_done()

#
def esc_sn030__q_thread(username):
    log.debug("Created esc_sn01__q_thread")
    thread_list.append(username)
    while True:
        t2 = threading.Timer(15.0, esc_sn030_handler, args=(username,))
        t2.setName("esc_sn030__q_thread")
        t2.start() #after 15 seconds, trigger esc_sn030_handler
        time.sleep(15)
        t2.cancel()

