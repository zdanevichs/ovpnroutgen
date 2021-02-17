#!/usr/bin/python3
# coding=utf-8
#################################################################################
#Скрипт для перенаправления траффика определенных доменов через openvpn тонель. #
#                          http://www.zdanevich.ru                              #
#################################################################################
# MIT License                                                                   #
#                                                                               #
# Copyright (c) 2021 Sergei Zdanevich                                           #
#                                                                               #
# Permission is hereby granted, free of charge, to any person obtaining a copy  #
# of this software and associated documentation files (the "Software"), to deal #
# in the Software without restriction, including without limitation the rights  #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     #
# copies of the Software, and to permit persons to whom the Software is         #
# furnished to do so, subject to the following conditions:                      #
#                                                                               #    
# The above copyright notice and this permission notice shall be included in all#
# copies or substantial portions of the Software.                               #
#                                                                               #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE #
# SOFTWARE.                                                                     #
#################################################################################
import sys, os, socket, dns.resolver, sqlite3, random
from netaddr import IPAddress, cidr_merge
from datetime import datetime, timedelta

upd=datetime.now() #Текущее время
days_storage=2 #Сколько дней хранить IP в БД
configfile='/etc/openvpn/rusvpn.conf' #Путь к файлу конфигурации openvpn
cert='/etc/openvpn/rusvpn.crt' #Путь к файлу сертификата openvpn
key='/etc/openvpn/rusvpn.key' #Путь к файлу ключа openvpn
ca='/etc/openvpn/rusvpn_ca.crt' #Путь к файлу сертификата openvpn
vpns=['ru22.rvpn.ws','ru25.rvpn.ws','ru28.rvpn.ws','ru29.rvpn.ws','ru31.rvpn.ws','ru33.rvpn.ws','ru35.rvpn.ws'] #Адреса VPN серверов 
domains = ["googleapis.l.google.com", "play.google.com", "android.l.google.com"] #Домены траффик на которые необходимо направлять в тонель openvpn
servers = ["10.77.0.1", "8.8.8.8", "77.88.8.8", "1.1.1.1"] #IP адреса DNS серверов с которых получать ip адреса для указанных доменов.

conn = sqlite3.connect('ips.db') 
cur = conn.cursor()
#Создаем БД, если отсутствует
cur.execute("""CREATE TABLE IF NOT EXISTS ips(
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   ip TEXT,
   domain TEXT,
   data timestamp,
   CONSTRAINT ip_unique UNIQUE (ip));
""")

#Получает все данные из БД
def get_all_data(conn,cur):
    cur.execute("SELECT ip,domain,data FROM ips;")
    return cur.fetchall()

#Добавляет отсутствующую запись БД
def add_data(conn,cur,data):
    try:
        cur.execute("INSERT INTO ips(ip,domain,data) VALUES ('{0}','{1}','{2}')".format(data[0],data[1],data[2]))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Ошибка добавления в базу IP {}. Запись существует.".format(data[0]))
    return cur.fetchall()

#Обновляет запись в БД
def add_upd(conn,cur,data):
    cur.execute("UPDATE ips SET ip='{0}',domain='{1}',data='{2}' WHERE ip='{0}'".format(data[0],data[1],data[2]))
    conn.commit()
    return cur.fetchall()

def del_old(conn,cur):
    cur.execute("DELETE FROM ips WHERE data <= '{0}'".format(datetime.now()-timedelta(days=days_storage)))
    conn.commit()
    return cur.fetchall()

#Получает все IP адреса от указанных DNS серверов для конкретных доменов
def get_dns_ip(domains,servers):
    result=list()
    for domain in domains:
        for server in servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(server)]
                resolver.timeout = 1
                resolver.lifetime = 1
                answer = resolver.query(domain, 'A')
                for rdata in answer :
                    result.append((rdata.address,domain,datetime.now()))
            except:
                print ("Ошибка получения списка IP. Домен: {0} DNS: {1}".format(domain, server))
    return result

#Функция добавляет в базу данных новые значения и обновляет существующие
def update_db(data):
    for k,v,d in data:
        dublicate=False
        result = get_all_data(conn,cur)
        for dbk,dbv,dbd in result:
            if k == dbk:
                dublicate=True
        if dublicate==True:
            add_upd(conn,cur,(k,v,d))
        else:
            add_data(conn,cur,(k,v,d))
    return get_all_data(conn,cur)

#Формирует текст для конфига
def gen_conf(networks, servers, cert, key, ca):
    total="#Total routes: {}\n".format(len(networks))
    networks=['route ' + str(k.ip) + ' ' + str(k.netmask) for k in networks]
    config='''client
dev tun
proto udp
remote {0} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 4
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ping 15
ping-restart 0
ping-timer-rem
reneg-sec 0
pull
fast-io
cipher AES-256-CBC
route-nopull
'''.format(random.choice(vpns))
    config=config+total
    config=config + '\n'.join(networks) + '\n\n'
    with open(ca) as ca:
        config = config + '<ca>\n' + ca.read() + '</ca>\n\n'
    with open(cert) as cert:
        config = config + '<cert>\n' + cert.read() + '</cert>\n\n'
    with open(key) as key:
        config = config + '<key>\n' + key.read() + '</key>\n\n'

    return config

del_old(conn,cur) #Удаляем старые IP из БД
get_dns = get_dns_ip(domains, servers) #Получаем список IP от DNS
db=update_db(get_dns) #Обновляем список адресов в БД
iplist=[IPAddress(k.strip()) for k,v,d in db]
netlist=cidr_merge(iplist) #Суммируем IP в подсети, где это возможно (для уменьшения кол-ва маршрутов)
config=gen_conf(netlist, servers, cert, key, ca) #Формируем конфиг
with open(configfile, 'w') as configfile: 
    configfile.write(config)

os.system('systemctl restart openvpn@rusvpn') #Перезапускаем сервис


