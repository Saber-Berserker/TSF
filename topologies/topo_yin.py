#!/usr/bin/python

from mininet.node import OVSBridge
from mininet.node import OVSSwitch
from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        switch_num = 6
        lagacySwitch_num = 2
        host_num = 6

        s = ['']
        h = ['']
        r = ['']

        for i in range(switch_num):
            dpid = "000000000000000{}".format(i + 1)
            management_ip = "192.168.16.{}/24".format(100 + i + 1)
            switch = self.addSwitch('s{}'.format(i + 1), dpid=dpid, ip=management_ip, cls=OVSSwitch, protocols='OpenFlow13')
            s.append(switch)

        for i in range(host_num):
            ip = "192.168.16.{}/24".format(i + 1)
            mac = "00:00:00:00:00:{:02x}".format(i + 1)
            host = self.addHost('h{}'.format(i + 1), ip=ip, mac=mac, defaultRoute=None)
            h.append(host)

        for i in range(lagacySwitch_num):
            legacy_switch = self.addSwitch('r{}'.format(switch_num + i + 1), cls=OVSBridge)
            r.append(legacy_switch)

        self.addLink(s[1], h[2])
        self.addLink(r[1], h[1])
        self.addLink(r[1], s[1])
        self.addLink(s[1], s[3])
        self.addLink(s[2], s[3])
        self.addLink(s[2], h[3])
        self.addLink(s[3], s[4])
        self.addLink(s[4], r[2])
        self.addLink(r[2], h[4])
        self.addLink(r[2], s[5])
        self.addLink(s[5], h[5])
        self.addLink(s[5], s[6])
        self.addLink(s[6], h[6])


topos = {'mytopo': (lambda: MyTopo())}

