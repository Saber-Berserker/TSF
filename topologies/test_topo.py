#!/usr/bin/env python

from mininet.node import OVSSwitch, OVSBridge
from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        switch_num = 1
        legacy_switch_num = 0
        host_num = 1

        switches = ['']
        hosts = ['']
        r = ['']

        # Add hosts
        for i in range(host_num):
            ip = "10.0.0.{}/24".format(i + 1)
            # mac = "00:00:00:00:00:{:02x}".format(i + 1)
            # host = net.addHost('h{}'.format(i), ip=ip, mac=mac, defaultRoute=None)
            host = self.addHost('h{}'.format(i + 1), ip=ip, defaultRoute=None)
            hosts.append(host)

        # Add switches
        for i in range(switch_num):
            dpid = "00000000000000{:02d}".format(i + 1)
            management_ip = "10.0.1.{}/24".format(i + 1)
            switch = self.addSwitch('s{}'.format(i + 1), dpid=dpid, ip=management_ip, cls=OVSSwitch, protocols='OpenFlow13')
            switches.append(switch)

        for i in range(legacy_switch_num):
            legacy_switch = self.addSwitch('r{}'.format(legacy_switch_num + i + 1), cls=OVSBridge)
            r.append(legacy_switch)

        # Add links, asymmetric topology

        self.addLink(switches[1], hosts[1])      # s1  - h1



topos = {'mytopo': (lambda: MyTopo())}

