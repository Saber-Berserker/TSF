#!/usr/bin/env python

from mininet.node import OVSSwitch, OVSBridge
from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        switch_num = 11
        legacy_switch_num = 1
        host_num = 10

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
        self.addLink(r[1], switches[1])  # r1 - s1
        self.addLink(r[1], switches[8])  # r1 - s8

        self.addLink(switches[1], switches[2])  # s1  - s2
        self.addLink(switches[1], switches[3])  # s1  - s3
        self.addLink(switches[2], switches[4])  # s2  - s4
        self.addLink(switches[2], switches[5])  # s2  - s5
        self.addLink(switches[3], switches[6])  # s3  - s6
        self.addLink(switches[3], switches[7])  # s3  - s7

        self.addLink(switches[8], switches[9])  # s8  - s9
        self.addLink(switches[8], switches[10])  # s8  - s10
        self.addLink(switches[9], switches[11])  # s9  - s11

        self.addLink(r[1], hosts[10])            # r1  - h10
        self.addLink(switches[1], hosts[1])      # s1  - h1
        self.addLink(switches[4], hosts[2])      # s4  - h2
        self.addLink(switches[5], hosts[3])      # s5  - h3
        self.addLink(switches[6], hosts[4])      # s6  - h4
        self.addLink(switches[7], hosts[5])      # s7  - h5
        self.addLink(switches[8], hosts[6])      # s8  - h6
        self.addLink(switches[9], hosts[7])      # s9 - h7
        self.addLink(switches[11], hosts[8])     # s11 - h8
        self.addLink(switches[11], hosts[9])     # s11 - h9


topos = {'mytopo': (lambda: MyTopo())}

