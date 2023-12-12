#!/usr/bin/python3

import typing
import pyshark
from pyshark.packet.packet import Packet
import datetime

CMD_ID = {'0x01': "Route request",
          '0x02': "Route reply",
          '0x03': "Network Status",
          '0x04': "Leave",
          '0x05': "Route Record",
          '0x06': "Rejoin request",
          '0x07': "Rejoin response",
          '0x08': "Link Status",
          '0x09': "Network Report",
          '0x0a': "Network Update",
          '0x0b': "End Device Timeout Request",
          '0x0c': "End Device Timeout Response",
          '0x0d': "Link Power Delta",
          # quick fix, pyshark 0.4 uses 1-byte ids
          #            pyshark 0.6 uses 4-byte
          '0x00000001': "Route request",
          '0x00000002': "Route reply",
          '0x00000003': "Network Status",
          '0x00000004': "Leave",
          '0x00000005': "Route Record",
          '0x00000006': "Rejoin request",
          '0x00000007': "Rejoin response",
          '0x00000008': "Link Status",
          '0x00000009': "Network Report",
          '0x0000000a': "Network Update",
          '0x0000000b': "End Device Timeout Request",
          '0x0000000c': "End Device Timeout Response",
          '0x0000000d': "Link Power Delta",}

DEVICE_ADDR = {
    '0x037f': "temp1",
    '0x21ff': "contact2",
    '0x5fa9': "plug1",
    '0x7e3f': "contact1",
    '0x8396': "temp2",
    '0xc287': "plug2",
    '0xdb4b': "water",
    '0x0000': "hub",
    '0xffff': "wpanBdcst",
    '0xfffc': "zbeeBdcst",
    # quick fix, pyshark 0.4 uses 2-bytes to represent 2-byte addresses
    #            pyshark 0.6 uses 4-bytes to represent 2-byte addresses...
    '0x0000037f': "temp1",
    '0x000021ff': "contact2",
    '0x00005fa9': "plug1",
    '0x00007e3f': "contact1",
    '0x00008396': "temp2",
    '0x0000c287': "plug2",
    '0x0000db4b': "water",
    '0x00000000': "hub",
    '0x0000ffff': "wpanBdcst",
    '0x0000fffc': "zbeeBdcst",
}

DEBUG = False

def processCapture(fileName:str):
    cap = pyshark.FileCapture(fileName, display_filter="wpan") # IEEE 802.15.4
    packets:list[Packet] = []

    # pyshark is really slow and no random access
    # buffer the packets so we can work them faster from memory
    _numPySharkPackets = 0
    for p in cap:
        _numPySharkPackets += 1
        packets.append(p)

        # print packets processed so far, every 100 packets
        _packetInterval = 100
        if _numPySharkPackets % _packetInterval == 0:
            print(_numPySharkPackets)
        if DEBUG and _numPySharkPackets == 500: break # stop it early for testing

    print(f'\nNumber of Packets buffered: {len(packets)}')

    # now that they're buffered, do something interesting
    firstPacketTime = packets[0].sniff_time
    lastPacketTime = packets[len(packets)-1].sniff_time
    timeDelta = lastPacketTime - firstPacketTime
    print(f'Loaded {fileName}')
    print(f'First ZigBeeCaptured packet captured at {firstPacketTime}')
    print(f'Last at {lastPacketTime}')
    print(f'Capture lasted {timeDelta}\n')
    print(f'Please be patient while packets are processed')

    layerSet = set() # all layers seen, from link to application
    highest_layerSet = set() # only count the highest layer seen from each packet
    srcSetWPAN = set() # WPAN and ZBEE_NWK addresses should all pretty much be the same
    dstSetWPAN = set()
    srcSetZBEE_NWK = set()
    dstSetZBEE_NWK = set()
    addrSet:set # set later as the union of the above sets
    cmdSet = set() # all zbee_nwk commands seen
    linkSet = set() # all link addresses (from link status commands) seen

    trafficSizeWPANSent: dict # thought of as total traffic that passed through a device
    trafficSizeWPANReceived: dict
    trafficSizeSourced: dict # specify that the traffic was not relayed (originated at that device)
    trafficSizeRelayed: dict # specify that the traffic was relayed
    linkStatusPackets = list()
    linkStatusByAddr: dict # per-device links seen
    deviceLinkStatuses : dict # per-device links reported, in terms of packets
    deviceReports : dict # per-device zbee_aps reports, in terms of overall sequences, not packets
    cmdCount : dict # how many times a command was used
    cmdByAddr : dict # how many times each device issued any command
    apsPackets = list()

    for p in packets:
        for l in p.layers:
            layerSet.add(l.layer_name)

        if hasattr(p, 'wpan'):
            if hasattr(p.wpan, 'dst16'):
                dstSetWPAN.add(p.wpan.dst16)
            if hasattr(p.wpan, 'src16'):
                srcSetWPAN.add(p.wpan.src16)

        if hasattr(p, 'zbee_nwk'):
            if hasattr(p.zbee_nwk, 'dst'):
                dstSetZBEE_NWK.add(p.zbee_nwk.dst)
            if hasattr(p.zbee_nwk, 'src'):
                srcSetZBEE_NWK.add(p.zbee_nwk.src)
        
        if hasattr(p, 'zbee_aps'):
            apsPackets.append(p)

        highest_layerSet.add(p.highest_layer)
        if p.highest_layer == 'ZBEE_NWK':
            if hasattr(p.zbee_nwk, 'cmd_id'):
                cmdSet.add(p.zbee_nwk.cmd_id)
                if p.zbee_nwk.cmd_id == '0x08': # link status command
                    linkStatusPackets.append(p)
                    linkSet.add(p.zbee_nwk.cmd_link_address) # unfortunately, only shows first link in list, not all

    srcSet = srcSetWPAN.union(dstSetZBEE_NWK)
    dstSet = dstSetWPAN.union(dstSetZBEE_NWK)
    addrSet = srcSet.union(dstSet)

    # generate map of device addresses to traffic in [bytes, packets] pairs
    trafficSizeWPANSent = dict({addr : [0,0] for addr in addrSet})
    trafficSizeWPANReceived = dict({addr : [0,0] for addr in addrSet})
    trafficSizeSourced = dict({addr : [0,0] for addr in addrSet})
    trafficSizeRelayed = dict({addr : [0,0] for addr in addrSet})
    cmdCount = dict({cmd : 0 for cmd in CMD_ID})

    # maps to pairs of [reports sent, list of timestamps]
    deviceLinkStatuses = dict({addr : [0, []] for addr in addrSet})
    deviceReports = dict({addr : [0, []] for addr in addrSet})

    # now that we know what addresses are in the capture, go through again to associate traffic with each address
    for p in packets:
        # count traffic
        if hasattr(p, 'wpan') and hasattr(p.wpan, 'dst16') and hasattr(p.wpan, 'src16'):
            trafficSizeWPANSent[p.wpan.src16][0] += int(p.length)
            trafficSizeWPANSent[p.wpan.src16][1] += 1

            trafficSizeWPANReceived[p.wpan.dst16][0] += int(p.length)
            trafficSizeWPANReceived[p.wpan.dst16][1] += 1

            if hasattr(p, 'zbee_nwk') and hasattr(p.zbee_nwk, 'src') and hasattr(p.zbee_nwk, 'dst'):
                if p.wpan.src16 == p.zbee_nwk.src or (p.wpan.src16 == '0xffff' and p.zbee_nwk.src == '0xfffc'): # wpan and zbee use different broadcast address, but mean the same thing
                    trafficSizeSourced[p.zbee_nwk.src][0] += int(p.length)
                    trafficSizeSourced[p.zbee_nwk.src][1] += 1
                else : # relayed that packet, credit goes to wpan address
                    trafficSizeRelayed[p.wpan.src16][0] += int(p.length)
                    trafficSizeRelayed[p.wpan.src16][1] += 1

                # if p.wpan.dst16 == p.zbee_nwk.dst or (p.wpan.dst16 == '0xffff' and p.zbee_nwk.dst == '0xfffc'):
                #     trafficSizeSourced[p.zbee_nwk.dst][0] += int(p.length)
                #     trafficSizeSourced[p.zbee_nwk.dst][1] += 1
                # else: # relayed
                #     trafficSizeRelayed[p.wpan.dst16][0] += int(p.length)
                #     trafficSizeRelayed[p.wpan.dst16][1] += 1 

        # count commands issued
        if hasattr(p, 'zbee_nwk') and hasattr(p.zbee_nwk, 'cmd_id'):
                cmdCount[p.zbee_nwk.cmd_id] += 1

    # record the links each device saw
    linkStatusByAddr = dict.fromkeys(addrSet, set())
    for p in linkStatusPackets:
        if hasattr(p.zbee_nwk, 'cmd_link_address'):
            linkStatusByAddr[p.wpan.src16].add(p.zbee_nwk.cmd_link_address)

    # count link status packets sent, and timestamps
    for p in linkStatusPackets:
        if hasattr(p, 'zbee_nwk') and hasattr(p.zbee_nwk, 'cmd_id'):
            if (p.zbee_nwk.src == p.wpan.src16):
                deviceLinkStatuses[p.zbee_nwk.src][0] += 1
                deviceLinkStatuses[p.zbee_nwk.src][1].append(p.sniff_time)

    # count sequences of zcl responses, and timestamps
    lastSeq = -1
    for p in apsPackets:
        if hasattr(p, 'zbee_zcl') and hasattr(p.zbee_zcl, 'cmd_tsn'):
            # device reports usually are several messages in a row
            # we want to only count the first
            # only count if its a new sequence and its not relayed
            if (int(p.zbee_zcl.cmd_tsn) != lastSeq + 1 and p.zbee_nwk.src == p.wpan.src16):   
                lastSeq = int(p.zbee_zcl.cmd_tsn)          
                deviceReports[p.zbee_nwk.src][0] += 1      
                deviceReports[p.zbee_nwk.src][1].append(p.sniff_time)
            elif (int(p.zbee_zcl.cmd_tsn) == lastSeq + 1 and p.zbee_nwk.src == p.wpan.src16):
                lastSeq = int(p.zbee_zcl.cmd_tsn) # still need to increment the seq counter, even if we want to ignore it

    # record what commands each device issued
    cmdByAddr = dict.fromkeys(addrSet, set())
    for p in packets:
        if hasattr(p, 'zbee_nwk') and hasattr(p.zbee_nwk, 'cmd_id'):
            cmdByAddr[p.wpan.src16].add(p.zbee_nwk.cmd_id)


    ###### Pretty Print the Results ######
    print(f'layerSet {layerSet}')
    print(f'highest_layerSet {highest_layerSet}\n')

    # print(f'srcSet {srcSet}')
    # print(f'dstSet {dstSet}\n')
    print(f'Devices:')
    for addr in addrSet:
        print(f'  {DEVICE_ADDR.get(addr, "Special")}: {addr}')
    print()

    print(f'cmdSet', end="{")
    for cmd in cmdSet:
        print(f'{cmd}: {CMD_ID.get(cmd, None)}, ', end=" ")
    print("}")
    for addr in cmdByAddr:
        print(f'  {addr} Cmds: {cmdByAddr[addr]}')
    totalCommands = 0
    for x in cmdCount:
        totalCommands += cmdCount[x]
    print(f'Commands issued {totalCommands}:')
    for cmd in cmdCount:
        if cmdCount[cmd] > 0:
            print(f'  {CMD_ID.get(cmd, cmd)}: {cmdCount[cmd]} ({cmdCount[cmd]/totalCommands*100}%)')
    print()

    print(f'linkSet {linkSet} (unfortunately, pyshark only shows one link per status packet. In reality, most broadcast at least two...)')
    for addr in linkStatusByAddr:
        print(f'  {addr} Links: {linkStatusByAddr[addr]}')
    print(f'{len(linkStatusPackets)} / {len(packets)} packets were link statuses ({len(linkStatusPackets)/len(packets)*100}%)\n')

    print(f'Total traffic in [bytes, packets] (sending and recieving combined, plus packets relayed):')
    print(f'Note that this double-counts the sender and reciever, and does not include WPAN acks, which have no addresses')
    print(f'It is also possible for a device to send a WPAN packet without any ZigBee layers')
    print(f'  device'.ljust(20) + f'Sourced'.ljust(20) + f'Relayed'.ljust(20) + f'Total WPAN Sent'.ljust(20) + f'Total WPAN Received')
    for addr in sorted(trafficSizeWPANSent, key=trafficSizeWPANSent.get, reverse=True):
        print(f'  {DEVICE_ADDR.get(addr, addr)}:'.ljust(20) + f'{trafficSizeSourced[addr]}'.ljust(20) + f'{trafficSizeRelayed[addr]}'.ljust(20) + f'{trafficSizeWPANSent[addr]}'.ljust(20) + f'{trafficSizeWPANReceived[addr]}')
    print()

    print(f'Link Status Updates by Device:')
    print(f'  Device'.ljust(12) + f'# of Reports'.ljust(20) + f'Average Interval')
    for addr in sorted(deviceLinkStatuses, key=deviceLinkStatuses.get, reverse=True):
        sum = datetime.timedelta()
        avg = datetime.timedelta()
        if len(deviceLinkStatuses[addr][1]) > 1:
            for i in range(1, len(deviceLinkStatuses[addr][1])):
                sum += deviceLinkStatuses[addr][1][i] - deviceLinkStatuses[addr][1][i-1]
            avg = sum/(len(deviceLinkStatuses[addr][1])-1)

        if (deviceLinkStatuses[addr][0] > 0):
            print(f'  {DEVICE_ADDR.get(addr, addr)}:'.ljust(12) + f'{deviceLinkStatuses[addr][0]}'.ljust(20) + f'{avg}')
    print()

    print(f'Device ZCL (application layer) reports:')
    print(f'  Device'.ljust(12) + f'# of Reports'.ljust(20) + f'Average Interval')
    for addr in sorted(deviceReports, key=deviceReports.get, reverse=True):
        sum = datetime.timedelta()
        avg = datetime.timedelta()
        if len(deviceReports[addr][1]) > 1:
            for i in range(1, len(deviceReports[addr][1])):
                sum += deviceReports[addr][1][i] - deviceReports[addr][1][i-1]
            avg = sum/(len(deviceReports[addr][1])-1)

        if (deviceReports[addr][0] > 0):
            print(f'  {DEVICE_ADDR.get(addr, addr)}:'.ljust(12) + f'{deviceReports[addr][0]}'.ljust(20) + f'{avg}')

if __name__ == '__main__':
    processCapture('1017.pcapng')
    print(f'\n##### Press enter for the next file #####')
    input()
    processCapture('1208.pcapng')
    print(f'\n##### Press enter for the next file #####')
    input()
    processCapture('1208-2.pcapng')
    print(f'\n##### Press enter for the next file #####')
    input()
    processCapture('1209.pcapng')
