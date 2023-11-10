import tkinter 
from tkinter import ttk
import pyshark
from threading import Thread
import re
import socket
import os
import subprocess
import tempfile
import sys
import dpkt
from datetime import datetime
from scapy.all import PcapWriter, raw
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import textwrap



Tshark_path = "C:\\Program Files\\Wireshark\\tshark.exe" 

# string换行, 默认为48个字符
def wrap(string, lenght=48):
    return '\n'.join(textwrap.wrap(string, lenght))

def passFilter(packet, filter_text):
    if packet.transport_layer == filter_text or filter_text == "":
        return True
    else:
        if hasattr(packet, "ip"):
            src = packet.ip.src
            dst = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src = packet.ipv6.src
            dst = packet.ipv6.dst
        else:
            return False
        # [ip.src = \"{src}\", ip.dst = \"{dst}\", tcp.srcport = \"{src_port}\", tcp.dstport = \"{dst_port}\"]
        src_list = re.compile("ip.src = \"([0-9\.\:a-zA-Z]*?)\"").findall(str(filter_text))
        dst_list = re.compile("ip.dst = \"([0-9\.\:a-zA-Z]*?)\"").findall(str(filter_text))
        for i in range(0, min(len(src_list), len(dst_list))):
            if src_list[i] == str(src) and dst_list[i] == str(dst):
                return True
    return False

class Sniffer:
    def __init__(self, master):
        self.master = master
        self.master.title("A Simple Sniffer")
        self.init()

    def init(self):
        self.packets = []
        self.running = False  
        self.interface = tkinter.StringVar()
        self.filter_text = tkinter.StringVar()
        self.filter = ""

        top_frame = ttk.Frame(self.master)
        top_frame.pack(side='top', fill='both', expand=False)
        middle_frame = ttk.Frame(self.master)
        middle_frame.pack(side='top', fill='both', expand=True)
        bottom_frame = ttk.Frame(self.master)
        bottom_frame.pack(side='bottom', fill='both', expand=True)
        bottom_left_frame = ttk.Frame(bottom_frame)
        bottom_left_frame.pack(side='left', fill='both', expand=True)
        bottom_right_frame = ttk.Frame(bottom_frame)
        bottom_right_frame.pack(side='right', fill='both', expand=True)

        interface_label = ttk.Label(top_frame, text="Interface:")
        interface_label.pack(side='left')
        interface_entry = ttk.Entry(top_frame, textvariable=self.interface)
        interface_entry.pack(side='left')

        filter_label = ttk.Label(top_frame, text="Filter:")
        filter_label.pack(side='left')
        filter_entry = ttk.Entry(top_frame, textvariable=self.filter_text)
        filter_entry.pack(side='left')

        self.start_or_stop_button = ttk.Button(top_frame, text="Start", command=self.startOrStop)
        self.start_or_stop_button.pack(side='left')
        filter_button = ttk.Button(top_frame, text="Filter", command=self.applyFilter)
        filter_button.pack(side='left')
        trace_button = ttk.Button(top_frame, text="Trace", command=self.trace)
        trace_button.pack(side='left')
        clear_button = ttk.Button(top_frame, text="Clear", command=self.clear)
        clear_button.pack(side='left')

        self.current_filter_label = ttk.Label(top_frame, text=f"current_filter:{self.filter}")
        self.current_filter_label.pack(side='left')
        

        self.packet_list = ttk.Treeview(middle_frame)
        self.packet_list["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Info")
        self.packet_list.column("#0", width=0, stretch=0)
        for column in self.packet_list["columns"]:
            self.packet_list.heading(column, text=column, anchor='w')

        self.packet_list.bind("<<TreeviewSelect>>", self.onPacketCliCk)
        self.packet_list.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(middle_frame, command=self.packet_list.yview)
        scrollbar.pack(side='right', fill='y')
        self.packet_list.configure(yscrollcommand=scrollbar.set)


        self.packet_info = ttk.Treeview(bottom_left_frame)
        self.packet_info["columns"] = ("value")

        self.packet_info.heading("#0", text="Field", anchor='w')
        self.packet_info.heading("value", text="Value", anchor='w')
        self.packet_info.pack(side='left', fill='both', expand=True)


        self.data = tkinter.Text(bottom_right_frame, wrap='word')
        self.data.pack(side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(bottom_right_frame, command=self.data.yview)
        scrollbar.pack(side='right', fill='y')
        self.data.configure(yscrollcommand=scrollbar.set)

    def startOrStop(self):
        if not self.running:
            self.running = True
            self.start_or_stop_button.config(text="Stop")
            self.packet_list.delete(*self.packet_list.get_children())
            self.packet_info.delete(*self.packet_info.get_children())
            self.data.delete("1.0", tkinter.END)
            self.capture = pyshark.LiveCapture(
                interface=self.interface.get(),
                tshark_path=Tshark_path,
                use_json=True,
                include_raw=True
            )

            self.capture_thread = Thread(target=self.run)
            self.capture_thread.daemon = True
            self.capture_thread.start()
        
        else:
            self.running = False  
            self.start_or_stop_button.config(text="Start")
            if hasattr(self, "capture"):
                self.capture.close()
            if hasattr(self, "capture_thread"):
                self.capture_thread.join()

    def run(self):
        while self.running:
            try:
                self.capture.apply_on_packets(self.handlePacket, packet_count=1)
            except Exception as e:
                print(f"Error while capturing packet: {str(e)}")

    def handlePacket(self, packet):
        self.packets.append(packet)
        if passFilter(packet, self.filter):
            self.showPacket(packet)

    def clear(self):
        self.packet_list.delete(*self.packet_list.get_children())
        self.packets.clear()
        self.filter = ""
        self.filter_text.set("")
        self.current_filter_label.config(text=f"current_filter:{self.filter}")
        self.packet_info.delete(*self.packet_info.get_children())
        self.data.delete("1.0", tkinter.END)

    def applyFilter(self):
        self.filter = self.filter_text.get()
        self.current_filter_label.config(text=f"current_filter:{self.filter}")
        self.packet_list.delete(*self.packet_list.get_children())
        self.packet_info.delete(*self.packet_info.get_children())
        self.data.delete("1.0", tkinter.END)

        for packet in self.packets:
            if passFilter(packet, self.filter):
                self.showPacket(packet)


    def showPacket(self, packet):
        protocol = getattr(packet, "transport_layer", "")

        if protocol == "TCP":
            packet_info = f"Seq={packet.tcp.seq}, Ack={packet.tcp.ack}, Win={packet.tcp.window_size}"
        elif protocol == "UDP":
            packet_info = f"Src Port={packet.udp.srcport}, Dst Port={packet.udp.dstport}"
        elif protocol == "ICMP":
            packet_info = f"Type={packet.icmp.type}, Code={packet.icmp.code}"
        elif protocol == "HTTP":
            packet_info = f"Request Method={packet.http.request_method}, URI={packet.http.request_uri}"
        elif protocol == "ARP":
            packet_info = f"Opcode={packet.arp.opcode}, Sender MAC={packet.arp.src_hw_mac}, Sender IP={packet.arp.src_proto_ipv4}, Target MAC={packet.arp.dst_hw_mac}, Target IP={packet.arp.dst_proto_ipv4}"
        elif protocol == None or "":
            return 
        else:
            packet_info = "unsupported protocol"

        value = []
        value.append(len(self.packet_list.get_children()) + 1)
        value.append(datetime.fromtimestamp(packet.sniff_time.timestamp()).strftime("%Y-%m-%d %H:%M:%S.%f"))
        if hasattr(packet, "ip"):
            src = packet.ip.src
            dst = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src = packet.ipv6.src
            dst = packet.ipv6.dst
        else:
            src = ""
            dst = ""
        value.append(src)
        value.append(dst)
        value.append(protocol)
        value.append(packet_info)

        self.packet_list.insert("", tkinter.END, values=tuple(value))

    def onPacketCliCk(self, event):
        item = self.packet_list.set(self.packet_list.focus())
        self.current_packet = self.packets[int(item["No."]) - 1]

        self.showPacketInfo()
        self.showData()

    def showPacketInfo(self):
        self.packet_info.delete(*self.packet_info.get_children())
        fields = ["eth", "ip", "tcp", "udp", "http", "dns", "arp"]

        for field in fields:
            if hasattr(self.current_packet, field):
                field_name = self.packet_info.insert("", tkinter.END, text=field)
                field = getattr(self.current_packet, field)
                for field_text in field.field_names:
                    field_value = getattr(field, field_text)
                    field_text = str(field_text)
                    if field_text[-3:] == "raw":
                        continue
                    # 下面两行可以删掉，影响不大
                    if type(field_value) == list:
                        field_value = field_value[0]
                    try:
                        temp = str(field_value)
                    except:
                        continue
                    self.packet_info.insert(field_name, tkinter.END, text=field_text, values=field_value)

    def showData(self):
        self.data.delete("1.0", tkinter.END)
        data = raw(Ether(self.current_packet.get_raw_packet()))
        hex_data = " ".join("{:02X}".format(byte) for byte in data)
        self.data.insert(tkinter.END, wrap(hex_data))


    def trace(self):
        self.packet_info.delete(*self.packet_info.get_children())
        self.data.delete("1.0", tkinter.END)
        if hasattr(self.current_packet, "ip"):
            src = self.current_packet.ip.src
            dst = self.current_packet.ip.dst
        elif hasattr(self.current_packet, "ipv6"):
            src = self.current_packet.ipv6.src
            dst = self.current_packet.ipv6.dst
        text = f"[ip.src = \"{src}\", ip.dst = \"{dst}\" || ip.src = \"{dst}\", ip.dst = \"{src}\"]"
        self.filter_text.set(text)
        self.applyFilter()



def main():
    root = tkinter.Tk()
    app = Sniffer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
