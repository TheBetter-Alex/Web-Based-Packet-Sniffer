import threading
import queue
import time
from datetime import datetime
from typing import Optional

from scapy.all import AsyncSniffer, get_if_list, conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from scapy.packet import Packet
    
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from st_aggrid import AgGrid, GridOptionsBuilder
from scapy.utils import wrpcap


class PacketSnifferThread(threading.Thread):
    def __init__(self, iface: Optional[str], bpf_filter: str, q: queue.Queue):
        super().__init__(daemon=True)
        self.iface = iface
        self.bpf_filter = bpf_filter       # <-- unified name
        self.q = q
        self._sniffer: Optional[AsyncSniffer] = None
        self._stop = threading.Event()
        self.dropped_packets = 0

    def _enqueue(self, pkt: Packet):
        timestamp = getattr(pkt, 'time', time.time())
        try:
            self.q.put_nowait((pkt, timestamp))
        except queue.Full:
            pass

    def run(self):
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            store=False,
            prn=self._enqueue,
            filter=self.bpf_filter or None,   # <-- use unified attr
            promisc=True,
        )
        self._sniffer.start()
        while not self._stop.is_set():
            time.sleep(0.05)
        try:
            self._sniffer.stop()
        except Exception:
            self.dropped_packets += 1

    def stop(self):
        self._stop.set()

class Handler:
    def __init__(self):
        self.packets = []
        self.all_packets = []
        self.q = queue.Queue(maxsize=1000)
        self.sniffer_thread = None
        self.max_packets = 3000
        self.index = 0
    
    def create_packet_dict(self, pkt):
        packet_dict = {}
        if not pkt:
            return None
        if Ether in pkt:
            eth = pkt[Ether]
            packet_dict['Ethernet'] = {
                'src': eth.src,
                'dst': eth.dst,
                'type': eth.type,
            }
        if IP in pkt:
            ip = pkt[IP]
            packet_dict['IP'] = {
                'src': ip.src,
                'dst': ip.dst,
                'version': ip.version,
                'ihl': ip.ihl,
                'tos': ip.tos,
                'len': ip.len,
                'id': ip.id,
                'flags': ip.flags,
                'frag': ip.frag,
                'ttl': ip.ttl,
                'proto': ip.proto,
                'chksum': ip.chksum,
            }
        if TCP in pkt:
            tcp = pkt[TCP]
            packet_dict['TCP'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'dataofs': tcp.dataofs,
                'reserved': tcp.reserved,
                'flags': tcp.flags,
                'window': tcp.window,
                'chksum': tcp.chksum,
                'urgptr': tcp.urgptr,
            }
        if UDP in pkt:
            udp = pkt[UDP]
            packet_dict['UDP'] = {
                'sport': udp.sport,
                'dport': udp.dport,
                'len': udp.len,
                'chksum': udp.chksum,
            }
        if ICMP in pkt:
            icmp = pkt[ICMP]
            packet_dict['ICMP'] = {
                'type': icmp.type,
                'code': icmp.code,
                'chksum': icmp.chksum,
                'id': icmp.id,
                'seq': icmp.seq,
            }
        if ARP in pkt:
            arp = pkt[ARP]
            packet_dict['ARP'] = {
                'hwtype': arp.hwtype,
                'ptype': arp.ptype,
                'hwlen': arp.hwlen,
                'plen': arp.plen,
                'op': arp.op,
                'hwsrc': arp.hwsrc,
                'psrc': arp.psrc,
                'hwdst': arp.hwdst,
                'pdst': arp.pdst,
            }
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            packet_dict['DNS'] = {
                'id': dns.id,
                'qr': dns.qr,
                'opcode': dns.opcode,
                'qdcount': dns.qdcount,
                'ancount': dns.ancount,
                'nscount': dns.nscount,
                'arcount': dns.arcount,
                'query': dns.qd.qname.decode() if dns.qd else None
            }
            answers = []

            for i in range(dns.ancount):
                ans = dns.an[i]
                if ans.type == 1:  # A record
                    answers.append({'Type': 'A', 'IP': ans.rdata})
                elif ans.type == 5:  # CNAME record
                    answers.append({'Type': 'CNAME', 'Alias': ans.rdata.decode()})
            if answers:
                packet_dict['DNS']['Answers'] = answers

        elif pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            packet_dict['HTTP'] = {
                'Method': http.Method.decode(),
                'Host': http.Host.decode(),
                'Path': http.Path.decode()
            }
        elif pkt.haslayer(HTTPResponse):
            http = pkt[HTTPResponse]
            packet_dict['HTTP'] = {
                'Status_Code': http.Status_Code.decode(),
                'Reason_Phrase': http.Reason_Phrase.decode()
            }
        
        elif pkt.haslayer(TLS):
            tls = pkt[TLS]
            tls_info = {'version': tls.version}
            if tls.haslayer(TLSClientHello):
                ch = tls[TLSClientHello]
                tls_info['type'] = 'ClientHello'
                tls_info['cipher_suites'] = ch.cipher_suites
            elif tls.haslayer(TLSServerHello):
                sh = tls[TLSServerHello]
                tls_info['type'] = 'ServerHello'
                tls_info['cipher_suite'] = sh.cipher_suite
            packet_dict['TLS'] = tls_info

        elif pkt.haslayer(Raw):
            raw = pkt[Raw]
            try:
                payload = raw.load.decode(errors="ignore")
                packet_dict['Raw'] = {'payload': payload}
            except Exception:
                packet_dict['Raw'] = {'payload': str(raw.load)}

        
        return packet_dict

    def summarize_packet(self, pkt, ts):
        
        proto = ""; src = ""; dst = ""; info = ""; length = 0
        time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        try:
            length = len(bytes(pkt))
        except Exception:
            pass
        try:
            if HTTPRequest in pkt:
                proto = "HTTP"
                http = pkt[HTTPRequest]
                src = pkt[IP].src if IP in pkt else "?"
                dst = pkt[IP].dst if IP in pkt else "?"
                info = f"{http.Method.decode()} {http.Path.decode()}"
            elif HTTPResponse in pkt:
                proto = "HTTP"
                http = pkt[HTTPResponse]
                src = pkt[IP].src if IP in pkt else "?"
                dst = pkt[IP].dst if IP in pkt else "?"
                info = f"{http.Status_Code.decode()} {http.Reason_Phrase.decode()}"
            
            elif DNS in pkt:
                proto = "DNS"
                dns = pkt[DNS]
                src = pkt[IP].src if IP in pkt else "?"
                dst = pkt[IP].dst if IP in pkt else "?"
                if dns.qr == 0 and dns.qdcount > 0:
                    qname = dns.qd.qname.decode() if dns.qd else "?"
                    info = f"Query: {qname}"
                elif dns.qr == 1 and dns.ancount > 0:
                    anames = []
                    for i in range(dns.ancount):
                        ans = dns.an[i]
                        if isinstance(ans, DNSRR):
                            anames.append(ans.rrname.decode())
                    info = f"Response: {', '.join(anames)}"
                
            elif TLS in pkt:
                proto = "HTTPS/TLS"
                src = pkt[IP].src if IP in pkt else "?"
                dst = pkt[IP].dst if IP in pkt else "?"
                tls = pkt[TLS]
                if tls.haslayer(TLSClientHello):
                    proto = "TLS ClientHello"
                    info = f"Cipher Suites: {tls[TLSClientHello].cipher_suites}"
                elif tls.haslayer(TLSServerHello):
                    proto = "TLS ServerHello"
                    info = f"Cipher Suite: {tls[TLSServerHello].cipher_suite}"

            elif ARP in pkt:
                proto = "ARP"
                psrc = getattr(pkt[ARP], 'psrc', "?")
                pdst = getattr(pkt[ARP], 'pdst', "?")
                op = getattr(pkt[ARP], 'op', 0)
                src, dst = psrc, pdst
                info = f"who-has {pdst} tell {psrc}" if op == 1 else f"{psrc} is-at …"
            elif IP in pkt:
                proto = "IP"
                src, dst = pkt[IP].src, pkt[IP].dst
                if ICMP in pkt:
                    proto = "ICMP"
                    info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
                elif TCP in pkt:
                    
                    proto = "TCP"
                    t = pkt[TCP]
                    info = f"{t.sport} → {t.dport} [flags={t.flags}]"
                elif UDP in pkt:
                    proto = "UDP"
                    u = pkt[UDP]
                    info = f"{u.sport} → {u.dport}"
            elif Ether in pkt:
                proto = "Ethernet"
                src = pkt[Ether].src
                dst = pkt[Ether].dst
            else:
                proto = getattr(pkt, 'name', 'Frame')
        except Exception:
            pass

        return {
            "No": self.index,
            "Time": time_str,
            "Source": src,
            "Destination": dst,
            "Protocol": proto,
            "Length": length,
            "Info": info,
            "_ts": ts,
            "_pkt": pkt,
        }
    
    def drain_queue(self):
        handled_packets = 0
        while not self.q.empty() and handled_packets < 2000:
            pkt, ts = self.q.get()
            self.packets.append(self.summarize_packet(pkt, ts)) 
            self.all_packets.append(pkt)
            self.index += 1
            handled_packets += 1

        if len(self.packets) > self.max_packets:
            self.packets = self.packets[-self.max_packets:]

    def get_packet_from_no(self, packet_no):
        for p in self.packets:
            if p['No'] == packet_no:
                return p['_pkt']
        return None
    
    def save_packets_to_pcap(self, filename: str):
        
        wrpcap(filename, self.all_packets)

class StreamlitUI:
    def __init__(self):
        st.set_page_config(page_title="Packet Viewer (Streamlit + Scapy)", layout="wide")
        self.ss = st.session_state

        self.ss.setdefault('Handler', Handler())
        self.ss.setdefault('Sniffer', None)
        self.ss.setdefault('iface', get_if_list()[4])
        self.ss.setdefault('bpf', "")
        self.ss.setdefault("running", False)
        self.ss.setdefault("auto_refresh", 2000)

    def setup_sniffer(self):
        pass

    def sidebar_controls(self):
        st.sidebar.header("Controls")

        self.ss.iface = st.sidebar.selectbox("Network Interface", options=get_if_list(), index=get_if_list().index(self.ss.iface))

        self.ss.bpf = st.sidebar.text_input("BPF Filter", value=self.ss.bpf)

        self.ss.auto_refresh = st.sidebar.slider("Auto-refresh Interval (ms)", min_value=500, max_value=10000, value=self.ss.auto_refresh, step=500)

        col1, col2 = st.sidebar.columns(2)
        start_clicked = col1.button("▶ Start", width="stretch", disabled=self.ss.running, key="btn_start")
        stop_clicked  = col2.button("⏸ Stop",  width="stretch", disabled=not self.ss.running, key="btn_stop")

        key_save = st.sidebar.button("💾 Save to PCAP", width="stretch", disabled=not self.ss.Handler.all_packets, key="btn_save")
        if key_save:
            filename = f"captured_packets_{int(time.time())}.pcap"
            self.ss.Handler.save_packets_to_pcap(filename)
            st.sidebar.success(f"Saved packets to {filename}")

        return start_clicked, stop_clicked

    def start_stop_logic(self, start_clicked: bool, stop_clicked: bool):

        if start_clicked and not self.ss.running:
            # reset and start
            self.ss.Sniffer = PacketSnifferThread(self.ss.iface, self.ss.bpf, self.ss.Handler.q)
            self.ss.Handler.sniffer_thread = self.ss.Sniffer
            self.ss.Sniffer.start()
            self.ss.running = True
            st.rerun()  # refresh UI state immediately

        if stop_clicked and self.ss.running:
            if self.ss.Sniffer:
                self.ss.Sniffer.stop()
                self.ss.Sniffer.join()
            self.ss.running = False
            st.rerun()
    
    def main_window(self):
        left, mid, right = st.columns([2,1,1])
        left.subheader("Packet List")

        # quick metrics
        now_ts = time.time()
        recent = [r for r in self.ss.Handler.packets if now_ts - r['_ts'] <= 5]
        pps = len(recent) / 5 if recent else 0.0
        mid.metric("PPS (5s)", f"{pps:,.1f}")
        if self.ss.Sniffer:
            right.metric("Dropped Packets", f"{self.ss.Sniffer.dropped_packets:,.0f}")
        else:
            right.metric("Dropped Packets", "0")

        # temporary: show last few lines as text until you add a dataframe
        if self.ss.Handler.packets:
            columns=["No","Time","Source","Destination","Protocol","Length","Info"]
            search = st.text_input("Search", value="", key="search_input")
            if search:
                filtered_packets = []
                for p in self.ss.Handler.packets:
                    for col in columns:
                        if search.lower() in str(p[col]).lower():
                            filtered_packets.append(p)
                            break
                        filtered_packets.append(p)

                display_packets = filtered_packets
            else:
                display_packets = self.ss.Handler.packets
            
            df = pd.DataFrame(
                display_packets,
                columns=columns
            )

            df = df.tail(1000).iloc[::-1].reset_index(drop=True)

            if self.ss.running:
                st.dataframe(df, width='stretch', height=360)

            else:
                gb = GridOptionsBuilder.from_dataframe(df)
                gb.configure_selection('single', use_checkbox=True)  # 'multiple' for multi-select
                grid_options = gb.build()

                grid_response = AgGrid(
                    df,
                    gridOptions=grid_options,
                    height=360,
                    width='100%',
                    enable_enterprise_modules=False,
                    theme="streamlit"
                )

                selected_rows = grid_response['selected_rows']
                    
                if isinstance(selected_rows, pd.DataFrame):
                    selected_no = selected_rows.iloc[0]["No"] if not selected_rows.empty else None
                    st.write("You selected No:", int(selected_no))
                    
                    selected_packet = (self.ss.Handler.get_packet_from_no(selected_no))
                    st.write("Packet details:")
                    if selected_packet:
                        packet_dict = self.ss.Handler.create_packet_dict(selected_packet)
                        for header, fields in packet_dict.items():
                            with st.expander(header):
                                for key, value in fields.items():
                                    st.write(f"**{key}**: {value}")
                    else:
                        st.info("No packet found for the selected No.")

                #if selected_rows:
                    # At least one row selected
                #    selected_packet = selected_rows.iloc[0]   # first selected row
                #    st.write("You selected:", selected_packet)

                                
                #else:
                #    st.info("No packets yet. Click Start, pick the right interface, and generate some traffic.")

    def start(self):
        
        start_clicked, stop_clicked = self.sidebar_controls()
        self.start_stop_logic(start_clicked, stop_clicked)
        self.ss.Handler.drain_queue()
        self.main_window()

        if self.ss.running:

            st_autorefresh(interval=self.ss.auto_refresh, key="dataframe_refresh")

if __name__ == "__main__":
    ui = StreamlitUI()
    ui.start()