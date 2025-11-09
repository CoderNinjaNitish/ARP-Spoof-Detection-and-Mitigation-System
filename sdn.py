# arp_simulator_streamlit.py
"""
Streamlit-based ARP spoof detection + visualization

Run:
    pip install streamlit networkx matplotlib
    streamlit run arp_simulator_streamlit.py

What it does:
 - Provides a simple interactive UI to run the same ARP-learning / spoof-detect simulator
 - Shows live log output, ARP table, blocked MACs, and a network graph
 - Controls let you choose mode (basic/random), number of hosts, spoof chance, and speed
"""
import streamlit as st
import time
import random
import networkx as nx
import matplotlib.pyplot as plt
from io import StringIO

# --- Simulator core (same logic as your script, adapted for Streamlit) ---
class SimpleController:
    def __init__(self, block_on_detect=True):

        self.arp_table = {}     # ip -> mac
        self.blocked_macs = set()
        self.block_on_detect = block_on_detect
        self.logs = []

    def _log(self, lvl, msg):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {lvl}: {msg}"
        self.logs.append(line)
        return line

    def receive_arp(self, src_ip, src_mac, pkt_info=""):
        if src_mac in self.blocked_macs:
            return self._log("DROP", f"Packet from blocked MAC {src_mac} dropped. ({pkt_info})")

        if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
            old = self.arp_table[src_ip]
            alert = self._log("ALERT", f"ARP spoof detected: IP {src_ip} was {old}, now {src_mac}. ({pkt_info})")
            if self.block_on_detect:
                self.block_mac(src_mac)
            return alert
        else:
            # learn mapping
            self.arp_table[src_ip] = src_mac
            return self._log("LEARN", f"Learned {src_ip} -> {src_mac}. ({pkt_info})")

    def block_mac(self, mac):
        if mac not in self.blocked_macs:
            self.blocked_macs.add(mac)
            return self._log("MITIGATE", f"Blocking MAC {mac} (simulated drop flow).")
        return None

# --- Utilities ---

def random_mac(prefix=None):
    if prefix:
        return prefix + ":" + ":".join(f"%02x" % random.randint(0,255) for _ in range(4))
    return ":".join(f"%02x" % random.randint(0,255) for _ in range(6))

# --- Streamlit UI ---
st.set_page_config(page_title="ARP Spoof Simulator", layout="wide")
st.title("ARP Spoof Detection — Visual Simulator")

with st.sidebar:
    st.header("Simulation Controls")
    mode = st.selectbox("Mode", ["basic", "random"], index=0)
    hosts_count = st.slider("Number of hosts", min_value=2, max_value=10, value=4)
    spoof_chance = st.slider("Spoof chance (random mode)", min_value=0.0, max_value=0.7, value=0.15, step=0.01)
    speed = st.slider("Pause between events (seconds)", 0.0, 1.5, 0.4, step=0.05)
    block_on_detect = st.checkbox("Auto-block attacker MACs on detect", value=True)
    run = st.button("Run simulation")
    step = st.button("Step one event")
    reset = st.button("Reset")

# session state initialization
if 'ctrl' not in st.session_state or reset:
    st.session_state.ctrl = SimpleController(block_on_detect=block_on_detect)
    # create hosts
    st.session_state.hosts = []
    for i in range(1, hosts_count + 1):
        ip = f"10.0.0.{i}"
        mac = f"02:00:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
        st.session_state.hosts.append((ip, mac))
    st.session_state.started = False
    st.session_state.logs_buf = []

# keep checkbox effect in sync
st.session_state.ctrl.block_on_detect = block_on_detect

col1, col2 = st.columns([1,1])

with col1:
    st.subheader("Controller Logs")
    log_area = st.empty()

    # show logs from session_state
    if st.session_state.ctrl.logs:
        log_text = "\n".join(st.session_state.ctrl.logs)
    else:
        log_text = "(no events yet)"
    log_area.text_area("", value=log_text, height=400)

    st.subheader("ARP Table")
    if st.session_state.ctrl.arp_table:
        st.table({"IP": list(st.session_state.ctrl.arp_table.keys()), "MAC": list(st.session_state.ctrl.arp_table.values())})
    else:
        st.write("(empty)")

    st.subheader("Blocked MACs")
    if st.session_state.ctrl.blocked_macs:
        st.write("\n".join(st.session_state.ctrl.blocked_macs))
    else:
        st.write("(none)")

with col2:
    st.subheader("Network Topology")
    graph_area = st.empty()

    def draw_graph(arp_table, blocked):
        G = nx.Graph()
        # add controller
        G.add_node("controller", bipartite=0)
        for ip, mac in arp_table.items():
            label = f"{ip}\n{mac}"
            G.add_node(label)
            G.add_edge("controller", label)
        # if there are hosts we didn't learn yet, show them as unknown
        for ip, mac in st.session_state.hosts:
            if ip not in arp_table:
                label = f"{ip}\n(unknown)"
                G.add_node(label)
                G.add_edge("controller", label)
        pos = nx.spring_layout(G, seed=42)
        fig, ax = plt.subplots(figsize=(6,5))
        nx.draw(G, pos, with_labels=True, node_size=900, font_size=8)
        # mark blocked macs with red border (simple visual cue)
        # (we won't specify colors globally)
        return fig

    fig = draw_graph(st.session_state.ctrl.arp_table, st.session_state.ctrl.blocked_macs)
    graph_area.pyplot(fig)

# --- Simulation behavior ---

# Initial learning step when simulation first started
if not st.session_state.started:
    for ip, mac in st.session_state.hosts:
        msg = st.session_state.ctrl.receive_arp(ip, mac, pkt_info="initial ARP")
    st.session_state.started = True

# Helper to perform one event
def one_event():
    if mode == 'basic':
        # basic sequence: normal learning already done; perform a deterministic spoof then a repeat
        attacker_mac = "aa:aa:aa:aa:aa:aa"
        # pick a victim (second host if exists)
        if len(st.session_state.hosts) >= 2:
            victim_ip = st.session_state.hosts[1][0]
            st.session_state.ctrl.receive_arp(victim_ip, attacker_mac, pkt_info="spoof attempt (basic)")
            # next event: attacker sends again
            st.session_state.ctrl.receive_arp(victim_ip, attacker_mac, pkt_info="spoof attempt (basic #2)")
    else:
        # random mode: either normal ARP or spoof
        if random.random() < spoof_chance:
            victim = random.choice(st.session_state.hosts)[0]
            attacker_mac = f"de:ad:be:ef:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
            st.session_state.ctrl.receive_arp(victim, attacker_mac, pkt_info="random spoof")
        else:
            s = random.choice(st.session_state.hosts)
            st.session_state.ctrl.receive_arp(s[0], s[1], pkt_info="normal ARP")

# Run / step handling
if step and not run:
    one_event()
    # refresh
    st.experimental_rerun()

if run:
    # run for a short while (non-blocking-ish): show updates as we go
    duration = 6 if mode == 'random' else 2
    start = time.time()
    while time.time() - start < duration:
        one_event()
        # update displays
        log_text = "\n".join(st.session_state.ctrl.logs)
        log_area.text_area("", value=log_text, height=400)
        if st.session_state.ctrl.arp_table:
            st.table({"IP": list(st.session_state.ctrl.arp_table.keys()), "MAC": list(st.session_state.ctrl.arp_table.values())})
        else:
            st.write("(empty)")
        fig = draw_graph(st.session_state.ctrl.arp_table, st.session_state.ctrl.blocked_macs)
        graph_area.pyplot(fig)
        time.sleep(speed)
    # finished run; final update
    st.experimental_rerun()

st.markdown("---")
st.write("Tip: use Reset to re-generate hosts and start fresh.")