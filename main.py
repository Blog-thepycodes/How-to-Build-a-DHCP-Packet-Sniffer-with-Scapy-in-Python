import threading
import logging
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff
from scapy.layers.dhcp import BOOTP, DHCP
import socket
 
 
# Configure logging to log DHCP details to a file
logging.basicConfig(filename="dhcp_listener.log", level=logging.INFO, format="%(asctime)s - %(message)s")
 
 
# Global variable to stop sniffing
sniffing = False
sniff_thread = None
 
 
# DHCP message type map
dhcp_message_types = {
   1: "DHCP Discover",
   2: "DHCP Offer",
   3: "DHCP Request",
   4: "DHCP Decline",
   5: "DHCP ACK",
   6: "DHCP NAK",
   7: "DHCP Release",
   8: "DHCP Inform"
}
 
 
# Function to handle incoming DHCP packets
def dhcp_packet_callback(packet, text_widget):
   if packet.haslayer(DHCP):
       bootp_layer = packet[BOOTP]
       dhcp_layer = packet[DHCP]
 
 
       client_mac = bootp_layer.chaddr[:6].hex(":")
       transaction_id = bootp_layer.xid
       client_ip = bootp_layer.yiaddr if bootp_layer.yiaddr else "N/A"
 
 
       # Identify the DHCP message type
       message_type = None
       for opt in dhcp_layer.options:
           if isinstance(opt, tuple) and opt[0] == 'message-type':
               message_type = dhcp_message_types.get(opt[1], "Unknown")
               break
 
 
       # Extract other DHCP options
       lease_time = None
       offered_ip = None
       server_ip = None
       hostname = None
       for opt in dhcp_layer.options:
           if isinstance(opt, tuple):
               if opt[0] == "lease-time":
                   lease_time = opt[1]
               elif opt[0] == "requested_addr":
                   offered_ip = opt[1]
               elif opt[0] == "server_id":
                   server_ip = opt[1]
               elif opt[0] == "hostname":
                   hostname = opt[1]
 
 
       # Format the information
       info = (f"\n--- Captured DHCP {message_type} Packet ---\n"
               f"Client MAC Address: {client_mac}\n"
               f"Transaction ID: {transaction_id}\n"
               f"Client IP: {client_ip}\n"
               f"Offered IP: {offered_ip}\n"
               f"Server IP: {server_ip}\n"
               f"Hostname: {hostname}\n"
               f"Lease Time: {lease_time}\n")
 
 
       # Insert into the Tkinter text widget and log it
       text_widget.insert(tk.END, info)
       text_widget.see(tk.END)  # Auto-scroll to the bottom
       logging.info(info)
 
 
# Function to start sniffing on the specified interface
def start_sniffing(interface, text_widget):
   global sniffing, sniff_thread
   sniffing = True
   print(f"Starting DHCP listener on {interface}")
 
 
   def sniff_thread_func():
       try:
           sniff(iface=interface, filter="udp and (port 67 or port 68)",
                 prn=lambda pkt: dhcp_packet_callback(pkt, text_widget), store=0, stop_filter=lambda x: not sniffing)
       except socket.error:
           error_msg = f"Error: Unable to start sniffing on interface {interface}. Please check the interface name."
           text_widget.insert(tk.END, error_msg + "\n")
           text_widget.see(tk.END)
           logging.error(error_msg)
           stop_sniffing()
 
 
   sniff_thread = threading.Thread(target=sniff_thread_func, daemon=True)
   sniff_thread.start()
 
 
# Function to stop sniffing
def stop_sniffing():
   global sniffing
   sniffing = False
   print("Stopping DHCP listener...")
 
 
# Function to start listener when button is pressed
def on_start_button():
   interface = interface_entry.get()
   if interface:
       start_sniffing(interface, text_area)
       start_button.config(state=tk.DISABLED)
       stop_button.config(state=tk.NORMAL)
 
 
# Function to stop listener when button is pressed
def on_stop_button():
   stop_sniffing()
   start_button.config(state=tk.NORMAL)
   stop_button.config(state=tk.DISABLED)
 
 
# Tkinter Setup
root = tk.Tk()
root.title("DHCP Listener - The Pycodes")
root.geometry("600x400")
 
 
# Interface label and entry
interface_label = tk.Label(root, text="Interface:")
interface_label.pack(pady=10)
 
 
interface_entry = tk.Entry(root)
interface_entry.pack(pady=5)
interface_entry.insert(0, "Wi-Fi")  # Default interface
 
 
# Start button
start_button = tk.Button(root, text="Start Listener", command=on_start_button)
start_button.pack(pady=5)
 
 
# Stop button
stop_button = tk.Button(root, text="Stop Listener", command=on_stop_button, state=tk.DISABLED)
stop_button.pack(pady=5)
 
 
# Text area to display packets
text_area = ScrolledText(root, wrap=tk.WORD, height=10)
text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
 
 
# Start the Tkinter event loop
root.mainloop()
