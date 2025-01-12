import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP
import threading

//variables 
sniffing = False
paused = False

//function for sniffing ports
def print_summary(pkt):
    if not paused:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if TCP in pkt:
                protocol = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                protocol = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                return
            console.insert(tk.END, f"{protocol} | {src_ip}:{sport} -> {dst_ip}:{dport}\n")
            console.yview(tk.END)

def sniff_packets():
    global sniffing
    sniff(prn=print_summary, store=False, stop_filter=lambda _: not sniffing)


//funcstion for starting the scan
def start():
    global sniffing
    if not sniffing:
        sniffing = True
        threading.Thread(target=sniff_packets, daemon=True).start()
        statuslabel.config(text="Status: Sniffing...")


//function for pausing or resuming the scan
def pause():
    global paused
    paused = not paused
    if paused:
        statuslabel.config(text="Status: Paused")
        pause_button.config(text="Resume Sniffing")
    else:
        statuslabel.config(text="Status: Sniffing...")
        pause_button.config(text="Pause Sniffing")
      
//function for stopping the scan
def stop():
    global sniffing, paused
    sniffing = False
    paused = False
    statuslabel.config(text="Status: Stopped")
    pause_button.config(text="Pause Sniffing")


//GUI based window -Tkinter
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("600x400")

tk.Label(root, text="Packet Sniffer", font=("Arial", 14)).pack(pady=10)

start_button = tk.Button(root, text="Start Sniffing", command=start, width=20)
start_button.pack(pady=5)

pause_button = tk.Button(root, text="Pause Sniffing", command=pause, width=20)
pause_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop, width=20)
stop_button.pack(pady=5)

console = tk.Text(root, height=15, width=70)
console.pack(pady=10)

statuslabel = tk.Label(root, text="Status: Idle", font=("Arial", 10))
statuslabel.pack(pady=5)

root.mainloop()
