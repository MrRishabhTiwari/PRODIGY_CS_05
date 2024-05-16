import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
from scapy.all import *
stop_sniffing_flag = False
sniffing_thread = None

def start_sniffing():
    global sniffing_thread, stop_sniffing_flag
    def packet_callback(packet):
        if stop_sniffing_flag:
            return
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto

                payload = None
                if Raw in packet:
                    payload = packet[Raw].load

                output.insert(
                    tk.END, f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol} | Payload: {payload}\n")

                if src_ip:
                    src_index_start = output.search(src_ip, "1.0", tk.END)
                    if src_index_start:
                        src_index_end = f"{src_index_start}+{len(src_ip)}c"
                        output.tag_configure('src_ip_color', foreground='red')
                        output.tag_add(
                            'src_ip_color', src_index_start, src_index_end)

                if dst_ip:
                    dst_index_start = output.search(dst_ip, "1.0", tk.END)
                    if dst_index_start:
                        dst_index_end = f"{dst_index_start}+{len(dst_ip)}c"
                        output.tag_configure('dst_ip_color', foreground='red')
                        output.tag_add(
                            'dst_ip_color', dst_index_start, dst_index_end)

                if payload:
                    payload_index_start = output.search(payload.decode('utf-8', 'ignore'), "1.0", tk.END)
                    if payload_index_start:
                        payload_index_end = f"{payload_index_start}+{len(payload)}c"
                        output.tag_configure(
                            'payload_color', foreground='green')
                        output.tag_add('payload_color',
                                       payload_index_start, payload_index_end)

                output.see(tk.END)  # Auto-scroll to the end of the text
        except Exception as e:
            print(f"Error processing packet: {e}")

    sniffing_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    output.delete(1.0, tk.END)  # Clear previous output
    output.insert(tk.END, "[+] Sniffing Started...\n")
    output.see(tk.END)  # Auto-scroll to the end of the text

    stop_sniffing_flag = False

    try:
        sniffing_thread = threading.Thread(target=sniff, kwargs={
            "prn": packet_callback, "store": False, "stop_filter": lambda x: stop_sniffing_flag})
        sniffing_thread.start()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        stop_sniffing()

def stop_sniffing():
    global stop_sniffing_flag, sniffing_thread
    stop_sniffing_flag = True
    if sniffing_thread and sniffing_thread.is_alive():
        sniffing_thread.join()
    sniffing_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    output.insert(tk.END, "[+] Sniffing Stopped.\n")
    output.see(tk.END)  # Auto-scroll to the end of the text

def save_log():
    log_text = output.get(1.0, tk.END)
    log_file_path = os.path.join(os.path.expanduser(
        "~"), "Downloads", "packet_log.txt")
    with open(log_file_path, "w") as file:
        file.write(log_text)
    messagebox.showinfo("Saved", "Log file saved successfully.")

root = tk.Tk()
root.title("Packet Sniffer")
root.configure(bg="red")  
root.geometry("500x500")

roboto_font = ("Roboto", 12)
consolas_font = ("Consolas", 10)

main_frame = tk.Frame(root, bg="blue")
main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

output = scrolledtext.ScrolledText(
    main_frame, wrap=tk.WORD, font=consolas_font, bg="yellow")
output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

button_frame = tk.Frame(main_frame, bg="#000000")
button_frame.pack(side=tk.BOTTOM, pady=10)

sniffing_button = tk.Button(button_frame, text="Start Sniffing",
                            command=start_sniffing, bg="#444444", fg="white", font=roboto_font)
sniffing_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing,
                        bg="#444444", fg="white", font=roboto_font, state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=10)

download_button = tk.Button(button_frame, text="Download Log",
                            command=save_log, bg="#444444", fg="white", font=roboto_font)
download_button.pack(side=tk.LEFT, padx=10)

root.mainloop()
