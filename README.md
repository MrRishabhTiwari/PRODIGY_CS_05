# PRODIGY_CS_05
This Python code creates a Packet Sniffer application using the tkinter and scapy libraries. Here's a summary of its functionality:

1. **Packet Sniffing Functionality:**
   - The `start_sniffing` function initiates packet sniffing using the `sniff` function from the scapy library. It captures network packets on the specified network interface and calls the `packet_callback` function for each packet.
   - The `packet_callback` function processes each captured packet, extracting information such as source and destination IP addresses, protocol, and payload. It then displays this information in the tkinter GUI's output area.

2. **GUI Creation:**
   - The tkinter library is utilized to create a user-friendly GUI for the packet sniffer application.
   - The GUI includes a scrolled text area (`scrolledtext.ScrolledText`) to display the packet information.
   - Buttons for starting, stopping, and downloading logs are created using `tk.Button`.

3. **Button Functionality:**
   - The "Start Sniffing" button initiates packet sniffing when clicked. It disables itself, enables the "Stop Sniffing" button, and starts displaying packet information in 
     the GUI.
   - The "Stop Sniffing" button halts packet sniffing when clicked. It re-enables the "Start Sniffing" button and disables itself.
   - The "Download Log" button saves the displayed packet log to a text file in the user's Downloads directory.
