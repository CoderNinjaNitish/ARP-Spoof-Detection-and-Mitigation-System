🛰️ ARP Spoof Detection Visual Simulator
🧠 Overview

The ARP Spoof Detection Visual Simulator is an interactive web-based tool built using Python, Streamlit, NetworkX, and Matplotlib.
It helps users visualize, understand, and simulate ARP spoofing attacks in a controlled virtual network environment.
The system models how an SDN-like controller can detect and mitigate spoofing attempts by monitoring ARP traffic in real time.
<img width="1919" height="855" alt="Screenshot 2025-11-09 163642" src="https://github.com/user-attachments/assets/4487d2bd-1b39-4467-81c9-685798521940" />
<img width="1919" height="869" alt="Screenshot 2025-11-09 163656" src="https://github.com/user-attachments/assets/88426c55-fb8b-421a-8899-0d17bac6ccf9" />



⚙️ Key Features

🖥️ Interactive Web Interface: Built with Streamlit for easy simulation and control.

🌐 Network Visualization: Displays a live network topology graph using NetworkX and Matplotlib.

🔐 ARP Spoof Detection: Detects when an IP address is mapped to a different MAC address.

🚫 Automatic Mitigation: Blocks the attacker’s MAC if spoofing is detected.

📜 Real-Time Logs: Live event logs showing learning, detection, and blocking actions.

⚡ Custom Controls:

Choose between Basic or Random simulation mode

Adjust number of hosts

Set spoofing probability

Control event speed

Enable or disable auto-blocking

🧩 How It Works

The simulator generates a network of hosts with unique IP and MAC addresses.

The controller learns and stores IP–MAC mappings in its ARP table.

During the simulation, normal and spoofed ARP packets are sent.

If an IP address is re-mapped to a different MAC, the controller detects spoofing.

Alerts are logged, and the malicious MAC can be automatically blocked.

🧰 Technologies Used

Python 3.x

Streamlit – for the web UI

NetworkX – for network graph visualization

Matplotlib – for plotting and rendering

🚀 How to Run
# Install dependencies
pip install streamlit networkx matplotlib

# Run the simulator
streamlit run arp_simulator_streamlit.py

📚 Use Case

This project is designed for students, cybersecurity learners, and network researchers who want to understand ARP spoofing detection in an interactive way. It’s a great visualization tool for teaching network security and Software Defined Networking (SDN) concepts.

👨‍💻 Author

Nitish Kumar
B.Tech in Computer Science, SRM Institute of Science and Technology
https://www.linkedin.com/in/ninjanitish/
