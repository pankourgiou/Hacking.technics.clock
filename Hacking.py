import tkinter as tk
import time

# Lists of hacking techniques
hours_techniques = [
    "SQL Injection", "Buffer Overflow", "Cross-Site Scripting", "Privilege Escalation",
    "Password Cracking", "Man-in-the-Middle", "Zero-Day Exploit", "Phishing",
    "Code Injection", "Session Hijacking", "Keylogging", "Ransomware"
]

# Extended to 60 items
minutes_techniques = [
    "Brute Force", "DNS Spoofing", "Social Engineering", "Packet Sniffing",
    "Rootkit", "Watering Hole Attack", "Credential Stuffing", "Clickjacking",
    "Trojan Horse", "Logic Bomb", "Eavesdropping", "Backdoor",
    "Typosquatting", "Drive-by Download", "Credential Harvesting", "Replay Attack",
    "Formjacking", "Command Injection", "Evil Twin", "Scareware",
    "Worm", "Steganography", "Adware", "SIM Swapping",
    "Macro Virus", "Bootkit", "Malvertising", "Session Fixation",
    "Exploit Kit", "Voice Phishing", "Clipboard Hijack", "Fake WAP",
    "DNS Tunneling", "Cross-Site Request Forgery", "Web Shell", "Shadow IT",
    "Remote Access Trojan", "ARP Spoofing", "DLL Injection", "Data Exfiltration",
    "IoT Hijack", "Mobile Malware", "Supply Chain Attack", "Clipboard Injection",
    "Email Spoofing", "Keystroke Injection", "Aircrack", "Zombie Bot",
    "DDoS", "Sniffing", "Script Kiddie", "Credential Reuse",
    "Tabnabbing", "USB Drop", "Exploit Obfuscation", "Browser Hijacking",
    "Fake Antivirus", "DNS Amplification", "CryptoJacking", "Piggybacking"
]

seconds_techniques = minutes_techniques  # Also 60 items

# GUI
root = tk.Tk()
root.title("Hacker Clock")

label = tk.Label(root, font=("Courier", 18), bg="black", fg="lime", width=50, height=10, justify="center")
label.pack(padx=20, pady=20)

def update_clock():
    now = time.localtime()
    h = now.tm_hour % 12
    m = now.tm_min
    s = now.tm_sec

    hour_text = hours_techniques[h]
    minute_text = minutes_techniques[m]
    second_text = seconds_techniques[s]

    display = f"""
    [HOUR]   {hour_text}
    [MINUTE] {minute_text}
    [SECOND] {second_text}
    """
    label.config(text=display)
    root.after(1000, update_clock)

update_clock()
root.mainloop()
