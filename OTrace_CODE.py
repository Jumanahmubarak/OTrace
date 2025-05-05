import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from fpdf import FPDF
import shutil
import hashlib
import pandas as pd
from datetime import datetime
import time  
from prettytable import PrettyTable
from colorama import Fore, Style, init
import subprocess
import pyshark
import platform
from cryptography.fernet import Fernet
import stat
import getpass
from collections import defaultdict
import math



if sys.platform.startswith('win'):
   ROOT_FOLDER = r'D:\ROOT'
   
else:
   ROOT_FOLDER = r'/media/kali/OTrace/ROOT'
# ========== Global Variables ==========

capture_device = "eth1"  # Change this if needed
duration_seconds = 60

# USB info
usb_device = "/dev/sdb1"
mount_path = "/media/kali/OTrace"

timestamp = int(time.time())
filename = f"evidence_{timestamp}.pcap"

RAW_FOLDER = os.path.join(os.getcwd(), "Raw_Files")
REPORT_FOLDER = os.path.join(ROOT_FOLDER, 'investigationreports')
CREDENTIALS_FILE = os.path.join(ROOT_FOLDER, 'credentials.csv')
AUDIT_LOG_FILE = os.path.join(ROOT_FOLDER, 'audit_log.txt')
ENCRYPTED_CREDENTIALS_FILE = os.path.join(ROOT_FOLDER, 'credentialsXXX.enc')
FERNET_KEY_FILE = os.path.join(ROOT_FOLDER, 'fernet.key')
LOG_REPORT_FILE = os.path.join(REPORT_FOLDER, "log_report")
FINDINGS_FILE = os.path.join(REPORT_FOLDER, "investigator_findings")
pcap_path = os.path.join(REPORT_FOLDER,"NetworkCaptures", filename)
hash_path = os.path.join(REPORT_FOLDER,"NetworkCaptures", "Hash", filename + ".sha256")
network_reports_folder = os.path.join(REPORT_FOLDER, "NetworkCaptures")

# ========== Helper Functions ==========
def ensure_folders():
    os.makedirs(RAW_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    os.makedirs(LOG_REPORT_FILE, exist_ok=True)
    
    


   

#----------------------------------------------



#---------------------network analysis relate------------------- 
# Normal packet range per chunk
BASE_LOWER = 5879.91
BASE_UPPER = 6153.79
CHUNK_SIZE = 60.0

# Modbus write functions of interest
MODBUS_WRITE_FUNCTIONS = {
    '5': 'Write Single Coil',
    '6': 'Write Holding Register',
    '15': 'Write Multiple Coils',
    '16': 'Write Multiple Registers'
}

def remount_usb(mode):
    system = platform.system()
    if system == 'Linux':
        if mode == "rw":
            os.system(f"sudo mount -o remount,rw {usb_device} {mount_path}")
            print("[*] USB remounted as READ-WRITE.")
        elif mode == "ro":
            os.system(f"sudo mount -o remount,ro {usb_device} {mount_path}")
            print("[*] USB remounted as READ-ONLY.")
        else:
            print("[!] Invalid remount mode!")
    else:
        # Windows or other OS — do nothing
        print(f"[!] Skipping USB remount on {system} (not Linux).")



def run_capture():
    print("[*] Starting packet capture...")

    if platform.system() == 'Windows':
        
        capture_interface = "11"  
    else:
        capture_interface = capture_device  

    subprocess.run([
        "tshark", "-i", capture_interface,
        "-a", f"duration:{duration_seconds}",
        "-w", pcap_path
    ], check=True)

    print(f"[+] PCAP saved to: {pcap_path}")


def generate_hash():
    print("[*] Generating SHA256 hash...")
    sha256 = hashlib.sha256()

    with open(pcap_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    with open(hash_path, "w") as f:
        f.write(sha256.hexdigest())

    print(f"[+] Hash saved to: {hash_path}")



def analyze_modbus_pcap(file_path):
    cap = pyshark.FileCapture(file_path, display_filter='modbus', use_json=True)
    suspicious_packets = []

    for pkt in cap:
        try:
            modbus_layer = pkt.modbus
            function_code = modbus_layer.func_code

            if function_code in MODBUS_WRITE_FUNCTIONS:
                suspicious_packets.append({
                    'No': pkt.number,
                    'Time': pkt.sniff_time,
                    'Source': pkt.ip.src if 'ip' in pkt else 'N/A',
                    'Destination': pkt.ip.dst if 'ip' in pkt else 'N/A',
                    'Function Code': function_code,
                    'Info': f"Suspicious Modbus: {MODBUS_WRITE_FUNCTIONS[function_code]}"
                })

        except AttributeError:
            continue  # Skip packets without Modbus or IP layers
        except Exception as e:
            print(f"Error processing packet {pkt.number}: {e}")
            continue

    cap.close()
    return suspicious_packets

def get_packet_timestamps(file_path):
    result = subprocess.run(
        ["tshark", "-r", file_path, "-T", "fields", "-e", "frame.time_relative"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    timestamps = result.stdout.strip().splitlines()
    return [float(ts) for ts in timestamps if ts.strip()]

def analyze_chunks(file_path):
    timestamps = get_packet_timestamps(file_path)
    if not timestamps:
        print("❌ Couldn't extract timestamps from the pcap file.")
        return []

    chunk_packets = defaultdict(list)
    for i, ts in enumerate(timestamps):
        chunk_index = int(ts // CHUNK_SIZE)
        chunk_packets[chunk_index].append(i + 1)

    total_chunks = int(math.ceil(max(timestamps) / CHUNK_SIZE))
    chunk_issues = []

    for i in range(total_chunks):
        packets = chunk_packets.get(i, [])
        count = len(packets)

        if BASE_LOWER <= count <= BASE_UPPER:
            continue

        chunk_issues.append({
            'chunk_index': i,
            'start_packet': packets[0] if packets else 'N/A',
            'end_packet': packets[-1] if packets else 'N/A',
            'packet_count': count
        })

    return chunk_issues

def generate_report(modbus_data, chunk_data, output_file):
    report_text = "==== Suspicious Modbus Activity Report ====\n\n"
    if modbus_data:
        for pkt in modbus_data:
            report_text += (
                f"No: {pkt['No']}, Time: {pkt['Time']}, "
                f"Src: {pkt['Source']} -> Dst: {pkt['Destination']}, "
                f"Func Code: {pkt['Function Code']}, Info: {pkt['Info']}\n"
            )
    else:
        report_text += "No suspicious Modbus activity detected.\n"

    report_text += "\n==== Packet Volume Anomaly Report ====\n\n"
    if chunk_data:
        for chunk in chunk_data:
            report_text += (
                f"Chunk {chunk['chunk_index']}: "
                f"Packets {chunk['start_packet']}–{chunk['end_packet']}, "
                f"Count: {chunk['packet_count']} (Expected: {int(BASE_LOWER)}–{int(BASE_UPPER)})\n"
            )
    else:
        report_text += "No abnormal packet volume detected in any chunk.\n"

    # Encrypt and save
    key = load_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(report_text.encode())

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    print(f"[+] Encrypted report saved to: {output_file}")

def network_analysis(logged_user):

      try:
        
        run_capture()
        generate_hash()
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_filename = f"network_{logged_user}_{timestamp}_report.txt"
        network_report_path = os.path.join(REPORT_FOLDER, "NetworkCaptures", report_filename)

        modbus_suspicious = analyze_modbus_pcap(pcap_path)
        chunk_suspicious = analyze_chunks(pcap_path)
        generate_report(modbus_suspicious, chunk_suspicious, network_report_path)
        
        print("[✓] Capture, analysis, and report complete. USB locked as read-only.")

      except subprocess.CalledProcessError as e:
        print(f"[!] Error: {e}")
        print("[!] Please check USB mount status manually.")

       

#----------------------------------------------------------------------




#-----------credentials related functions------------------
def generate_key():
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, 'wb') as key_file:
            key_file.write(key)

def load_key():
    return open(FERNET_KEY_FILE, 'rb').read()

        
def generate_encrypted_credentials():
    with open(FERNET_KEY_FILE, 'rb') as f:
        key = f.read()
    fernet = Fernet(key)

    with open(CREDENTIALS_FILE, 'rb') as f:
        original = f.read()

    encrypted = fernet.encrypt(original)

    with open(ENCRYPTED_CREDENTIALS_FILE, 'wb') as f:
        f.write(encrypted)

    print(" Encrypted credentials file generated successfully.")

def ensure_encrypted_credentials():
    if not os.path.exists(ENCRYPTED_CREDENTIALS_FILE):
        if not os.path.exists(CREDENTIALS_FILE):
            raise FileNotFoundError(" credentials.csv not found to generate encrypted file!")
        generate_encrypted_credentials()

# Always check before starting anything
ensure_encrypted_credentials()

def load_credentials():
    with open(FERNET_KEY_FILE, 'rb') as f:
        key = f.read()
    fernet = Fernet(key)

    with open(ENCRYPTED_CREDENTIALS_FILE, 'rb') as f:
        encrypted = f.read()
    
    decrypted = fernet.decrypt(encrypted)
    
    # Parse CSV from memory
    lines = decrypted.decode().splitlines()
    credentials = {}
    for line in lines:
        username, password, role = line.split(',')
        credentials[username.strip()] = (password.strip(), role.strip())
    
    return credentials

#---------------------------------------------------------------------------------------





#--------------------admin functions -----------------------
def add_investigator():
    credentials = load_credentials()
    username = input("Enter new investigator username: ").strip()
    password = getpass.getpass("Enter password for the investigator: ").strip()

    if username in credentials:
        print("[!] Username already exists.")
    else:
        credentials[username] = (password, 'investigator')

        # Write updated credentials to CSV (temporarily in memory)
        lines = []
        for user, (pwd, role) in credentials.items():
            lines.append(f"{user},{pwd},{role}")

        temp_csv = '\n'.join(lines).encode()

        # Encrypt and overwrite encrypted file
        with open(FERNET_KEY_FILE, 'rb') as f:
            key = f.read()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(temp_csv)
        with open(ENCRYPTED_CREDENTIALS_FILE, 'wb') as f:
            f.write(encrypted)

        print("[✔] Investigator added successfully.")
        audit_log(f"Admin added investigator: {username}")
        print("!! After adding new investigator you must restart OTrace in order to be able to sign in as the new investigator !!")


def remove_investigator():
    credentials = load_credentials()
    username = input("Enter investigator username to remove: ").strip()

    if username in credentials and credentials[username][1] == 'investigator':
        del credentials[username]

        lines = []
        for user, (pwd, role) in credentials.items():
            lines.append(f"{user},{pwd},{role}")

        temp_csv = '\n'.join(lines).encode()

        with open(FERNET_KEY_FILE, 'rb') as f:
            key = f.read()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(temp_csv)
        with open(ENCRYPTED_CREDENTIALS_FILE, 'wb') as f:
            f.write(encrypted)

        print("[✔] Investigator removed successfully.")
        audit_log(f"Admin removed investigator: {username}")
        print("!! After removing investigator you must restart OTrace in order to completly remove investigator !!")
    else:
        print("[!] Investigator not found.")

def admin_menu_logs():
    while True:
        print("="*40)
        print("Admin Menu")
        print("="*40)
        print("[1] Review Raw Traces")
        print("[2] Exit")
        choice = input("Enter your choice: ").strip()
        if choice == '1':
            review_samples()
        elif choice == '2':
            print("Exiting Admin Menu...")
            break     
        else:
            print("Invalid choice.\n")

#----------------------------------------------------------------------------

#---------------log functions----------------------------------

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def audit_log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(AUDIT_LOG_FILE, 'a') as log:
        log.write(f"[{timestamp}] {message}\n")


def review_samples(logged_user):
    files = [f for f in os.listdir(RAW_FOLDER) if f.endswith('.csv')]
    if not files:
        print("[!] No raw traces available.\n")
        return

    # Let admin choose a file
    print("\nAvailable Raw Trace Files:")
    for idx, fname in enumerate(files, 1):
        print(f"[{idx}] {fname}")
    
    choice = input("\nEnter the number of the file to analyze: ").strip()

    if not choice.isdigit() or not (1 <= int(choice) <= len(files)):
        print("[!] Invalid selection.\n")
        return

    selected_file = files[int(choice) - 1]
    file_path = os.path.join(RAW_FOLDER, selected_file)
    df = pd.read_csv(file_path)

    time_col = next((col for col in df.columns if col.startswith("X(ms)")), None)
    if not time_col:
        print("[!] No valid time column (X(ms)...) found in file.")
        return

    abnormal_samples = []

    print("=" * 140)
    print("Sample | X(ms) [UTC] | MAX_REQ | EXIST_LITER_TANK | MIN_REQ | ABNORMAL_HIGH_STATUS | NORMAL_LAMP | ABNORMAL_LOW_STATUS")
    print("-" * 140)

    for index, row in df.iterrows():
        high_status = int(row['ABNORMAL_HIGH_STATUS[%M10.0]'])
        low_status = int(row['ABNORMAL_LOW_STATUS[%M10.1]'])

        line = f"{int(row['Sample']):<6} | {row[time_col]:<22} | " \
               f"{row['MAX_REQ[%MD0]']:<7.2f} | {row['EXIST LITER_TANK[%QD38]']:<15.2f} | " \
               f"{row['MIN_REQ[%MD4]']:<7.2f} | {high_status:<21} | " \
               f"{int(row['NORMAL_LAMP[%Q0.1]']):<11} | {low_status:<20}"

        if high_status == 1 or low_status == 1:
            abnormal_samples.append(line)
            print(Fore.RED + line + Style.RESET_ALL)
        else:
            print(line)

        time.sleep(0.005)

    print("=" * 140)

    if abnormal_samples:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_name = f"logreport_{logged_user}_{timestamp}.txt"
        os.makedirs(LOG_REPORT_FILE, exist_ok=True)
        report_path = os.path.join(LOG_REPORT_FILE, report_name)

        key = load_key()
        fernet = Fernet(key)

        report_text = "OTrace Investigation Report\n"
        report_text += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_text += "="*80 + "\n"
        report_text += "Sample | X(ms) [UTC] | MAX_REQ | EXIST_LITER_TANK | MIN_REQ | ABNORMAL_HIGH_STATUS | NORMAL_LAMP | ABNORMAL_LOW_STATUS\n"
        report_text += "-"*80 + "\n"
        for abnormal_line in abnormal_samples:
            report_text += abnormal_line + "\n"

        with open(report_path, 'wb') as rep:
            rep.write(fernet.encrypt(report_text.encode()))

        print(f"\n[✔] Encrypted investigation report generated: {report_name}\n")
        audit_log(f"Encrypted investigation report created for {selected_file}.")

    else:
        print("\n[!] No abnormalities detected. No report generated.\n")

    print(f"[✔] Finished reviewing {selected_file}.")





#---------------------------------------------------------------------------------------------------


# ========== Login ==========
def login(credentials):
    print("Login:")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()
    if username in credentials:
        stored_password, stored_role = credentials[username]
        if password == stored_password:
            audit_log(f"{username} ({stored_role}) logged in successfully.")
            print(f"Login successful! Welcome {username} ({stored_role.capitalize()})\n")
            return stored_role.lower()  # Return the role for later use
        else:
            print("[!] Invalid password.\n")
    else:
        print("[!] Invalid username.\n")
    return None


from colorama import Fore, Style, init

init(autoreset=True)  # Initialize colorama for auto reset after every print





# ========== Investigator Functions ==========


    

def view_reports(logged_user,logged_role):
    print("\nWhich type of report do you want to view?")
    print("[1] Log Reports")
    print("[2] Network Report")
    report_type = input("Enter your choice: ").strip()
    
    if report_type == '1':
        # Log Reports
        if not os.path.exists(LOG_REPORT_FILE):
            print("[!] No log reports folder found.")
            return

        log_files = [f for f in os.listdir(LOG_REPORT_FILE) if f.endswith('.txt') and (logged_role == 'admin' or logged_user in f)]
        if not log_files:
            print("[!] No log reports available.")
            return

        print("\nAvailable Log Reports:")
        for idx, f in enumerate(log_files, 1):
            print(f"[{idx}] {f}")

        choice = input("\nSelect a report number to view: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(log_files):
            selected_file = log_files[int(choice) - 1]
            selected_path = os.path.join(LOG_REPORT_FILE, selected_file)

            print(f"\n=== {selected_file} ===\n")
            try:
                with open(selected_path, 'rb') as file:
                    encrypted = file.read()
                key = load_key()
                fernet = Fernet(key)
                decrypted = fernet.decrypt(encrypted)
                print(decrypted.decode())
            except Exception as e:
                print("[!] Failed to decrypt or read the report:", e)

            audit_log(f"Investigator viewed report: {selected_file}")
           
        else:
            print("[!] Invalid selection.")

    elif report_type == '2':
    
        if not os.path.exists(network_reports_folder):
            print("[!] Network reports folder not found.")
            return

        reports = [f for f in os.listdir(network_reports_folder) if f.endswith('_report.txt') and (logged_role == 'admin' or logged_user in f)]
        if not reports:
            print("[!] No network reports available.")
            return

        print("\nAvailable Network Reports:")
        for idx, f in enumerate(reports, 1):
            print(f"[{idx}] {f}")

        choice = input("\nSelect a report number to view: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(reports):
            selected_file = reports[int(choice) - 1]
            selected_path = os.path.join(network_reports_folder, selected_file)

            print(f"\n=== {selected_file} ===\n")
            try:
                with open(selected_path, 'rb') as file:
                    encrypted = file.read()
                key = load_key()
                fernet = Fernet(key)
                decrypted = fernet.decrypt(encrypted)
                print(decrypted.decode())
            except Exception as e:
                print("[!] Failed to decrypt or read the report:", e)

            audit_log(f"Investigator viewed report: {selected_file}")
            
        else:
            print("[!] Invalid selection.")




def write_findings(logged_user):
    os.makedirs(FINDINGS_FILE, exist_ok=True)
    print("\nWrite your findings and recommendations:")
    finding = input("Finding: ")
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')  
    finding_filename = f"finding_{logged_user}_{timestamp}.txt"
    finding_path = os.path.join(FINDINGS_FILE, finding_filename)

    key = load_key()
    fernet = Fernet(key)

    finding_text = f"Timestamp: {timestamp}\nFinding: {finding}\n"
    encrypted = fernet.encrypt(finding_text.encode())

    with open(finding_path, 'wb') as f:
        f.write(encrypted)

    print(f"[✓] Finding recorded as {finding_filename}.")
    audit_log(f"Investigator wrote finding: {finding_filename}")





def view_findings(logged_role, logged_user):
    os.makedirs(FINDINGS_FILE, exist_ok=True)
    findings_files = [f for f in os.listdir(FINDINGS_FILE) if f.startswith('finding_') and f.endswith('.txt') and (logged_role == 'admin' or logged_user in f)]

    if not findings_files:
        print("[!] No findings recorded yet.")
        return

    print("\n=== Available Findings ===")
    for idx, file in enumerate(findings_files, 1):
        print(f"[{idx}] {file}")

    choice = input("\nEnter the number of the finding you want to read: ").strip()

    if choice.isdigit() and 1 <= int(choice) <= len(findings_files):
        selected_file = findings_files[int(choice) - 1]
        selected_path = os.path.join(FINDINGS_FILE, selected_file)
        print(f"\n=== Content of {selected_file} ===\n")
        with open(selected_path, 'rb') as f:
            encrypted = f.read()

        try:
            key = load_key()
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted)
            print(decrypted.decode())
        except Exception as e:
            print("[!] Failed to decrypt finding:", e)
        print("="*60)
    else:
        print("[!] Invalid selection.")

    audit_log(f"Admin viewed finding: {selected_file}")
    

        

#---------------------------------------------------------------            

def visual_welcome():
    print("="*80)
    print("""
  ██████╗ ████████╗██████╗  █████╗  ██████╗ ███████╗
 ██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝
 ██║   ██║   ██║   ██████╔╝███████║██║      █████╗  
 ██║   ██║   ██║   ██╔═ ██║██╔══██║██║      ██╔══╝  
 ╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗ ███████╗
  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

        O T R A C E   -   USB Forensics Toolkit
    """)
    print("="*80)
    print()

remount_usb("rw")            

# ========== Main Program ==========
def main():
    visual_welcome()
    ensure_folders()
    credentials = load_credentials()

    while True:
        print("\nPlease select your role:")
        print("[1] Admin")
        print("[2] Investigator")
        print("[3] Shutdown System and Exit")
        role_choice = input("\nEnter your choice (1/2/3): ").strip()

        if role_choice == '3':
            remount_usb("ro")
            visual_welcome()
            print("GOODBYE!...")
            exit()

        if role_choice not in ['1', '2']:
            print("\nInvalid selection. Please try again.")
            continue

        # Ask login
        logged_role = None
        logged_user = None
        while not logged_role:
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()
            if username in credentials:
                stored_password, stored_role = credentials[username]
                if password == stored_password:
                    logged_role = stored_role.lower()
                    logged_user = username
                    audit_log(f"{username} ({logged_role}) logged in successfully.")
                    print(f"Login successful! Welcome {username} ({logged_role.capitalize()})\n")
                else:
                    print("[!] Invalid password.\n")
            else:
                print("[!] Invalid username.\n")


        # Check if role matches
        if (role_choice == '1' and logged_role != 'admin') or (role_choice == '2' and logged_role != 'investigator'):
            print("\n[!] Role mismatch! Please login with the correct role.")
            continue

        # After successful login
        while True:
            if (logged_role == 'admin'):
                print("[1] Add Investigator")
                print("[2] Remove Investigator")
                print("[3] View Investigator Findings")
                print("[4] Exit")

                analysis_choice = input("\nEnter your choice: ").strip()

                
                if analysis_choice == '1':
                    add_investigator()
                elif analysis_choice == '2':
                    remove_investigator()
                elif analysis_choice == '3':
                    view_findings(logged_role, logged_user)
                elif analysis_choice == '4':
                    print("\nLogging out...")
                    audit_log(f"{logged_role.capitalize()} logged out.")
                    break
                else:
                    print("\nInvalid selection. Please try again.")



            elif (logged_role == 'investigator'):
                print("\nInvestigator Menu")
                print("[1] Network Analysis")
                print("[2] Log Analysis")
                print("[3] View Reports")
                print("[4] Write Findings and Recommendations")
                print("[5] View My Findings")
                print("[6] Logout")

                choice = input("Enter your choice: ").strip()

                if choice == '1':
                    network_analysis(logged_user)
                    audit_log("Investigator performed Network Analysis.")
                elif choice == '2':
                    review_samples(logged_user) 
                    audit_log("Investigator performed Log Analysis.")               
                elif choice == '3':
                    view_reports(logged_user, logged_role)
                elif choice == '4':
                    write_findings(logged_user)
                elif choice == '5':
                    view_findings(logged_role, logged_user)   
                elif choice == '6':
                    audit_log(f"{logged_role.capitalize()} logged out.")
                    print("Logging out...\n")
                    break
                
                else:
                    print("Invalid selection. Try again.\n")


     

if __name__ == "__main__":
    main()
