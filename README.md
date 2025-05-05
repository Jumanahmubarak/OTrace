# OTraceREADME
======================================================
OTrace: USB-Based Forensics Toolkit for OT Systems
======================================================

Author(s): Jumanah Albishi, Leen Alwadei, Nourah Alanazi, 
           Samar Alshahrani, Shahad Alammar


-----------------------------
1. OVERVIEW
-----------------------------
OTrace is a plug-and-play USB-based forensic toolkit developed 
for conducting live digital forensics investigations in 
Operational Technology (OT) environments. It supports real-time 
network traffic capture, log analysis, and encrypted reporting 
without disrupting system operations.

-----------------------------
2. SYSTEM REQUIREMENTS
-----------------------------
- Operating System: Linux (Kali preferred) or Windows
- Python 3.9+
- Wireshark & Tshark
- Required Python Libraries:
  - pandas
  - pyshark
  - cryptography
  - prettytable
  - colorama
  - fpdf (optional for PDF reports)

-----------------------------
3. RUNNING OTRACE
-----------------------------
1. Insert the USB into the OT system or monitoring station.
2. Open a terminal and navigate to the toolkit directory:
   > cd /media/<username>/OTrace

3. Run the main Python script:
   > python3 main.py

-----------------------------
4. USER ROLES
-----------------------------
>> ADMIN:
- Add/Remove Investigator Accounts
- View Investigator Findings
- Exit Program

>> INVESTIGATOR:
- Perform Network Traffic Analysis
- Analyze System Logs (CSV)
- View Encrypted Reports
- Write and Read Investigation Findings
- Logout

-----------------------------
5. INVESTIGATOR MANUAL
-----------------------------
> [1] Network Analysis:
   - Captures packets using tshark
   - Analyzes Modbus activity
   - Detects anomalies based on packet volume
   - Saves encrypted report to /investigationreports/NetworkCaptures

> [2] Log Analysis:
   - Perform log analysis
   - Highlights abnormal conditions (e.g., overflow)
   - Encrypted report saved to /investigationreports/log_report/

> [3] View Reports:
   - Decrypts and displays previous network/log reports

> [4] Write Findings:
   - Records investigator notes and recommendations
   - Encrypted and stored securely

> [5] View My Findings:
   - Displays previous entries written by the logged-in investigator

-----------------------------
6. SECURITY MEASURES
-----------------------------
- All reports and credentials are encrypted.
- Role-Based Access Control (RBAC) implemented.
- Hashing is used to verify network capture integrity.
- Automatic USB remount as read-only after investigations.


-----------------------------
7. TROUBLESHOOTING
-----------------------------
- If Wireshark is not found: install tshark (`sudo apt install tshark`)
- If reports cannot be viewed: check for correct Fernet key
- Restart after adding or removing investigators

-----------------------------
9. CONTACT
-----------------------------
For academic/research use only. For questions, contact one of the creators.
