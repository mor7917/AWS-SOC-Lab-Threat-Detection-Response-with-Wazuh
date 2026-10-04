# 🛡️ AWS SOC Lab: Threat Detection & Response with Wazuh

A hands-on Security Operations Center (SOC) lab on **AWS EC2**. It collects endpoint and network telemetry, writes custom detections mapped to **MITRE ATT&CK**, simulates attacks, and documents each one the way a SOC analyst would.

> ⚠️ **Legal / ethical notice:** Attack only infrastructure that you own. Everything here targets your own EC2 instances. Review the [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/) first. Denial-of-service and flooding attacks are not permitted.

---

## 📑 Table of Contents

1. [What You Will Build](#-what-you-will-build)
2. [Architecture](#-architecture)
3. [Components](#-components)
4. [Prerequisites & Cost](#-prerequisites--cost)
5. [Step-by-Step Setup](#-step-by-step-setup)
6. [Attack Simulation](#-attack-simulation)
7. [Custom Detection Rules](#-custom-detection-rules)
8. [Active Response](#-active-response-auto-block)
9. [Output Screenshots](#-output-screenshots)
10. [Investigating Alerts](#-investigating-alerts)
11. [Incident Report Template](#-incident-report-template)
12. [Troubleshooting](#-troubleshooting)
13. [Cost Management & Cleanup](#-cost-management--cleanup)
14. [Learning Path](#-learning-path)
15. [Project Structure](#-project-structure)
16. [License](#-license)

---

## 🎯 What You Will Build

- A **SIEM** (Wazuh manager, indexer and dashboard) running on AWS
- A **Windows victim** reporting process, registry and network events through **Sysmon**
- A **network IDS** (Suricata) and an **SSH honeypot** (Cowrie)
- **Custom detection rules** for encoded PowerShell, LSASS credential dumping and RDP brute force
- **Repeatable attack tests** with Atomic Red Team, each mapped to a MITRE technique
- **Auto-blocking** with Wazuh Active Response
- A **portfolio** of incident reports with detection gaps and fixes

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AWS VPC (10.0.0.0/16)                           │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Public Subnet (10.0.1.0/24)                                     │   │
│  │  ┌──────────────────┐    ┌──────────────────┐                    │   │
│  │  │  Wazuh EC2       │◀───│  Windows EC2     │                    │   │
│  │  │  Manager+Dash    │    │  (Victim)        │                    │   │
│  │  │  + Suricata      │    │  + Wazuh Agent   │                    │   │
│  │  │  + Cowrie        │    │  + Sysmon        │                    │   │
│  │  └──────────────────┘    └──────────────────┘                    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Private Subnet (10.0.2.0/24), optional                          │   │
│  │  ┌──────────────────┐                                            │   │
│  │  │  Windows EC2     │  Domain Controller + AD DS                 │   │
│  │  └──────────────────┘                                            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │ attacks (internet or same VPC)
                         ┌──────────┴──────────┐
                         │   Kali Linux (You)  │
                         │   (Attacker Box)    │
                         └─────────────────────┘
```

**Data flow:** Sysmon and Windows event logs → Wazuh agent (TCP 1514) → Wazuh manager (decoders and rules) → indexer → dashboard alerts. Suricata and Cowrie logs are read locally on the manager host.

---

## 🧩 Components

| Component | Role | Where it runs |
|-----------|------|---------------|
| **Wazuh Manager + Indexer + Dashboard** | SIEM: log analysis, correlation, alerting, UI | Ubuntu 24.04 EC2 |
| **Wazuh Agent** | Collects endpoint logs, FIM, inventory | Windows Server 2022 EC2 |
| **Sysmon** | Detailed process, network and registry telemetry | Windows Server 2022 EC2 |
| **Suricata** | Network IDS (scans, C2, known-bad signatures) | Wazuh EC2 |
| **Cowrie** | SSH/Telnet honeypot (logs credentials and commands) | Wazuh EC2 |
| **Atomic Red Team** | MITRE-mapped attack simulation | Windows EC2 |
| **Kali Linux** | External attacker (nmap, hydra) | Local VM or EC2 |

---

## 📋 Prerequisites & Cost

- An AWS account with a billing alert or AWS Budget set up
- Basic familiarity with SSH, RDP, security groups and the Linux command line
- A Kali Linux machine (local VM or a separate EC2 instance)
- An SSH key pair created in your AWS region

**Recommended instance sizes**

| Instance | Type | Why |
|----------|------|-----|
| Wazuh (all-in-one) | `t3.large` (2 vCPU / 8 GB) | The indexer needs memory. `t3.medium` (4 GB) often runs out of RAM. |
| Windows victim | `t3.medium` | Windows Server is sluggish on 1 GB `t2.micro` instances. |

Costs depend on how many hours the instances run, plus EBS storage and any Elastic IPs. See [Cost Management](#-cost-management--cleanup). Check current prices on the AWS pricing page.

---

## 🚀 Step-by-Step Setup

### Step 1: Create the network (VPC)

**Why:** Putting both servers in one VPC and subnet lets the agent reach the manager over **private IPs**. That is more reliable and more secure than routing over the internet.

You can use the default VPC. If you want a dedicated lab network:

1. **VPC Console → Create VPC → "VPC and more"**
2. CIDR: `10.0.0.0/16`, 1 public subnet (`10.0.1.0/24`), 1 private subnet (`10.0.2.0/24`, optional)
3. Make sure the public subnet has a route to an Internet Gateway.

### Step 2: Create security groups

**Why:** Security groups are the firewall around each instance. Exposing a SIEM to the whole internet is a common beginner mistake, so keep the rules tight.

**`sg-wazuh`** (Wazuh server)

| Type | Port | Source | Purpose |
|------|------|--------|---------|
| SSH | 22 | **Your IP** `/32` | Admin access |
| HTTPS | 443 | **Your IP** `/32` | Dashboard |
| Custom TCP | 1514, 1515 | `10.0.0.0/16` (VPC CIDR) | Agent traffic and enrollment |
| Custom TCP | 2222 | `0.0.0.0/0` | Cowrie honeypot (added in Step 8) |

**`sg-windows`** (Windows victim)

| Type | Port | Source | Purpose |
|------|------|--------|---------|
| RDP | 3389 | **Your IP** `/32` | Admin access |
| RDP | 3389 | Kali IP `/32` | For the brute-force test only |
| HTTP | 80 | Kali IP `/32` | For DVWA tests (Phase 4) |

> 🔒 Do **not** open 1514, 1515 or 514 to `0.0.0.0/0`. Anyone could then register agents or flood your SIEM with logs.

### Step 3: Launch the Wazuh server (Ubuntu 24.04)

1. **EC2 → Launch instance**
2. Name: `wazuh-soc` | AMI: **Ubuntu Server 24.04 LTS** | Type: `t3.large`
3. Key pair: your existing key
4. Network: your VPC and public subnet | Security group: `sg-wazuh`
5. Storage: **50 GB** gp3 (the indexer stores logs)
6. Launch

Connect:

```bash
chmod 400 my-key.pem
ssh -i my-key.pem ubuntu@<wazuh-public-ip>
```

### Step 4: Install Wazuh (all-in-one)

**Why:** The official installation assistant installs and configures the manager, indexer and dashboard together, and generates the certificates and credentials. This is much more reliable than installing the packages by hand.

```bash
sudo apt-get update && sudo apt-get upgrade -y
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The install takes about 10 to 15 minutes. At the end it prints a generated admin password. **Copy it and store it somewhere safe.**

```
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: <generated-password>
```

Open `https://<wazuh-public-ip>` in your browser. You will see a certificate warning because the certificate is self-signed. That is expected in a lab. Log in as `admin`.

> Lost the password? Run `sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt`.

Verify the services:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

### Step 5: Launch the Windows victim

1. **EC2 → Launch instance**
2. Name: `win-victim` | AMI: **Windows Server 2022 Base** | Type: `t3.medium`
3. Same VPC and subnet as Wazuh | Security group: `sg-windows`
4. Launch, then **Connect → RDP client → Get password** (upload your `.pem`) to decrypt the Administrator password.
5. RDP in with an RDP client and the public IP.

### Step 6: Install the Wazuh agent on Windows

**Why:** The agent runs on the endpoint, collects logs, file changes and system inventory, and ships them securely to the manager.

1. In the Wazuh dashboard, go to **Endpoints → Deploy new agent**.
2. Choose **Windows MSI**, enter the Wazuh server's **private IP** (for example `10.0.1.x`) as the server address, and name the agent `win-victim`.
3. Copy the generated command and run it in **PowerShell as Administrator**. It looks like this:

```powershell
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER="<wazuh-private-ip>" WAZUH_AGENT_NAME="win-victim"
NET START WazuhSvc
Set-Service -Name WazuhSvc -StartupType Automatic
```

Check on the Wazuh server:

```bash
sudo /var/ossec/bin/agent_control -l
```

**Expected output:**

```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-soc (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: win-victim, IP: any, Active
```

### Step 7: Install Sysmon and feed it to Wazuh

**Why:** Default Windows logs are thin. Sysmon records process creation with full command lines, network connections, registry changes and process access (for example LSASS). Almost every rule in this lab depends on it.

On the Windows victim (PowerShell as Administrator):

```powershell
# Download Sysmon and a community-maintained config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath C:\Sysmon -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"

# Install
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

**Tell the agent to read the Sysmon channel.** Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add this inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent:

```powershell
Restart-Service -Name WazuhSvc
```

Verify: in the dashboard, open **Threat Hunting → Events** and search `data.win.system.providerName: "Microsoft-Windows-Sysmon"`. You should see events within a minute or two.

### Step 8: Install Suricata (network IDS)

**Why:** The endpoint agent cannot see network-level activity such as port scans or beaconing. Suricata inspects packets and raises signature-based alerts.

On the Wazuh server:

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt-get update && sudo apt-get install -y suricata
sudo suricata-update            # downloads the Emerging Threats Open ruleset
```

Find your network interface name. On modern EC2 instances it is usually `ens5`, **not** `eth0`:

```bash
ip -br a
```

Edit `/etc/suricata/suricata.yaml`:

- Set `HOME_NET: "[10.0.0.0/16]"`
- Under `af-packet:`, set `- interface: ens5` (use your interface name)
- Make sure the `eve-log` output is enabled (it is by default)

Start it and check the config:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl enable --now suricata
```

**Send Suricata logs to Wazuh.** On the Wazuh server, add this to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-manager
```

> ℹ️ **Visibility limit:** Suricata on the Wazuh host only sees traffic to and from that host. To inspect traffic reaching the Windows instance, use [VPC Traffic Mirroring](https://docs.aws.amazon.com/vpc/latest/mirroring/) (Nitro instances only) or install Suricata on the Windows victim's network path.

### Step 9: Install Cowrie (SSH honeypot)

**Why:** Attackers probe SSH constantly. Cowrie pretends to be a vulnerable SSH server and records every login attempt and typed command.

Cowrie is not a standard apt package. Install it from source as an unprivileged user:

```bash
sudo apt-get install -y git python3-venv libssl-dev libffi-dev build-essential libpython3-dev
sudo adduser --disabled-password --gecos "" cowrie
sudo su - cowrie

git clone https://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
bin/cowrie start
exit
```

Cowrie listens on port **2222** by default, which is why `sg-wazuh` allows 2222 from the internet. **Keep real SSH on 22, restricted to your IP.**

Send its JSON log to Wazuh (`/var/ossec/etc/ossec.conf` on the Wazuh server):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
</localfile>
```

Test: `ssh -p 2222 root@<wazuh-public-ip>` from Kali, try a few passwords, then check `cowrie.json` for `cowrie.login.failed` events.

> ⚠️ A honeypot on the same machine as your SIEM is fine for a lab. In production, isolate honeypots on their own host.

### Step 10: Sync time everywhere

**Why:** Alert timelines and correlation rules need accurate, consistent timestamps.

```bash
# Linux
sudo timedatectl set-ntp true
timedatectl status
```

```powershell
# Windows
w32tm /query /status
w32tm /resync
```

---

## ⚔️ Attack Simulation

Each test follows this loop: **run the attack → find the alert → record the rule ID → note what was missed → write a report.**

### A. Reconnaissance from Kali (T1046 Network Service Discovery)

```bash
nmap -sS -sV -sC <windows-public-ip>
smbclient -L //<windows-public-ip> -N
```

Expected: Suricata scan signatures (if traffic passes through the monitored host) and Windows Filtering Platform events.

### B. RDP brute force from Kali (T1110)

```bash
hydra -L users.txt -P passwords.txt rdp://<windows-public-ip> -t 2
```

Use a small wordlist and low thread count, because RDP rate-limits quickly. Expected: Windows event **4625** failed logons and the custom rule `100103` (see below).

### C. Atomic Red Team (MITRE-mapped)

On the Windows victim, in PowerShell as Administrator:

```powershell
# Lab only: stop Defender from deleting test payloads
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

# Install the framework and the atomics library
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Run techniques:

```powershell
# See what a test does first
Invoke-AtomicTest T1059.001 -ShowDetails -TestNumbers 1

# Check and install prerequisites
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs

# Encoded PowerShell (T1059.001)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# LSASS memory access (T1003.001)
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Registry Run key persistence (T1547.001)
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Always clean up afterwards
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

### D. File Integrity Monitoring (FIM) test

```powershell
New-Item C:\fim_test.txt -Value "SOC Lab Test"
```

Add a monitored folder to the agent's `ossec.conf` under `<syscheck>`:

```xml
<directories realtime="yes" check_all="yes">C:\Users\Administrator\Desktop</directories>
```

Create or change a file there and look for FIM alerts (rule group `syscheck`).

---

## 📝 Custom Detection Rules

Why write your own? Default rules are generic. Custom rules let you detect specific techniques and show analysts what you can do.

Create `/var/ossec/etc/rules/00-custom_rules.xml` on the Wazuh server:

```xml
<group name="custom,sysmon,windows,">

  <!-- T1059.001: Encoded PowerShell (Sysmon Event 1) -->
  <rule id="100101" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}</field>
    <description>Encoded PowerShell execution detected</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- T1003.001: LSASS process access (Sysmon Event 10) -->
  <rule id="100102" level="14">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">0x1010|0x1410|0x1fffff</field>
    <description>Possible credential dumping: LSASS memory access</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <!-- T1110: Brute force, 5 failed logons from one source within 5 minutes -->
  <rule id="100103" level="10" frequency="5" timeframe="300">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Brute force: 5 failed Windows logons from the same source in 5 minutes</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- Cowrie honeypot: failed SSH login -->
  <rule id="100110" level="6">
    <decoded_as>json</decoded_as>
    <field name="eventid">cowrie.login.failed</field>
    <description>Cowrie honeypot: failed SSH login attempt</description>
  </rule>

</group>
```

**Test before deploying** with Wazuh's rule tester:

```bash
sudo /var/ossec/bin/wazuh-logtest
# Paste a sample log line and confirm the rule ID that fires
```

Apply the rules:

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/00-custom_rules.xml
sudo systemctl restart wazuh-manager
```

> 💡 Field names and base rule IDs can differ between Wazuh versions. Use `wazuh-logtest` and the dashboard's JSON view of a real event to confirm exact field names such as `win.eventdata.ipAddress`.

---

## 🚫 Active Response (Auto-Block)

Active Response runs a script on an endpoint when a rule fires. Add this to the **manager's** `/var/ossec/etc/ossec.conf`:

```xml
<!-- Block brute-force sources on the Windows agent -->
<active-response>
  <command>netsh</command>
  <location>local</location>
  <rules_id>100103</rules_id>
  <timeout>600</timeout>
</active-response>

<!-- Block honeypot attackers on the Linux manager (iptables) -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100110</rules_id>
  <timeout>3600</timeout>
</active-response>
```

> ⚠️ `firewall-drop` is Linux-only (iptables). Windows agents use `netsh`. Whitelist your own IP under `<global><white_list>` so you can't lock yourself out. Test with low timeouts first.

Check the blocks:

```bash
sudo iptables -L -n | grep DROP          # Linux
```
```powershell
netsh advfirewall firewall show rule name=all | findstr /i "wazuh"   # Windows
```

---

## 📸 Output Screenshots

Capture **your own** screenshots as proof of a working lab. Real, dated evidence is what makes a portfolio credible. Save the images under `screenshots/` with the names below and they will render automatically.

> 🔸 Redact public IPs, account IDs and any passwords or API keys before publishing.

### 1. Wazuh dashboard overview, agent active
**Capture:** Dashboard home showing **1+ active agents** and alert counts.
![Wazuh dashboard overview](screenshots/01-dashboard-overview.png)

### 2. Sysmon events flowing into Wazuh
**Capture:** **Threat Hunting → Events** filtered by `data.win.system.providerName: "Microsoft-Windows-Sysmon"` with events listed.
![Sysmon events](screenshots/02-sysmon-events.png)

### 3. Custom rule 100101 firing (encoded PowerShell)
**Capture:** The alert after running `Invoke-AtomicTest T1059.001 -TestNumbers 1`. Expand the alert to show `rule.id: 100101`, the command line and the MITRE tag.
![Encoded PowerShell alert](screenshots/03-alert-encoded-powershell.png)

### 4. RDP brute force detected (rule 100103)
**Capture:** Failed-logon alerts (event 4625) plus the frequency alert after the Hydra run.
![RDP brute force alert](screenshots/04-rdp-bruteforce.png)

### 5. MITRE ATT&CK coverage
**Capture:** **Threat Intelligence → MITRE ATT&CK** (the exact menu name varies by version) showing the techniques you triggered.
![MITRE ATT&CK view](screenshots/05-mitre-attack.png)

**Optional extras:** Suricata alert from an nmap scan, a Cowrie credential-capture event, an Active Response block entry.

---

## 🔎 Investigating Alerts

| Dashboard area | What to use it for |
|----------------|--------------------|
| **Overview** | Alert volume, agent health |
| **Threat Hunting → Events** | Search raw events (filter by `rule.id`, `agent.name`, `data.srcip`) |
| **MITRE ATT&CK** | Map alerts to tactics and techniques, find coverage gaps |
| **File Integrity Monitoring** | Track file and registry changes |
| **Configuration Assessment (SCA)** | CIS benchmark checks for hardening |
| **Vulnerability Detection** | CVEs found on endpoints |
| **Rules** (Server management) | View and edit decoders and rules |

**Useful queries:**

```
rule.id: 100101
rule.mitre.id: T1003.001
agent.name: win-victim AND rule.level >= 10
```

---

## 📄 Incident Report Template

Write one per simulated attack and save it in `reports/`.

```markdown
## Incident #00X: [Title]

**Date:** YYYY-MM-DD
**Analyst:** [Name]
**Severity:** Low / Medium / High / Critical

### Summary
[1-2 sentences: what happened]

### Attack Details
- **Technique:** T1059.001 (PowerShell)
- **Tool / Command:** `Invoke-AtomicTest T1059.001 -TestNumbers 1`

### Timeline
| Time (UTC) | Event |
|------------|-------|
| 10:00:00 | Attack executed |
| 10:00:03 | Wazuh alert 100101 fired |
| 10:05:00 | Investigation started |

### IOCs
| Type | Value |
|------|-------|
| IP | x.x.x.x |
| Process | powershell.exe -enc ... |
| Hash | sha256... |

### MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | PowerShell | T1059.001 |

### Detection
- **Rule ID / Level:** 100101 / 12
- **What it caught:** ...
- **What it MISSED (gap):** ...
- **How to close the gap:** new rule / extra telemetry

### Response
- [ ] Contained
- [ ] Eradicated
- [ ] Recovered
- [ ] Lessons learned

### Evidence
![Alert](../screenshots/03-alert-encoded-powershell.png)
```

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---------|-----|
| Agent shows **Disconnected** | Use the manager's **private IP** and confirm `sg-wazuh` allows 1514/1515 from the VPC CIDR. Check `C:\Program Files (x86)\ossec-agent\ossec.log`. |
| No Sysmon events | Verify the `eventchannel` block in the agent's `ossec.conf` and run `Restart-Service WazuhSvc`. |
| Dashboard won't load | Check `sudo systemctl status wazuh-dashboard`. The instance may be out of RAM, so use `t3.large`. |
| Custom rule never fires | Run `wazuh-logtest`, check the exact field names in a real event and look for XML errors in `/var/ossec/logs/ossec.log`. |
| Suricata shows no alerts | Confirm the right interface (`ip -br a`) and that the traffic actually reaches that host (see the visibility note). |
| Atomic test blocked | Windows Defender is deleting payloads. Add the lab exclusion shown above, in this lab only. |
| Alert times look wrong | Fix NTP/time zone on all hosts (Step 10). |

---

## 💰 Cost Management & Cleanup

| Action | Command |
|--------|---------|
| Stop instances | `aws ec2 stop-instances --instance-ids i-xxx i-yyy` |
| List running instances | `aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query "Reservations[].Instances[].InstanceId"` |
| Terminate when finished | `aws ec2 terminate-instances --instance-ids i-xxx i-yyy` |

- ⚠️ **Stopped instances still incur EBS storage charges.** Terminate and delete volumes when you are done.
- Release unused **Elastic IPs**, which are billed when idle.
- Set an **AWS Budget alert** (Billing → Budgets) before you begin.

---

## 📚 Learning Path

| Phase | Focus | Duration |
|-------|-------|----------|
| 1 | Wazuh + Agent + Sysmon | Week 1 |
| 2 | Custom rules + Atomic Red Team + MITRE mapping | Week 2 |
| 3 | Suricata + Cowrie (network layer) | Week 3 |
| 4 | DVWA + web attack detection (IIS logs) | Week 4 |
| 5 | Active Response + threat-intel integrations (VirusTotal, AbuseIPDB) | Week 5 |
| 6 | Domain Controller + AD attacks (Kerberoasting T1558.003, pass-the-hash T1550.002) | Week 6 |
| 7-8 | Full kill chain (recon → C2 → lateral movement → exfil), documented end to end | Week 7-8 |

---

## 📂 Project Structure

```
aws-soc-lab/
├── README.md
├── configs/
│   ├── wazuh/
│   │   ├── ossec.conf
│   │   └── rules/
│   │       └── 00-custom_rules.xml
│   ├── sysmon/
│   │   └── sysmonconfig.xml
│   └── suricata/
│       └── suricata.yaml
├── attacks/
│   ├── nmap/
│   ├── hydra/
│   └── atomic-red-team/
├── reports/
│   ├── incident-001-nmap-scan.md
│   ├── incident-002-rdp-brute-force.md
│   └── incident-003-lsass-dump.md
└── screenshots/
    ├── 01-dashboard-overview.png
    ├── 02-sysmon-events.png
    ├── 03-alert-encoded-powershell.png
    ├── 04-rdp-bruteforce.png
    └── 05-mitre-attack.png
```

> 🔐 **Before you push to GitHub:** remove API keys (VirusTotal, AbuseIPDB), passwords, `.pem` files and public IPs from every config and screenshot. Add them to `.gitignore`.

---

## 🙏 Credits

[Wazuh](https://wazuh.com) · [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) · [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) · [Suricata](https://suricata.io) · [Cowrie](https://github.com/cowrie/cowrie) · [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) · [MITRE ATT&CK](https://attack.mitre.org)

