# TSF (TopoState-Fuzzer)

**TopoState-Fuzzer (TSF)** is the first topology-state heuristic fuzzer designed specifically for the OpenFlow Discovery Protocol (OFDP) in Software-Defined Networking (SDN). It automates the discovery of deep-seated protocol implementation flaws and logic vulnerabilities in SDN controllers by leveraging topology state guidance and Multidimensional feedback.

## 🌟 Key Features

- **Scenario-Aware Test Generation:** Targets contextual vulnerabilities involving multiple OFDP packets by mutating pre-defined scenario streams rather than isolated packets.


- **Multi-Source SDN Oracle:** Continuously monitors controller behavior (anomalies), link communication states, and global topology consistency to capture silent or deep-seated bugs.


- **Semantic-Operational Feedback:** Replaces conventional code-coverage with an SDN-specific feedback model to dynamically optimize the MOPT scheduler's strategy selection.


- **Automated Scripted Restarts:** Eliminates state caching and pollution by enforcing a complete environment reset (graceful shutdown and restart) after each test cycle, ensuring high reliability and a low false-positive rate.


- **Low Overhead:** Maintains stable memory usage (140 MB to 160 MB) and extremely low average CPU utilization (2% to 6%) under high-concurrency conditions.



## 🐛 Discovered Vulnerabilities

TSF has been evaluated on three mainstream SDN controllers and successfully uncovered several critical, previously unknown vulnerabilities:

| CVE-ID | Controller | Type | Description |
| --- | --- | --- | --- |
| **CVE-2025-29310** | ONOS | Syntactic | A malformed LLDP End TLV triggers a deserialization failure, causing switch reconnections, flow-table loss, and DoS.|
| **CVE-2025-29312** | ONOS | Syntactic | Forged LLDP packets permanently convert non-direct links to direct links, leading to topology deception.|
| **CVE-2025-45480** | Floodlight | Semantic | Link-spoofing misclassifies host ports as non-boundary, blocking Packet-In forwarding and flow rule installation.|
| **Pending** | OpenDaylight | Semantic | Incomplete signature validation allows attackers to modify TLV fields while preserving the original signature to fabricate malicious links.|

## ⚙️ Environment Prerequisites

To avoid network I/O bottlenecks and ensure stable fuzzing execution, it is recommended to co-locate TSF, the Mininet emulator, and the target controller on a dedicated high-performance server (e.g., Ubuntu, Intel Xeon, 64GB RAM).

- **OS:** Ubuntu Linux 
- **Python:** Python 3 (For the TSF framework)
- **Emulator:** Mininet v2.2.2 
- **Core Libraries:** `Pwntools` (for lifecycle management), `Scapy` (for packet injection), `NetworkX` & `JSON` (for topology graph consistency checking).


## 🚀 Target Controller Deployment

For reproducible results, deploy the specific controller versions tested (During the test, simply select a running option):

### 1. ONOS (v2.7.0-rc2)

```bash
# Build and run ONOS with a clean debug state
bazel run onos-local -- clean debug

```

*Note: The Web UI is accessible at `http://localhost:8181/onos/ui` (Default credentials: `onos/rocks`).*

### 2. Floodlight (v1.2)

```bash
# Compile and run the Fat Jar
ant
java -jar target/floodlight.jar

```

### 3. OpenDaylight (v20.3 / Calcium SR3)

Ensure `JAVA_HOME` is set to JDK 11 before starting.

```bash
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
./bin/karaf

```

Inside the Karaf console, install the necessary topology features:

```bash
feature:install odl-openflowplugin-app-topology-lldp-discovery odl-openflowplugin-app-table-miss-enforcer odl-openflowplugin-flow-services odl-openflowplugin-flow-services-rest odl-openflowplugin-app-topology-manager odl-openflowplugin-app-lldp-speaker

```

## 🛠️ Installation & Usage

**1. Clone the repository**

```bash
git clone https://github.com/Saber-Berserker/TSF.git
cd TSF

```

**2. Install Python dependencies**

```bash
pip3 install -r requirements.txt

```

**3. Configure the Fuzzer**
Edit the `config.toml` file in the root directory to specify your target controller, IP, OpenFlow port (e.g., 6653 or 6633), and desired fuzzing parameters.

**4. Start the Fuzzing Campaign**
TSF requires root privileges to operate Mininet and inject raw Ethernet frames.

```bash
sudo python3 Main.py

```

## 📊 Topology Design

TSF evaluates the controllers using a hybrid, asymmetric topology that incorporates both SDN switches and legacy switches. This design effectively triggers the controller's boundary logic and exposes potential defects in path computation and topology discovery. You can find the topology scripts in the `topologies`/`topography` directory.
