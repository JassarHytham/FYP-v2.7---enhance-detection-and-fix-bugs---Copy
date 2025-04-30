# A sophisticated network traffic analysis tool that detects and reports security threats, malicious activities, and network anomalies in PCAP files.

## Features

- **Advanced Traffic Analysis**
  - Network scan detection (SYN, UDP scans)
  - ARP poisoning detection
  - Covert channel detection (ICMP/DNS tunneling)
  - Traffic anomaly detection
  - Protocol distribution analysis

- **Interactive Visualization**
  - Real-time traffic timeline
  - Protocol distribution charts
  - Network topology visualization
  - Interactive threat analysis dashboard

- **Reporting**
  - Detailed PDF report generation
  - Severity-based threat classification
  - Historical analysis storage
  - Real-time logging system

- **Security Features**
  - VirusTotal API integration
  - Domain/IP reputation checking
  - Threat scoring system
  - Detailed security recommendations

## Installation

1. Clone the repository
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Key configuration files and directories:
- `/logs` - Application logs
- `/reports` - JSON analysis reports
- `/DeepSeek_Reports` - Generated PDF reports
- `/static` - Static web assets
- `/templates` - HTML templates

## Usage

1. Start the application:
```bash
python app.py
```

2. Access the web interface at `http://localhost:5000`

3. Upload a PCAP file for analysis:
   - Drag and drop or select a PCAP file
   - Enable/disable PDF report generation
   - Click "ANALYZE TRAFFIC"

## Key Components

- **TrafficAnalyzer**: Core analysis engine
- **ReportGenerator**: PDF report generation
- **Flask Application**: Web interface and API endpoints
- **Visualization Engine**: D3.js and Plotly based visualizations

## Project Structure

```
├── app.py                 # Main Flask application
├── ReportGenerator.py     # PDF report generation
├── TrafficAnalyzer.py     # Traffic analysis engine
├── requirements.txt       # Python dependencies
├── static/               # Static assets
│   ├── css/             # Stylesheets
│   └── js/              # JavaScript files
├── templates/            # HTML templates
├── DeepSeek_Reports/    # Generated PDF reports
├── logs/                # Application logs
└── reports/             # Analysis reports (JSON)
```

## API Endpoints

- `/analyze` - Upload and analyze PCAP files
- `/get_visualization_data` - Fetch visualization data
- `/get_timeline_data` - Get timeline analysis
- `/get_topology_data` - Get network topology
- `/virustotal_check` - VirusTotal API integration

## Requirements

- Python 3.x
- Flask
- Plotly
- D3.js
- ReportLab (PDF generation)
- Additional requirements in requirements.txt

## Security Features

- Real-time threat detection
- ARP poisoning detection
- Network scan identification
- Covert channel detection
- Traffic anomaly detection
- IP/Domain reputation checking
