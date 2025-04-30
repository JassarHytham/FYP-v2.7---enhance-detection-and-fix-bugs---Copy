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

## License

# License

Copyright (c) 2025 Jassar

## Terms of Use

1. **Proprietary Software**
   - This software is proprietary and confidential.
   - All rights are reserved by Jassar.
   - Unauthorized copying, modification, distribution, or use of this software is strictly prohibited.

2. **Usage Restrictions**
   - This software may only be used for authorized network traffic analysis and security assessment purposes.
   - Any malicious use, including but not limited to network attacks or unauthorized surveillance, is strictly prohibited.

3. **Warranty Disclaimer**
   - THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
   - The author makes no warranties regarding the software's fitness for any particular purpose.
   - The author is not liable for any damages or losses arising from the use of this software.

4. **Academic and Research Use**
   - Use of this software for academic research purposes requires written permission from the author.
   - All publications or presentations using this software must properly cite and acknowledge the author.

5. **Distribution**
   - Redistribution in any form is prohibited without explicit written permission from the author.
   - The software and its components may not be incorporated into other products without authorization.

6. **Modifications**
   - Users may not modify, decompile, reverse engineer, or create derivative works based on this software.
   - All improvements or modifications must be submitted to the original author for review.

7. **Data Privacy**
   - Users must comply with all applicable data protection and privacy laws when using this software.
   - The author is not responsible for any privacy violations resulting from improper use.

8. **Termination**
   - This license is effective until terminated.
   - The author reserves the right to terminate the license at any time if terms are violated.

9. **Governing Law**
   - This license shall be governed by and construed in accordance with the laws of Saudi Arabia.

## Contact Information

For licensing inquiries or permissions, please contact:
- Author: Jassar
- Email: Jassar.official@gmail.com
- Institution: Asia Pacific University

## Citation

If you use this software in your research, please cite as:
```
Jassar. (2025). Enhanced Network Traffic Analysis for Identifying Suspicious Activities in Cybersecurity. [Software].
```

All rights reserved © 2024 Jassar
## Author

Your Name
Jassar
