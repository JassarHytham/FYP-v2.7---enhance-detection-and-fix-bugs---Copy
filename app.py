from collections import Counter, defaultdict
from datetime import datetime
import os
import sys
import io
from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash, jsonify
import re
from werkzeug.utils import secure_filename
from TrafficAnalyzer import TrafficAnalyzer
import json
import requests

app = Flask(__name__, static_url_path='/static')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")  # Set this in your environment


# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.root_path, 'reports'), exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        flash('No file part in the request.')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.')
        return redirect(url_for('index'))
    
    # Save the file securely
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # Check PDF generation preference
    generate_pdf = 'generate_pdf' in request.form
    
    # Instantiate the analyzer with the uploaded file
    analyzer = TrafficAnalyzer(file_path=filepath)
    
    # Capture console output by redirecting stdout
    output_stream = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = output_stream
    
    try:
        # Pass the generate_pdf flag to the analysis
        analyzer.run_analysis(generate_pdf=generate_pdf)
        
        # Load the generated JSON report
        with open('reports/latest_analysis.json') as f:
            report_data = json.load(f)
            
        # Extract metadata
        metadata = report_data.get('metadata', {})
        
        # Extract scores with fallback to zeros if not found
        threat_scores = report_data.get('threat_analysis', {}).get('scores', {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        })
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        flash(f"Analysis error: {str(e)}")
        return redirect(url_for('index'))
    finally:
        sys.stdout = old_stdout  # Restore stdout
        
    analysis_output = output_stream.getvalue()
    
    # Only get PDF filename if generation was requested and available
    pdf_filename = os.path.basename(analyzer.pdf_file) if generate_pdf and analyzer.pdf_file else None
    
    return render_template('results.html', 
                         analysis_output=analysis_output,
                         pdf_filename=pdf_filename,
                         file_path=metadata.get('file_path', 'Unknown'),
                         analysis_date=metadata.get('analysis_date', 'Unknown'),
                         analysis_duration=metadata.get('analysis_duration', 'Unknown'),
                         total_packets=metadata.get('total_packets', 0),
                         critical_count=threat_scores['critical'],
                         high_count=threat_scores['high'],
                         medium_count=threat_scores['medium'],
                         low_count=threat_scores['low'])


# In get_visualization_data() endpoint
@app.route('/get_visualization_data')
def get_visualization_data():
    report_filename = request.args.get('report', 'latest_analysis.json')
    try:
        report_path = os.path.join(app.root_path, 'reports', report_filename)
        with open(report_path) as f:
            data = json.load(f)
        
        # 1. Protocol Distribution - Use statistics section
        stats = data.get('statistics', {})
        protocol_data = {
            'tcp': stats.get('tcp_packets', 0),
            'udp': stats.get('udp_packets', 0),
            'icmp': stats.get('icmp_packets', 0),
            'arp': stats.get('arp_packets', 0),
            'dns': stats.get('dns_packets', 0)
        }
        
        # 2. Timeline Data - Create from metadata if needed
        if 'temporal_analysis' in data:
            timeline_data = [
                {'timestamp': window, 'count': stats['count']}
                for window, stats in data['temporal_analysis'].items()
            ]
            timeline_data.sort(key=lambda x: x['timestamp'])
        else:
            # Fallback to using busiest_minute if available
            timeline_data = []
            if 'busiest_minute' in data.get('statistics', {}):
                minute = data['statistics']['busiest_minute']
                timeline_data.append({
                    'timestamp': minute['minute'],
                    'count': minute['packet_count']
                })
        
        # 3. Topology Data - Try to get from detailed_findings if available
        nodes = set()
        links = []
        
        if 'detailed_findings' in data:
            for packet in data['detailed_findings']:
                src_ip = packet.get('src_ip')
                dst_ip = packet.get('dst_ip')
                if src_ip and dst_ip:
                    nodes.add(src_ip)
                    nodes.add(dst_ip)
                    links.append({
                        'source': src_ip,
                        'target': dst_ip,
                        'value': 1  # Default value
                    })
        
        # If no detailed findings, use unique IPs from statistics
        if not nodes and 'statistics' in data:
            if data['statistics'].get('unique_source_ips', 0) > 0:
                nodes.add("Source_IPs")
            if data['statistics'].get('unique_destination_ips', 0) > 0:
                nodes.add("Destination_IPs")
            if nodes:
                links.append({
                    'source': "Source_IPs",
                    'target': "Destination_IPs",
                    'value': data['statistics'].get('total_packets', 1)
                })
        
        return jsonify({
            'protocol_distribution': protocol_data,
            'timeline_data': timeline_data,
            'topology_data': {
                'nodes': [{'id': ip, 'label': ip} for ip in nodes],
                'links': links
            }
        })
        
    except Exception as e:
        app.logger.error(f"Visualization error: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'protocol_distribution': {
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'arp': 0,
                'dns': 0
            },
            'timeline_data': [],
            'topology_data': {
                'nodes': [],
                'links': []
            }
        }), 500
    
@app.route('/get_timeline_data')
def get_timeline_data():
    report_filename = request.args.get('report', 'latest_analysis.json') 
    try:
        report_path = os.path.join(app.root_path, 'reports', report_filename)  # Modified
        with open(report_path) as f:  # Changed from hardcoded path
            data = json.load(f)
        
        # Aggregate packets by minute
        time_counts = defaultdict(int)
        for packet in data['packet_reports']:
            if 'timestamp' in packet:
                try:
                    # Parse timestamp to datetime object
                    dt = datetime.fromisoformat(packet['timestamp'].replace('Z', '+00:00'))
                    # Truncate to minute and convert back to ISO format
                    minute_key = dt.replace(second=0, microsecond=0).isoformat()
                    time_counts[minute_key] += 1
                except ValueError:
                    continue
        
        # Convert to list of {timestamp, count} sorted chronologically
        aggregated_data = [
            {'timestamp': k, 'count': v} 
            for k, v in sorted(time_counts.items(), key=lambda x: x[0])
        ]
        
        return jsonify(aggregated_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_topology_data')
def get_topology_data():
    report_filename = request.args.get('report', 'latest_analysis.json')  # Add this
    report_path = os.path.join(app.root_path, 'reports', report_filename)  # Modified
    with open(report_path) as f:  # Changed from hardcoded path
        data = json.load(f)
    return jsonify({
        'nodes': list(set([p['src_ip'] for p in data['packet_reports'] if p['src_ip']])),
        'links': [{'source': p['src_ip'], 'target': p['dst_ip']} 
                 for p in data['packet_reports'] if p['src_ip'] and p['dst_ip']]
    })
    
@app.route('/DeepSeek_Reports/<path:filename>')
def serve_report(filename):
    reports_dir = os.path.join(os.getcwd(), 'DeepSeek_Reports')
    return send_from_directory(reports_dir, filename)

@app.route('/logs')
def view_logs():
    log_file = os.path.join('logs', 'traffic_analysis.log')  # Updated path to include the logs folder
    try:
        with open(log_file, 'r') as f:
            log_entries = f.read().split('\n')
        # Reverse to show latest entries first
        log_entries = [entry for entry in reversed(log_entries) if entry.strip()]
        return render_template('logs.html', log_entries=log_entries)
    except FileNotFoundError:
        flash('Log file not found yet. Perform an analysis first.')
        return redirect(url_for('index'))

@app.route('/history')
def view_history():
    reports_dir = os.path.join(app.root_path, 'reports')
    pdf_dir = os.path.join(os.getcwd(), 'DeepSeek_Reports')
    
    try:
        reports = []
        for filename in os.listdir(reports_dir):
            if filename.endswith('.json') and filename != 'latest_analysis.json':
                try:
                    # Extract base information
                    parts = filename.split('_report_')
                    original_name = parts[0]
                    timestamp_str = parts[1].split('.')[0]
                    timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                    # Find matching PDF report
                    pdf_filename = f"security_report_{timestamp_str}.pdf"
                    pdf_path = os.path.join(pdf_dir, pdf_filename)
                    
                    report_data = {
                        'filename': filename,
                        'original_name': original_name,
                        'timestamp': timestamp,
                        'display_name': f"{original_name} - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                        'pdf_filename': pdf_filename if os.path.exists(pdf_path) else None
                    }
                    
                    reports.append(report_data)
                    
                except Exception as e:
                    print(f"Skipping invalid filename {filename}: {str(e)}")
                    continue
        
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        return render_template('history.html', reports=reports)
    
    except Exception as e:
        flash(f'Error loading history: {str(e)}')
        return redirect(url_for('index'))

from TrafficAnalyzer import TrafficAnalyzer  # adjust if needed

@app.route('/view_report/<filename>')
def view_report(filename):
    try:
        report_path = os.path.join(app.root_path, 'reports', filename)

        if not os.path.exists(report_path):
            flash('Report file not found', 'error')
            return redirect(url_for('view_history'))

        with open(report_path) as f:
            report_data = json.load(f)

        analyzer = TrafficAnalyzer(file_path=report_data.get('metadata', {}).get('file_path', ''))

        # Initialize data structures
        nmap_scans = Counter()
        arp_entries = defaultdict(set)
        icmp_tunnel = 0
        dns_tunnel = 0
        anomaly_ips = []
        anomaly_counts = Counter()
        suspicious_ips = []

        if 'threat_analysis' in report_data and 'suspicious_ips' in report_data['threat_analysis']:
            suspicious_ips = report_data['threat_analysis']['suspicious_ips']

        # Temporal analysis for ARP poisoning
        if 'temporal_analysis' in report_data:
            for minute_data in report_data['temporal_analysis'].values():
                for detection in minute_data.get('detections', []):
                    if 'arp poisoning' in detection.lower():
                        ip_match = re.search(r'IP ([\d.]+)', detection)
                        if ip_match:
                            ip = ip_match.group(1)
                            arp_entries[ip].add("multiple")

        # Parse detailed findings
        for packet in report_data.get('detailed_findings', []):
            for detail in packet.get('detection_details', []):
                detail_lower = detail.lower()

                if 'scan' in detail_lower:
                    if 'syn scan' in detail_lower:
                        nmap_scans['syn'] += 1
                    elif 'xmas scan' in detail_lower:
                        nmap_scans['xmas'] += 1
                    elif 'null scan' in detail_lower:
                        nmap_scans['null'] += 1
                    elif 'fin scan' in detail_lower:
                        nmap_scans['fin'] += 1
                    elif 'udp scan' in detail_lower:
                        nmap_scans['udp'] += 1
                    elif 'tcp connect' in detail_lower:
                        nmap_scans['tcp_connect'] += 1

                elif 'arp poisoning' in detail_lower:
                    ip_match = re.search(r'IP ([\d.]+)', detail)
                    if ip_match:
                        ip = ip_match.group(1)
                        arp_entries[ip].add("multiple")
                elif 'arp' in detail_lower or 'poisoning' in detail_lower:
                    ip_mac = re.search(r'IP ([\d.]+).*MAC: ([\w:]+)', detail)
                    if ip_mac:
                        ip = ip_mac.group(1)
                        mac = ip_mac.group(2)
                        arp_entries[ip].add(mac)

                elif 'icmp tunnel' in detail_lower:
                    icmp_tunnel += 1
                elif 'dns tunnel' in detail_lower:
                    dns_tunnel += 1

                elif 'anomal' in detail_lower or 'unusual' in detail_lower:
                    ip_match = re.search(r'IP ([\d.]+)', detail)
                    if ip_match:
                        ip = ip_match.group(1)
                        anomaly_counts[ip] += 1
                        if ip not in anomaly_ips:
                            anomaly_ips.append(ip)

        # ARP poisoning cases
        arp_poisoning_cases = {}
        for ip, macs in arp_entries.items():
            if len(macs) > 1 or "multiple" in macs:
                arp_poisoning_cases[ip] = list(macs)

        # Prepare anomaly data as list of dicts
        anomaly_data = [{'ip': ip} for ip in anomaly_ips]

        # Combine with suspicious_ips
        all_anomalous_ips = anomaly_data + suspicious_ips

        # Capture the output
        output_stream = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_stream

        analyzer.print_results(
            nmap_scan_detected=nmap_scans,
            arp_poisoning_seen=arp_poisoning_cases,
            icmp_tunnel=icmp_tunnel,
            dns_tunnel=dns_tunnel,
            anomaly_detected=[item['ip'] if isinstance(item, dict) else item for item in all_anomalous_ips]
        )

        sys.stdout = old_stdout
        analysis_output = output_stream.getvalue()

        metadata = report_data.get('metadata', {})
        threat_scores = report_data.get('threat_analysis', {}).get('scores', {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        })

        pdf_filename = None
        if '_report_' in filename:
            timestamp_part = filename.split('_report_')[1].split('.')[0]
            pdf_filename = f"security_report_{timestamp_part}.pdf"
            pdf_path = os.path.join(app.root_path, 'DeepSeek_Reports', pdf_filename)
            if not os.path.exists(pdf_path):
                pdf_filename = None

        return render_template(
            'results.html',
            analysis_output=analysis_output,
            pdf_filename=pdf_filename,
            file_path=metadata.get('file_path', 'Unknown'),
            analysis_date=metadata.get('analysis_date', 'Unknown'),
            analysis_duration=metadata.get('analysis_duration', 'Unknown'),
            total_packets=metadata.get('total_packets', 0),
            critical_count=threat_scores['critical'],
            high_count=threat_scores['high'],
            medium_count=threat_scores['medium'],
            low_count=threat_scores['low'],
            report_filename=filename,
            suspicious_ips=suspicious_ips,
            all_anomalous_ips=all_anomalous_ips
        )
    except Exception as e:
        flash(f"Error loading report: {str(e)}", 'error')
        return redirect(url_for('view_history'))


def generate_analysis_output(report_data):
    """Generate formatted analysis output with properly organized findings"""
    output = []
    
    # Start with the standard header
    output.append("=== ANALYSIS RESULTS SUMMARY ===")
    
    # Initialize detection storage by category
    detections = {
        'scan': [],
        'arp': [],
        'tunneling': [],
        'anomalies': []
    }
    
    # Categorize all detections first
    if 'detailed_findings' in report_data:
        for finding in report_data['detailed_findings']:
            for detail in finding.get('detection_details', []):
                detail_lower = detail.lower()
                if 'scan' in detail_lower:
                    detections['scan'].append(detail)
                elif 'arp' in detail_lower or 'poisoning' in detail_lower:
                    detections['arp'].append(detail)
                elif 'tunneling' in detail_lower:
                    detections['tunneling'].append(detail)
                else:
                    detections['anomalies'].append(detail)
    
    # 1. Network Scan Detection
    output.append("\n• Network Scan Detection:")
    if detections['scan']:
        for detection in detections['scan']:
            if 'syn scan' in detection.lower():
                output.append(f"  [CRITICAL] {detection}")
            elif 'udp scan' in detection.lower():
                output.append(f"  [HIGH] {detection}")
            else:
                output.append(f"  [WARNING] {detection}")
    else:
        output.append("  [INFO] No network scanning activity detected")
    
    # 2. ARP Security Analysis
    output.append("\n• ARP Security Analysis:")
    if detections['arp']:
        output.append("  [CRITICAL] ARP cache poisoning detected!")
        for detection in detections['arp']:
            output.append(f"    - {detection}")
    else:
        output.append("  [INFO] No ARP spoofing detected")
    
    # 3. Covert Channel Analysis
    output.append("\n• Covert Channel Analysis:")
    if detections['tunneling']:
        icmp_count = sum(1 for d in detections['tunneling'] if 'icmp' in d.lower())
        dns_count = sum(1 for d in detections['tunneling'] if 'dns' in d.lower())
        
        if icmp_count > 0:
            output.append(f"  [CRITICAL] ICMP tunneling detected ({icmp_count} packets)")
        if dns_count > 0:
            output.append(f"  [CRITICAL] DNS tunneling detected ({dns_count} packets)")
        
        # Show first 3 examples of each type
        shown_icmp = 0
        shown_dns = 0
        for detection in detections['tunneling']:
            if 'icmp' in detection.lower() and shown_icmp < 3:
                output.append(f"    - {detection}")
                shown_icmp += 1
            elif 'dns' in detection.lower() and shown_dns < 3:
                output.append(f"    - {detection}")
                shown_dns += 1
    else:
        output.append("  [INFO] No covert channel activity detected")
    
    # 4. Traffic Anomalies
    output.append("\n• Traffic Anomalies:")
    if detections['anomalies']:
        anomaly_counts = Counter(detections['anomalies'])
        for detection, count in anomaly_counts.most_common(3):
            if count > 10:
                output.append(f"  [CRITICAL] {detection} ({count} occurrences)")
            elif count > 5:
                output.append(f"  [HIGH] {detection} ({count} occurrences)")
            else:
                output.append(f"  [MEDIUM] {detection} ({count} occurrences)")
    else:
        output.append("  [INFO] No significant traffic anomalies detected")
    
    # 5. Security Posture Assessment
    output.append("\n• Security Posture Assessment:")
    severity = report_data.get('threat_analysis', {}).get('scores', {}).get('severity', 'Low')
    output.append(f"  [INFO] Overall Network Security Posture: {severity.upper()}")
    
    output.append("\n=== END OF REPORT ===")
    return "\n".join(output)


@app.template_filter('format_output')
def format_output(text):
    if isinstance(text, dict):
        # Handle JSON report data
        output = []
        output.append("=== ANALYSIS RESULTS SUMMARY ===")
        
        # Add sections from JSON data
        if text.get('threat_analysis'):
            output.append("\n• Threat Analysis:")
            for level, count in text['threat_analysis']['scores'].items():
                if count > 0:
                    output.append(f"  [{level.upper()}] {count} {level} severity findings")
        
        # Add other sections...
        return [section for section in output if section.strip()]
    
    # Original text processing for console output
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned = ansi_escape.sub('', text)
    return [section for section in cleaned.split('\n\n') if section.strip()]



@app.route('/virustotal_check', methods=['POST'])
def virustotal_check():
    try:
        app.logger.debug("Received VirusTotal check request")
        data = request.get_json()
        app.logger.debug(f"Request data: {data}")
        data = request.get_json()
        target = data.get('target')
        target_type = data.get('type')  # 'ip' or 'domain'
        
        if not target or not target_type:
            return jsonify({'error': 'Missing target or type'}), 400
        
        try:
            # Configure your VirusTotal API key
            VT_API_KEY = ('046c09eb9f8b3ff30c4c5fac4aee7ca12a60d692c244de8ca013e553e6563da0')  # Recommended: store in environment variables
            
            headers = {
                'x-apikey': VT_API_KEY,
                'Accept': 'application/json'
            }
            
            if target_type == 'ip':
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{target}'
            elif target_type == 'domain':
                url = f'https://www.virustotal.com/api/v3/domains/{target}'
            else:
                return jsonify({'error': 'Invalid type'}), 400
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raises exception for 4XX/5XX status codes
            
            return jsonify(response.json())
        
            
        except requests.exceptions.RequestException as e:
            return jsonify({
                'error': f'VirusTotal API error: {str(e)}',
                'details': f'Status code: {e.response.status_code if hasattr(e, "response") else "N/A"}'
        }), 500
    except Exception as e:
        app.logger.error(f"Error in virustotal_check: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
def test_vt_key(api_key, ip='8.8.8.8'):
    headers = {'x-apikey': api_key}
    response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers=headers)
    print(f"Status: {response.status_code}")
    print(response.json())
    
@app.template_filter('extract_ip')
def extract_ip_filter(text):
    import re
    ip_match = re.search(r'(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)(?::\d+)?', text)
    return ip_match.group(0).split(':')[0] if ip_match else None

if __name__ == '__main__':
    app.run(debug=True)