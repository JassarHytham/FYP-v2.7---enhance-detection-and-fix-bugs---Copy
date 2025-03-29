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

app = Flask(__name__, static_url_path='/static')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key

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
    except Exception as e:
        print(f"Error during analysis: {e}")
    finally:
        sys.stdout = old_stdout  # Restore stdout
        
    analysis_output = output_stream.getvalue()
    
    # Only get PDF filename if generation was requested and available
    pdf_filename = os.path.basename(analyzer.pdf_file) if generate_pdf and analyzer.pdf_file else None
    
    return render_template('results.html', 
                           analysis_output=analysis_output,
                           pdf_filename=pdf_filename)

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
    log_file = 'traffic_analysis.log'
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

@app.route('/view_report/<filename>')
def view_report(filename):
    try:
        report_path = os.path.join(app.root_path, 'reports', filename)
        
        # Verify the report exists
        if not os.path.exists(report_path):
            flash('Report file not found', 'error')
            return redirect(url_for('view_history'))
            
        with open(report_path) as f:
            report_data = json.load(f)
        
        # Generate analysis output from the stored data
        analysis_output = generate_analysis_output(report_data)
        
        # Get PDF filename if available
        pdf_filename = None
        if '_report_' in filename:
            timestamp_part = filename.split('_report_')[1].split('.')[0]
            pdf_filename = f"security_report_{timestamp_part}.pdf"
            pdf_path = os.path.join(app.root_path, 'DeepSeek_Reports', pdf_filename)
            if not os.path.exists(pdf_path):
                pdf_filename = None
        
        return render_template('results.html',
            analysis_output=analysis_output,
            pdf_filename=pdf_filename,
            report_filename=filename,
            file_path=report_data.get('metadata', {}).get('file_path', 'Unknown'),
            analysis_date=report_data.get('metadata', {}).get('analysis_date', 'Unknown'),
            analysis_duration=report_data.get('metadata', {}).get('analysis_duration', 'Unknown'),
            total_packets=report_data.get('statistics', {}).get('total_packets', 0),
            critical_count=calculate_critical_count(report_data),
            #high_count=calculate_high_count(report_data),
            #medium_count=calculate_medium_count(report_data),
            #low_count=calculate_low_count(report_data)
        )
        
    except Exception as e:
        app.logger.error(f"Error loading report {filename}: {str(e)}")
        flash('Error loading report', 'error')
        return redirect(url_for('view_history'))

def generate_analysis_output(report_data):
    """Convert stored report data back to the console output format"""
    output = []
    
    # 1. Scan Detection
    output.append("=== ANALYSIS RESULTS SUMMARY ===")
    output.append("\n• Network Scan Detection:")
    if 'nmap_scan_types' in report_data:
        for scan_type, count in Counter(report_data['nmap_scan_types']).items():
            output.append(f"  [WARNING] {scan_type} scans detected: {count}")
    else:
        output.append("  [INFO] No network scanning activity detected")
    
    # 2. ARP Poisoning
    output.append("\n• ARP Security Analysis:")
    if 'arp_poisoning' in report_data and report_data['arp_poisoning']:
        output.append("  [CRITICAL] ARP cache poisoning detected!")
        for entry in report_data['arp_poisoning']:
            output.append(f"  [WARNING] Suspicious ARP mapping - IP: {entry['ip']} → MAC: {entry['mac']}")
    else:
        output.append("  [INFO] No ARP spoofing detected")
    
    # ... add other sections similarly ...
    
    output.append("\n=== END OF REPORT ===")
    return "\n".join(output)

def calculate_critical_count(report_data):
    """Count critical findings in the report"""
    count = 0
    if report_data.get('arp_poisoning'):
        count += len(report_data['arp_poisoning'])
    if report_data.get('icmp_tunnel', 0) > 5:
        count += 1
    if report_data.get('dns_tunnel', 0) > 3:
        count += 1
    return count

# Similar functions for high_count, medium_count, low_count

def _format_historical_report(report_data):
    """Convert stored JSON data to formatted analysis output"""
    # Use the pre-generated analysis summary if available
    if 'analysis_summary' in report_data:
        return report_data['analysis_summary']
    
    # Fallback to original formatting if summary missing
    output = []
    
    # Reconstruct analysis summary from packet data
    nmap_counts = Counter()
    arp_entries = set()
    anomalies = set()
    icmp_count = 0
    dns_count = 0

    # Extract stats from attack_stats instead of recalculating
    stats = report_data.get('attack_stats', {})
    
    for packet in report_data.get('packet_reports', []):
        for detail in packet.get('detection_details', []):
            if 'scan detected' in detail:
                if 'TCP connect' in detail:
                    nmap_counts['tcp_connect'] += 1
                elif 'SYN scan' in detail:
                    nmap_counts['syn'] += 1
                elif 'XMAS scan' in detail:
                    nmap_counts['xmas'] += 1
            elif 'ARP poisoning' in detail:
                arp_entries.add(detail.split('IP ')[1].split(' ')[0])
            elif 'anomaly' in detail.lower():
                anomalies.add(detail.split('IP ')[1].split(' ')[0])
            elif 'ICMP tunneling' in detail:
                icmp_count += 1
            elif 'DNS tunneling' in detail:
                dns_count += 1

    # Build output to match live analysis format
    output.append("=== Analysis Results ===")
    
    output.append("\nNmap Scan Detection:")
    for scan_type, count in nmap_counts.items():
        output.append(f"  {scan_type.replace('_', ' ')} scans detected: {count}")
    
    output.append("\nARP Poisoning Detection:")
    if arp_entries:
        for ip in arp_entries:
            output.append(f"  Suspicious ARP Entry: IP - {ip}")
    else:
        output.append("  No ARP poisoning detected.")
    
    output.append("\nICMP Tunneling Detection:")
    output.append(f"  Potential ICMP tunneling activities detected: {icmp_count}")
    
    output.append("\nDNS Tunneling Detection:")
    output.append(f"  Potential DNS tunneling activities detected: {dns_count}")
    
    output.append("\nAnomaly Detection:")
    for ip in anomalies:
        output.append(f"  Anomalous activity detected from IP: {ip}")

    # Add statistics section
    output.append("\n=== Statistics ===")
    output.append(f"Total packets analyzed: {stats.get('total_packets', 0)}")
    output.append(f"TCP packets: {stats.get('tcp_packets', 0)}")
    output.append(f"UDP packets: {stats.get('udp_packets', 0)}")
    output.append(f"ICMP packets: {stats.get('icmp_packets', 0)}")
    output.append(f"Unique source IPs: {stats.get('unique_source_ips', 0)}")
    
    return '\n'.join(output)

    

@app.template_filter('format_output')
def format_output(text):
    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned = ansi_escape.sub('', text)
    
    # Split into sections based on lines ending with ===
    sections = []
    current_section = []
    
    for line in cleaned.split('\n'):
        if line.strip().endswith('==='):
            if current_section:
                sections.append('\n'.join(current_section))
                current_section = []
        current_section.append(line)
    
    if current_section:
        sections.append('\n'.join(current_section))
    
    return sections

if __name__ == '__main__':
    app.run(debug=True)