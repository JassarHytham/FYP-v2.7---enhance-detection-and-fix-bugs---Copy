import argparse
import asyncio
import concurrent.futures
import json
import logging
import math
import os
import statistics
import traceback
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

import numpy as np
import pyshark
from colorama import Fore, Style, init
from logging.handlers import RotatingFileHandler

from ReportGenerator import ReportGenerator 


class TrafficAnalyzer:
    def __init__(self, file_path: Optional[str] = None, verbose: bool = False) -> None:
        """
        Initialize the TrafficAnalyzer with optional pcap file path and verbosity.
        """
        self.file_path: Optional[str] = file_path
        self.pdf_file: Optional[str] = None
        init(autoreset=True)

        # Configure logging for the analyzer
        self.logger = self._configure_logging(verbose)
        # Disable pyshark's internal logging to avoid clutter
        logging.getLogger('pyshark').setLevel(logging.WARNING)

    def _configure_logging(self, verbose: bool) -> logging.Logger:
        """
        Configure and return a logger with file and optional console handlers.
        """
        logger = logging.getLogger('TrafficAnalyzer')
        logger.setLevel(logging.DEBUG)
        log_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
        )

        # Ensure the logs directory exists
        os.makedirs('logs', exist_ok=True)

        # File handler with rotation to manage log size
        file_handler = RotatingFileHandler(
            os.path.join('logs', 'traffic_analysis.log'),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8',
            delay=True
        )
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

        # Optional console handler for verbose mode
        if verbose:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(log_formatter)
            console_handler.setLevel(logging.INFO)
            logger.addHandler(console_handler)

        return logger

    def run_analysis(self, generate_pdf=True) -> None:
        """
        Run the traffic analysis on the specified pcap file and generate reports.
        """
        self.logger.info(f"Starting analysis of file: {self.file_path}")
        start_time = datetime.now()

        try:
            # Set up an asyncio event loop to avoid deprecation warnings
            self._setup_event_loop()

            # Load packets from the pcap file
            capture = self._load_packets()

            # Process packets in chunks for efficiency
            results = self._process_packets_in_chunks(capture, chunk_size=100)

            # Close the capture object to release resources
            capture.close()

            # Sort results by packet number for consistency
            results.sort(key=lambda x: x['packet_info']['packet_number'])

            # Aggregate results into a summary report
            packet_reports = self.aggregate_results(results)

            # Apply dynamic threshold and temporal analysis
            self.apply_dynamic_threshold(packet_reports)
            self.apply_temporal_analysis(packet_reports)

            # Generate JSON and optionally PDF reports
            self.generate_json_report(packet_reports)
            if generate_pdf:
                self.pdf_file = self.generate_pdf_report(packet_reports)
            else:
                self.logger.info("Skipping PDF report generation")
                self.pdf_file = None

        except Exception as e:
            # Log critical errors and print to the console
            self.logger.critical(f"Analysis failed: {str(e)}")
            self.logger.debug(traceback.format_exc())
            print(Fore.RED + f"Error during analysis: {str(e)}")
        finally:
            # Log the total duration of the analysis
            duration = datetime.now() - start_time
            self.logger.info(f"Analysis completed in {duration.total_seconds():.2f} seconds")

    def _process_packets_in_chunks(self, capture: pyshark.FileCapture, chunk_size: int) -> List[Dict[str, Any]]:
        """
        Process packets in parallel using chunks directly from the capture object.
        """
        max_workers = min(32, (os.cpu_count() or 4) * 2)  # Determine optimal thread pool size
        self.logger.debug(f"Creating ThreadPoolExecutor with {max_workers} workers")
        results: List[Dict[str, Any]] = []
        current_chunk = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            # Iterate through packets and group them into chunks
            for packet in capture:
                current_chunk.append(packet)
                if len(current_chunk) >= chunk_size:
                    # Submit the chunk for processing
                    futures.append(executor.submit(self.process_packet_batch, current_chunk))
                    current_chunk = []

            # Process any remaining packets in the last chunk
            if current_chunk:
                futures.append(executor.submit(self.process_packet_batch, current_chunk))

            # Collect results from all futures
            for future in concurrent.futures.as_completed(futures):
                try:
                    batch_result = future.result()
                    results.extend(batch_result)
                    self.logger.debug(f"Completed batch with {len(batch_result)} results")
                except Exception as e:
                    self.logger.error(f"Error processing batch: {str(e)}")
                    self.logger.debug(traceback.format_exc())

        return results

    def _setup_event_loop(self) -> None:
        """
        Set up a new asyncio event loop to avoid deprecation warnings.
        """
        self.logger.debug("Creating new event loop")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    def _load_packets(self) -> pyshark.FileCapture:
        """
        Return the capture object for lazy iteration.
        """
        self.logger.debug("Opening pcap file with pyshark")
        return pyshark.FileCapture(
            self.file_path,
            display_filter="arp or icmp or dns or tcp or udp",  # Filter for relevant protocols
            keep_packets=False,  # Avoid keeping packets in memory
            use_json=True  # Use JSON for faster parsing
        )

    def process_packet_batch(self, packets: List[Any]) -> List[Dict[str, Any]]:
        """
        Process a batch of packets and return a list of result dictionaries.
        """
        self.logger.debug(f"Processing batch of {len(packets)} packets")
        results = []
        for packet in packets:
            try:
                result = self.process_packet(packet)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error processing individual packet: {str(e)}")
                self.logger.debug(traceback.format_exc())
        return results

    def process_packet(self, packet: Any) -> Dict[str, Any]:
        """
        Process an individual packet and return its analysis result.
        """
        packet_number = int(packet.number)
        self.logger.debug(f"Processing packet #{packet_number}")

        # Initialize packet information and result structure
        packet_info: Dict[str, Any] = {
            "packet_number": packet_number,
            "timestamp": packet.sniff_time.isoformat(),
            "minute": None,
            "protocols": [],
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "detection_details": []
        }
        result: Dict[str, Any] = {
            'nmap_scan_types': [],
            'arp_entries': [],
            'icmp_tunnel': 0,
            'dns_tunnel': 0,
            'src_ip_anomaly': None,
            'packet_info': packet_info
        }

        try:
            # Extract IP information if available
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                packet_info.update({"src_ip": src_ip, "dst_ip": dst_ip})
                result['src_ip_anomaly'] = src_ip
                self.logger.debug(f"Packet #{packet_number} IP: {src_ip} -> {dst_ip}")

                # Check for both TCP and UDP in the same packet
                if hasattr(packet, 'tcp') and hasattr(packet, 'udp'):
                    detail = f"IP {src_ip} sent both TCP and UDP."
                    packet_info["detection_details"].append(detail)
                    self.logger.warning(f"Packet #{packet_number}: {detail}")

                # Analyze payload entropy for potential anomalies
                if hasattr(packet, 'data'):
                    raw_data = str(packet.data)
                    entropy = self.compute_entropy(raw_data)
                    if entropy > 7.0:
                        detail = f"High payload entropy ({entropy:.2f}) detected from IP {src_ip}"
                        packet_info["detection_details"].append(detail)
                        self.logger.warning(f"Packet #{packet_number}: {detail}")

            # Add protocol layers to the packet info
            for layer in ['tcp', 'udp', 'arp', 'icmp', 'dns']:
                if hasattr(packet, layer) and layer.upper() not in packet_info["protocols"]:
                    packet_info["protocols"].append(layer.upper())

            # Detect various anomalies and update the result
            tcp_scans, tcp_details = self.detect_tcp_scans(packet)
            udp_scans, udp_details = self.detect_udp_scans(packet)
            arp_entries, arp_details = self.detect_arp_poisoning(packet)
            icmp_tunnel, icmp_details = self.detect_icmp_tunneling(packet)
            dns_tunnel, dns_details = self.detect_dns_tunneling(packet)

            result.update({
                'nmap_scan_types': tcp_scans + udp_scans,
                'arp_entries': arp_entries,
                'icmp_tunnel': icmp_tunnel,
                'dns_tunnel': dns_tunnel
            })

            detection_details = tcp_details + udp_details + arp_details + icmp_details + dns_details
            packet_info["detection_details"].extend(detection_details)

            if detection_details:
                self.logger.info(f"Packet #{packet_number} detections: {detection_details}")

        except AttributeError as e:
            self.logger.error(f"AttributeError in packet #{packet_number}: {str(e)}")
            self.logger.debug(traceback.format_exc())
        except Exception as e:
            self.logger.error(f"Error processing packet #{packet_number}: {str(e)}")
            self.logger.debug(traceback.format_exc())

        return result

    def aggregate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Aggregate individual packet results into summary reports.
        """
        self.logger.info("Aggregating results from all packets")
        nmap_scan_detected: Counter = Counter()
        arp_poisoning_seen: Dict[str, str] = {}
        icmp_tunnel_total = 0
        dns_tunnel_total = 0
        anomaly_counts: Counter = Counter()
        packet_reports: List[Dict[str, Any]] = []

        for result in results:
            pkt_info = result['packet_info']
            pkt_info['minute'] = self._format_timestamp(pkt_info.get('timestamp'), pkt_info.get('packet_number'))
        
        for result in results:
            for scan_type in result['nmap_scan_types']:
                nmap_scan_detected[scan_type] += 1

            for entry in result['arp_entries']:
                ip, mac = entry
                if ip in arp_poisoning_seen and arp_poisoning_seen[ip] != mac:
                    detail = f"ARP poisoning detected: IP {ip} has multiple MAC addresses."
                    result['packet_info']['detection_details'].append(detail)
                    self.logger.warning(f"ARP poisoning detected for IP {ip}")
                else:
                    arp_poisoning_seen[ip] = mac

            icmp_tunnel_total += result['icmp_tunnel']
            dns_tunnel_total += result['dns_tunnel']

            # Count occurrences of each source IP (for anomaly detection)
            src_ip = result.get('src_ip_anomaly')
            if src_ip:
                anomaly_counts[src_ip] += 1

            if result['packet_info']['detection_details']:
                packet_reports.append(result['packet_info'])

        # Create a list of anomalous IPs based on the counts
        anomaly_ips = list(anomaly_counts.keys())

        self.print_results(nmap_scan_detected, arp_poisoning_seen,
                           icmp_tunnel_total, dns_tunnel_total, anomaly_ips)
        self.logger.info("Aggregation complete")
        return packet_reports


    def _format_timestamp(self, timestamp: Optional[str], packet_number: Any) -> Optional[str]:
        """
        Convert ISO timestamp to a formatted string. Returns None if conversion fails.
        """
        if not timestamp:
            return None
        try:
            ts = datetime.fromisoformat(timestamp)
            return ts.strftime('%Y-%m-%d %H:%M')
        except Exception as e:
            self.logger.warning(f"Invalid timestamp in packet #{packet_number}: {str(e)}")
            return None

    def apply_dynamic_threshold(self, packet_reports: List[Dict[str, Any]]) -> None:
        """
        Apply dynamic threshold analysis using the Interquartile Range (IQR) method
        to detect IP anomalies based on packet counts.
        """
        self.logger.info("Applying dynamic threshold analysis using IQR")
        try:
            # 1. Count packets per source IP
            ip_counts = Counter(packet.get("src_ip") for packet in packet_reports if packet.get("src_ip"))
            if not ip_counts:
                self.logger.warning("No source IPs found for dynamic threshold analysis")
                return  # Exit if no IPs

            # 2. Calculate IQR
            counts = list(ip_counts.values())
            q1, q3 = np.percentile(counts, [25, 75])
            iqr = q3 - q1
            if iqr == 0:
                self.logger.debug("IQR is zero; insufficient variance. Skipping.")
                return  # Exit if no variance
            threshold = q3 + 1.5 * iqr

            self.logger.debug(f"IQR threshold: {threshold:.2f} (Q1={q1}, Q3={q3})")

            # 3. Identify and flag anomalies
            for ip, count in ip_counts.items():
                if count > threshold:
                    detail = f"Dynamic anomaly: IP {ip} sent {count} packets (>{threshold:.2f})"
                    self.logger.warning(detail)
                    for packet in packet_reports:
                        if packet.get("src_ip") == ip:
                            packet['detection_details'].append(detail) # Append, don't overwrite
        except Exception as e:
            self.logger.error(f"Dynamic threshold error: {e}")
            self.logger.debug(traceback.format_exc())



    def apply_temporal_analysis(self, packet_reports: List[Dict[str, Any]]) -> None:
        """
        Apply temporal analysis by grouping packets into time windows (minutes)
        and detecting IPs with unusually high packet counts within those windows.
        """
        self.logger.info("Applying temporal analysis")
        try:
            # 1. Group packets by minute
            window_map = defaultdict(list)
            for packet in packet_reports:
                minute = packet.get("minute")
                if minute:
                    window_map[minute].append(packet)

            # 2. Analyze each time window
            for window, packets in window_map.items():
                ip_counts = Counter(pkt.get("src_ip") for pkt in packets if pkt.get("src_ip"))
                if not ip_counts:
                    continue  # Skip empty windows

                counts = list(ip_counts.values())
                mean_count = statistics.mean(counts)
                stdev = statistics.stdev(counts) if len(counts) > 1 else 0  # Handle single-count case
                threshold = mean_count + 2 * stdev

                self.logger.debug(f"Temporal window: {window}, threshold: {threshold:.2f}")

                # 3. Flag IPs exceeding the threshold
                for ip, count in ip_counts.items():
                    if count > threshold:
                        detail = f"Temporal anomaly: {ip} sent {count} packets in {window} (>{threshold:.2f})"
                        self.logger.warning(detail)
                        for pkt in packets:
                            if pkt.get("src_ip") == ip:
                                pkt['detection_details'].append(detail)
        except Exception as e:
            self.logger.error(f"Temporal analysis error: {e}")
            self.logger.debug(traceback.format_exc())

    def generate_pdf_report(self, packet_reports: List[Dict[str, Any]]) -> str:
        """
        Generate a PDF report from the packet reports.
        """
        #hi there
        self.logger.info("Generating PDF report")
        try:
            analysis_data = {
                'detection_counts': dict(Counter(
                    entry for result in packet_reports for entry in result['detection_details']
                )),
                'attack_stats': {
                    'tcp_packets': sum(1 for p in packet_reports if 'TCP' in p['detection_details']),
                    'udp_packets': sum(1 for p in packet_reports if 'UDP' in p['detection_details']),
                    'icmp_packets': sum(1 for p in packet_reports if 'ICMP' in p['detection_details']),
                    'arp_packets': sum(1 for p in packet_reports if 'ARP' in p['detection_details']),
                },
                'top_threats': sorted(packet_reports, key=lambda x: len(x['detection_details']), reverse=True)[:5],
            }
            generator = ReportGenerator(analysis_data)
            report_file = generator.generate_pdf_report()
            self.logger.info(f"Successfully generated PDF report: {report_file}")
            return report_file
        except Exception as e:
            self.logger.error(f"PDF generation failed: {str(e)}")
            self.logger.debug(traceback.format_exc())
            raise



    def generate_json_report(self, packet_reports: List[Dict[str, Any]]) -> str:
        """
        Generate an enhanced JSON report with detailed analysis and modular threat scoring.
        """
        self.logger.info("Generating enhanced JSON report")
        try:
            base_filename = os.path.basename(self.file_path)
            filename_without_ext = os.path.splitext(base_filename)[0]
            output_filename = f"reports/{filename_without_ext}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            output_path = os.path.join(os.getcwd(), output_filename)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # Generate all analysis components
            stats = self.generate_attack_stats(packet_reports)
            temporal_stats = self.generate_temporal_stats(packet_reports)
            protocol_dist = self.generate_protocol_distribution(packet_reports)
            top_talkers = self.generate_top_talkers(packet_reports)
            conversations = self.generate_conversation_analysis(packet_reports)
            threat_scores = self.generate_threat_scores(packet_reports)
            suspicious_ips = self.get_suspicious_ips(packet_reports)
            recommendations = self.generate_recommendations(packet_reports)

            # Filter critical findings by specific keywords
            keyword_critical_findings = [
                d for p in packet_reports for d in p.get('detection_details', [])
                if any(pattern in d.lower() for pattern in ['poisoning', 'tunneling', 'xmas', 'null'])
            ]

            report = {
                "metadata": {
                    "file_path": self.file_path,
                    "analysis_date": datetime.now().isoformat(),
                    "analysis_duration": str(datetime.now() - datetime.fromisoformat(packet_reports[0]['timestamp'])) 
                        if packet_reports and 'timestamp' in packet_reports[0] else "N/A",
                    "total_packets": len(packet_reports),
                    "first_packet": packet_reports[0]['timestamp'] if packet_reports else None,
                    "last_packet": packet_reports[-1]['timestamp'] if packet_reports else None,
                },
                "statistics": stats,
                "temporal_analysis": temporal_stats,
                "tcp_packets": len([p for p in packet_reports if "TCP" in p.get("protocols", [])]),
                "udp_packets": len([p for p in packet_reports if "UDP" in p.get("protocols", [])]),
                "protocol_distribution": protocol_dist,
                "top_talkers": top_talkers,
                "conversations": conversations,
                "threat_analysis": {
                    "scores": {
                        "critical": threat_scores.get("critical", 0),
                        "high": threat_scores.get("high", 0),
                        "medium": threat_scores.get("medium", 0),
                        "low": threat_scores.get("low", 0),
                        "scanning_score": threat_scores.get("scanning_score", 0),
                        "tunneling_score": threat_scores.get("tunneling_score", 0),
                        "anomaly_score": threat_scores.get("anomaly_score", 0),
                        "overall_score": threat_scores.get("overall_score", 0),
                        "severity": threat_scores.get("severity", "Unknown")
                    },
                    "critical_findings": keyword_critical_findings,
                    "suspicious_ips": suspicious_ips
                },
                "detailed_findings": packet_reports,
                "recommendations": recommendations
            }

            # Save the report
            with open(output_path, 'w') as json_file:
                json.dump(report, json_file, indent=4)

            # Save a copy as the latest
            with open('reports/latest_analysis.json', 'w') as f:
                json.dump(report, f)

            self.logger.info(f"Enhanced JSON report generated: {output_path}")
            print(Fore.CYAN + f"\nEnhanced JSON report generated: {output_path}")

            return output_path

        except Exception as e:
            self.logger.error(f"JSON report generation failed: {str(e)}")
            self.logger.debug(traceback.format_exc())
            raise

    def generate_temporal_stats(self, packet_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate temporal statistics by minute"""
        time_stats = defaultdict(lambda: {
            'count': 0,
            'protocols': defaultdict(int),
            'src_ips': set(),
            'detections': []
        })

        for packet in packet_reports:
            if not packet.get('minute'):
                continue

            minute = packet['minute']
            time_stats[minute]['count'] += 1
            time_stats[minute]['src_ips'].add(packet.get('src_ip', 'unknown'))

            for protocol in packet.get('protocols', []):
                time_stats[minute]['protocols'][protocol] += 1

            if packet.get('detection_details'):
                time_stats[minute]['detections'].extend(packet['detection_details'])

        # Convert sets to counts and find peak periods
        for minute in time_stats:
            time_stats[minute]['unique_src_ips'] = len(time_stats[minute]['src_ips'])
            del time_stats[minute]['src_ips']

        return dict(time_stats)

    def generate_protocol_distribution(self, packet_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed protocol distribution statistics"""
        protocol_counts = Counter()
        protocol_pair_counts = Counter()

        for packet in packet_reports:
            protocols = packet.get('protocols', [])
            protocol_counts.update(protocols)

            # Count protocol pairs (e.g., TCP-DNS)
            if len(protocols) > 1:
                protocol_pair_counts.update(['-'.join(sorted(protocols))])

        return {
            'protocols': dict(protocol_counts.most_common()),
            'protocol_pairs': dict(protocol_pair_counts.most_common()),
            'most_common_protocol': protocol_counts.most_common(1)[0][0] if protocol_counts else None
        }

    def generate_top_talkers(self, packet_reports: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Identify top talkers by packet count and detection count"""
        ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'detection_count': 0,
            'protocols': set(),
            'detections': set()
        })

        for packet in packet_reports:
            src_ip = packet.get('src_ip')
            if not src_ip:
                continue

            ip_stats[src_ip]['packet_count'] += 1
            ip_stats[src_ip]['protocols'].update(packet.get('protocols', []))

            if packet.get('detection_details'):
                ip_stats[src_ip]['detection_count'] += len(packet['detection_details'])
                ip_stats[src_ip]['detections'].update(packet['detection_details'])

        # Convert to list of dicts and sort
        top_talkers = []
        for ip, stats in ip_stats.items():
            talker = {
                'ip': ip,
                'packet_count': stats['packet_count'],
                'detection_count': stats['detection_count'],
                'protocols': list(stats['protocols']),
                'unique_detections': list(stats['detections'])
            }
            top_talkers.append(talker)

        return {
            'by_packet_count': sorted(top_talkers, key=lambda x: x['packet_count'], reverse=True)[:10],
            'by_detection_count': sorted(top_talkers, key=lambda x: x['detection_count'], reverse=True)[:10]
        }

    def generate_conversation_analysis(self, packet_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze conversations between hosts"""
        conversations = defaultdict(lambda: {
            'packet_count': 0,
            'protocols': set(),
            'ports': set(),
            'detections': set()
        })

        for packet in packet_reports:
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            if not src_ip or not dst_ip:
                continue

            # Use sorted tuple as key to treat A->B and B->A as same conversation
            key = tuple(sorted((src_ip, dst_ip)))
            conversations[key]['packet_count'] += 1
            conversations[key]['protocols'].update(packet.get('protocols', []))

            if packet.get('src_port') and packet.get('dst_port'):
                conversations[key]['ports'].add((packet['src_port'], packet['dst_port']))

            if packet.get('detection_details'):
                conversations[key]['detections'].update(packet['detection_details'])

        # Convert to list of dicts and sort
        conv_list = []
        for ips, stats in conversations.items():
            conv = {
                'hosts': list(ips),
                'packet_count': stats['packet_count'],
                'protocols': list(stats['protocols']),
                'ports': [{'src_port': p[0], 'dst_port': p[1]} for p in stats['ports']],
                'detection_count': len(stats['detections']),
                'detections': list(stats['detections'])
            }
            conv_list.append(conv)

        return {
            'most_active': sorted(conv_list, key=lambda x: x['packet_count'], reverse=True)[:10],
            'most_suspicious': sorted(conv_list, key=lambda x: x['detection_count'], reverse=True)[:10]
        }

    def generate_threat_scores(self, packet_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate threat scores with severity breakdown and weighted metrics"""
        scores = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'scanning_score': 0,
            'tunneling_score': 0,
            'anomaly_score': 0
        }

        # Combined patterns from both versions
        severity_patterns = {
            'critical': [
                'arp poisoning', 'icmp tunneling', 'dns tunneling',
                'xmas scan', 'null scan', 'anomalous activity',
                'tunneling detected', 'poisoning'
            ],
            'high': [
                'syn scan', 'udp scan', 'high payload entropy',
                'multiple mac', 'suspicious arp', 'high entropy'
            ],
            'medium': [
                'unusual port', 'unusual protocol',
                'high packet rate', 'unusual packet size',
                'unusual activity', 'suspicious pattern'
            ],
            'low': [
                'uncommon user agent', 'dns query',
                'http request', 'common scan pattern',
                'informational', 'common scan'
            ]
        }

        scan_types = ['syn', 'xmas', 'null', 'fin', 'udp']

        for packet in packet_reports:
            for detection in packet.get('detection_details', []):
                detection_lower = detection.lower()

                # Sub-score calculation
                if any(scan in detection_lower for scan in scan_types):
                    scores['scanning_score'] += 1
                if 'tunnel' in detection_lower:
                    scores['tunneling_score'] += 1
                if 'anomal' in detection_lower:
                    scores['anomaly_score'] += 1

                # Severity matching
                if any(pattern in detection_lower for pattern in severity_patterns['critical']):
                    scores['critical'] += 1
                elif any(pattern in detection_lower for pattern in severity_patterns['high']):
                    scores['high'] += 1
                elif any(pattern in detection_lower for pattern in severity_patterns['medium']):
                    scores['medium'] += 1
                elif any(pattern in detection_lower for pattern in severity_patterns['low']):
                    scores['low'] += 1
                else:
                    # Default fallback
                    scores['medium'] += 1

        # Normalize scoring based on total packet count
        total_packets = len(packet_reports)
        if total_packets > 0:
            for key in ['scanning_score', 'tunneling_score', 'anomaly_score']:
                scores[key] = min(100, int((scores[key] / total_packets) * 1000))

        # Calculate overall threat score (weighted)
        weights = {'scanning_score': 0.4, 'tunneling_score': 0.3, 'anomaly_score': 0.3}
        scores['overall_score'] = int(sum(scores[k] * weights[k] for k in weights))

        # Determine severity level from overall score
        overall = scores['overall_score']
        if overall >= 80:
            scores['severity'] = "Critical"
        elif overall >= 50:
            scores['severity'] = "High"
        elif overall >= 20:
            scores['severity'] = "Medium"
        else:
            scores['severity'] = "Low"

        self.logger.info(f"Calculated threat scores: {scores}")
        return scores


    def get_critical_findings(self, packet_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract the most critical findings from the analysis"""
        critical_keywords = [
            'poisoning', 'tunneling', 'scan detected', 'high payload entropy',
            'multiple MAC', 'anomalous activity'
        ]

        critical_findings = []
        for packet in packet_reports:
            for detection in packet.get('detection_details', []):
                if any(keyword in detection.lower() for keyword in critical_keywords):
                    finding = {
                        'packet_number': packet['packet_number'],
                        'timestamp': packet.get('timestamp'),
                        'src_ip': packet.get('src_ip'),
                        'detection': detection,
                        'protocols': packet.get('protocols', [])
                    }
                    critical_findings.append(finding)

        return critical_findings[:50]  # Limit to top 50 critical findings

    def get_suspicious_ips(self, packet_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify suspicious IPs based on multiple factors"""
        ip_scores = defaultdict(int)

        for packet in packet_reports:
            src_ip = packet.get('src_ip')
            if not src_ip:
                continue

            # Score based on detections
            ip_scores[src_ip] += len(packet.get('detection_details', []))

            # Bonus points for critical protocols
            if 'ARP' in packet.get('protocols', []):
                ip_scores[src_ip] += 2
            if 'ICMP' in packet.get('protocols', []):
                ip_scores[src_ip] += 1

        # Convert to list of dicts and sort
        suspicious_ips = [{'ip': ip, 'score': score} for ip, score in ip_scores.items()]
        return sorted(suspicious_ips, key=lambda x: x['score'], reverse=True)[:20]

    def generate_recommendations(self, packet_reports: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        findings = self.get_critical_findings(packet_reports)

        # Check for specific threats and add relevant recommendations
        has_arp_poisoning = any('poisoning' in f['detection'].lower() for f in findings)
        has_tunneling = any('tunneling' in f['detection'].lower() for f in findings)
        has_scans = any('scan detected' in f['detection'].lower() for f in findings)

        if has_arp_poisoning:
            recommendations.extend([
                "Implement ARP inspection on network switches",
                "Consider deploying ARP spoofing detection tools",
                "Enable DHCP snooping if not already enabled"
            ])

        if has_tunneling:
            recommendations.extend([
                "Inspect ICMP and DNS traffic for unusual patterns",
                "Implement rate limiting for ICMP and DNS queries",
                "Consider using a next-gen firewall with tunneling detection"
            ])

        if has_scans:
            recommendations.extend([
                "Review firewall rules to ensure only necessary ports are open",
                "Implement intrusion detection/prevention systems",
                "Consider implementing port knocking for sensitive services"
            ])

        # Add general recommendations
        recommendations.extend([
            "Review all critical findings in the report for specific actions",
            "Monitor the top suspicious IPs for further malicious activity",
            "Consider implementing network segmentation based on traffic patterns"
        ])

        return recommendations

    def compute_entropy(self, data: Any) -> float:
        """
        Compute and return the Shannon entropy of the provided data.
        """
        self.logger.debug("Computing entropy for data block")
        try:
            if not data:
                self.logger.debug("Empty data for entropy calculation")
                return 0.0
            counts = Counter(data)
            total = len(data)
            entropy = sum(- (count / total) * math.log2(count / total) for count in counts.values())
            self.logger.debug(f"Computed entropy: {entropy:.2f}")
            return entropy
        except Exception as e:
            self.logger.error(f"Entropy calculation error: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return 0.0

    def detect_tcp_scans(self, packet: Any) -> Tuple[List[str], List[str]]:
        """
        Detect potential nmap scan types from a packet.
        """
        scans: List[str] = []
        details: List[str] = []
        if hasattr(packet, 'tcp'):
            # Normalize TCP flags to an integer value
            flags_str = getattr(packet.tcp, 'flags', '0x000')
            try:
                flags = int(flags_str, 16)
            except Exception as e:
                self.logger.error(f"Error converting TCP flags: {flags_str} - {str(e)}")
                flags = 0

            window_size = int(getattr(packet.tcp, 'window_size', '0'))
            
            if flags == 0x2:  # SYN flag (SYN scan or TCP connect)
                if window_size > 1024:
                    scans.append('tcp_connect')
                    details.append("TCP connect scan detected: SYN flag with window size > 1024")
                else:
                    scans.append('syn')
                    details.append("SYN scan detected: SYN flag with window size <= 1024")
            elif flags == 0x29:  # XMAS scan: FIN, PSH, and URG (1+8+32=41, 0x29)
                scans.append('xmas')
                details.append("XMAS scan detected")
            elif flags == 0x0:  # NULL scan: no flags set
                scans.append('null')
                details.append("NULL scan detected")
            elif flags == 0x1:  # FIN scan: FIN flag only
                scans.append('fin')
                details.append("FIN scan detected")
        return scans, details


    def detect_udp_scans(self, packet: Any) -> Tuple[List[str], List[str]]:
        """
        Detect UDP scan patterns from a packet.
        """
        scans: List[str] = []
        details: List[str] = []
        if hasattr(packet, 'udp'):
            length = int(getattr(packet.udp, 'length', 0))
            if length <= 8:
                scans.append('udp')
                details.append("UDP scan detected: Packet length <= 8")
        return scans, details

    def detect_arp_poisoning(self, packet: Any) -> Tuple[List[Tuple[str, str]], List[str]]:
        """
        Detect ARP poisoning by examining ARP packets.
        """
        entries: List[Tuple[str, str]] = []
        details: List[str] = []
        
        if hasattr(packet, 'arp'):
            try:
                # Updated field names for pyshark
                opcode = getattr(packet.arp, 'opcode', None)
                src_ip = getattr(packet.arp, 'src.proto_ipv4', None)  # Changed from src_proto_ipv4
                src_mac = getattr(packet.arp, 'src.hw_mac', None)     # Changed from src_hw_mac
                
                if opcode == '2' and src_ip and src_mac:  # opcode 2 is ARP reply
                    entry = (src_ip, src_mac)
                    entries.append(entry)
                    
                    # Additional check for gratuitous ARP
                    if getattr(packet.arp, 'dst.proto_ipv4', None) == src_ip:
                        details.append(f"Gratuitous ARP detected from {src_ip} ({src_mac})")
                        
            except Exception as e:
                self.logger.error(f"Error processing ARP packet: {str(e)}")
                self.logger.debug(traceback.format_exc())
                
        return entries, details

    def detect_icmp_tunneling(self, packet: Any) -> Tuple[int, List[str]]:
        """
        Detect potential ICMP tunneling by analyzing payload entropy.
        Returns a tuple of (detection_score, detection_details)
        """
        if not hasattr(packet, 'icmp') or not hasattr(packet.icmp, 'data'):
            return 0, []

        try:
            data_layer = packet.icmp.data

            # Extract the actual hex string from JsonLayer
            if hasattr(data_layer, 'raw_value'):
                data_bytes = data_layer.raw_value  # Already bytes
            elif hasattr(data_layer, 'hex_value'):
                data_bytes = bytes.fromhex(data_layer.hex_value)
            else:
                # Fallback: convert to string, clean it, then decode
                data_str = str(data_layer)
                cleaned_hex = ''.join(c for c in data_str if c.lower() in '0123456789abcdef')
                if len(cleaned_hex) < 16:  # At least 8 bytes
                    return 0, []
                if len(cleaned_hex) % 2 != 0:
                    cleaned_hex = cleaned_hex[:-1]
                data_bytes = bytes.fromhex(cleaned_hex)

            data_length = len(data_bytes)
            if data_length < 64:
                return 0, []

            entropy = self.compute_entropy(data_bytes)
            if entropy > 5.0:
                detail = (f"Potential ICMP tunneling detected "
                        f"(payload length={data_length} bytes, entropy={entropy:.2f})")
                return 1, [detail]

        except Exception as e:
            self.logger.error(f"Unexpected error in ICMP tunneling detection: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return 0, []

        return 0, []


    def detect_dns_tunneling(self, packet: Any) -> Tuple[int, List[str]]:
        """
        Detect potential DNS tunneling based on query name length and entropy.
        """
        try:
            if hasattr(packet, 'dns'):
                self.logger.debug(f"Packet #{getattr(packet, 'number', 'N/A')}: DNS layer found")

                all_fields = getattr(packet.dns, '_all_fields', {})
                self.logger.debug(f"DNS all fields: {all_fields}")

                queries = all_fields.get('Queries')
                if not queries or not isinstance(queries, dict):
                    self.logger.debug("No valid 'Queries' found in DNS packet.")
                    return 0, []

                # Get the first query in the dictionary
                first_query_info = next(iter(queries.values()), {})
                query_name = first_query_info.get('dns.qry.name')

                if not query_name:
                    self.logger.debug("No 'dns.qry.name' found inside Queries.")
                    return 0, []

                query_name_str = str(query_name)
                self.logger.debug(f"Extracted DNS query name: {query_name_str}")

                length = len(query_name_str)
                self.logger.debug(f"Query name length: {length}")

                if length > 20:
                    entropy = self.compute_entropy(query_name_str)
                    self.logger.debug(f"Query name entropy: {entropy:.2f}")
                    if entropy > 3.0:
                        detail = f"Potential DNS tunneling detected (length={length}, entropy={entropy:.2f})"
                        return 1, [detail]

            else:
                self.logger.debug("No DNS layer present in packet.")

        except Exception as e:
            self.logger.error(f"Error detecting DNS tunneling: {str(e)}")
            self.logger.debug(traceback.format_exc())

        return 0, []




    def generate_attack_stats(self, packet_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate enhanced attack statistics with additional metrics.
        """
        stats = {
            "total_packets": len(packet_reports),
            "tcp_packets": len([p for p in packet_reports if "TCP" in p.get("protocols", [])]),
            "udp_packets": len([p for p in packet_reports if "UDP" in p.get("protocols", [])]),
            "icmp_packets": len([p for p in packet_reports if "ICMP" in p.get("protocols", [])]),
            "arp_packets": len([p for p in packet_reports if "ARP" in p.get("protocols", [])]),
            "dns_packets": len([p for p in packet_reports if "DNS" in p.get("protocols", [])]),
            "unique_source_ips": len(set(p.get("src_ip") for p in packet_reports if p.get("src_ip"))),
            "unique_destination_ips": len(set(p.get("dst_ip") for p in packet_reports if p.get("dst_ip"))),
            "unique_ports": len(set(
                (p.get("src_port"), p.get("dst_port")) 
                for p in packet_reports 
                if p.get("src_port") and p.get("dst_port")
            )),
            "packets_with_detections": len([p for p in packet_reports if p.get("detection_details")]),
            "total_detections": sum(len(p.get("detection_details", [])) for p in packet_reports),
            "average_packets_per_second": self.calculate_packet_rate(packet_reports),
            "busiest_minute": self.find_busiest_minute(packet_reports)
        }
        return stats
    
    def calculate_packet_rate(self, packet_reports: List[Dict[str, Any]]) -> float:
        """
        Calculate average packets per second.
        """
        if len(packet_reports) < 2:
            return 0.0
        
        try:
            first = datetime.fromisoformat(packet_reports[0]['timestamp'])
            last = datetime.fromisoformat(packet_reports[-1]['timestamp'])
            duration = (last - first).total_seconds()
            return len(packet_reports) / duration if duration > 0 else 0.0
        except Exception as e:
            self.logger.error(f"Error calculating packet rate: {str(e)}")
            return 0.0
    
    def find_busiest_minute(self, packet_reports: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Find the minute with the most packet activity"""
        minute_counts = Counter(p.get('minute') for p in packet_reports if p.get('minute'))
        if not minute_counts:
            return None
        
        busiest_minute, count = minute_counts.most_common(1)[0]
        return {
            'minute': busiest_minute,
            'packet_count': count,
            'percentage': (count / len(packet_reports)) * 100
        }

    def print_results(self, nmap_scan_detected: Counter, arp_poisoning_seen: Dict[str, str],
                    icmp_tunnel: int, dns_tunnel: int, anomaly_detected: List[str]) -> None:
        """
        Enhanced analysis results printing with detailed insights and recommendations
        """
        # Section headers with consistent formatting
        section_header = lambda title: f"\n{Fore.CYAN}{Style.BRIGHT}=== {title} ==={Style.RESET_ALL}"
        sub_header = lambda title: f"\n{Fore.GREEN}{Style.BRIGHT}• {title}:{Style.RESET_ALL}"
        finding = lambda text, severity="info": f"  {Fore.YELLOW if severity == 'warning' else Fore.RED if severity == 'critical' else Fore.WHITE}{text}{Style.RESET_ALL}"
        recommendation = lambda text: f"  {Fore.BLUE}[RECOMMENDATION] {text}{Style.RESET_ALL}"

        print(section_header("ANALYSIS RESULTS SUMMARY"))
#testing git
        # 1. Scan Detection Analysis
        print(sub_header("Network Scan Detection"))
        if nmap_scan_detected:
            total_scans = sum(nmap_scan_detected.values())
            print(finding(f"Total scan attempts detected: {total_scans}", "critical"))
            
            for scan_type, count in nmap_scan_detected.most_common():
                scan_details = {
                    'syn': "SYN scans check for open ports without completing connections",
                    'tcp_connect': "Full TCP connection scans indicate active reconnaissance",
                    'xmas': "XMAS scans use unusual flag combinations to evade detection",
                    'null': "NULL scans can bypass some firewall rules",
                    'udp': "UDP scans are slower but can reveal vulnerable services"
                }.get(scan_type, "Scan type indicates potential reconnaissance activity")
                
                print(finding(f"{scan_type.upper()} scans: {count} instances", "warning"))
                print(f"    - Technical Detail: {scan_details}")
                
                if count > 10:
                    print(recommendation(f"Investigate source IPs performing {scan_type} scans"))
        else:
            print(finding("No network scanning activity detected", "info"))

        # 2. ARP Spoofing Analysis
        print(sub_header("ARP Security Analysis"))
        if arp_poisoning_seen:
            print(finding("ARP cache poisoning detected!", "critical"))
            print(finding(f"Total suspicious ARP entries: {len(arp_poisoning_seen)}", "critical"))
            
            for ip, mac in arp_poisoning_seen.items():
                print(finding(f"Suspicious ARP mapping - IP: {ip} → MAC: {mac}", "warning"))
                print(recommendation(f"Verify MAC address {mac} is legitimate for IP {ip}"))
            
            print(recommendation("Enable DHCP snooping and ARP inspection on network switches"))
            print(recommendation("Isolate affected hosts and investigate for MITM attacks"))
        else:
            print(finding("No ARP spoofing detected", "info"))
            print(recommendation("Consider enabling ARP inspection as a preventive measure"))

        # 3. Tunneling Detection
        print(sub_header("Covert Channel Analysis"))
        
        # ICMP Tunneling
        icmp_level = "HIGH" if icmp_tunnel > 5 else "MODERATE" if icmp_tunnel > 0 else "NONE"
        print(finding(f"ICMP tunneling suspicion: {icmp_level} ({icmp_tunnel} packets)", 
                    "critical" if icmp_tunnel > 5 else "warning"))
        
        if icmp_tunnel:
            print(finding("ICMP packets with unusual payload characteristics detected", "warning"))
            print(recommendation("Monitor ICMP traffic patterns for command-and-control activity"))
            print(recommendation("Consider rate-limiting ICMP packets per host"))
        
        # DNS Tunneling
        dns_level = "HIGH" if dns_tunnel > 3 else "MODERATE" if dns_tunnel > 0 else "NONE"
        print(finding(f"DNS tunneling suspicion: {dns_level} ({dns_tunnel} packets)", 
                    "critical" if dns_tunnel > 3 else "warning"))
        
        if dns_tunnel:
            print(finding("DNS queries with unusual characteristics detected", "warning"))
            print(recommendation("Inspect DNS logs for suspicious domain patterns"))
            print(recommendation("Implement DNS query length restrictions"))

        # 4. Anomaly Detection
        print(sub_header("Traffic Anomalies"))
        if anomaly_detected:
            anomaly_counts = Counter(anomaly_detected)
            top_anomalous = anomaly_counts.most_common(3)
            
            print(finding(f"Total anomalous IPs detected: {len(anomaly_counts)}", "warning"))
            print(finding("Most active anomalous sources:", "warning"))
            
            for ip, count in top_anomalous:
                print(f"  {ip}: {count} anomalous events")
                print(recommendation(f"Capture full traffic logs for IP {ip} for analysis"))
            
            if len(anomaly_counts) > 3:
                print(finding(f"Plus {len(anomaly_counts)-3} additional anomalous IPs", "info"))
        else:
            print(finding("No significant traffic anomalies detected", "info"))

        # 5. Security Posture Summary
        print(sub_header("Security Posture Assessment"))
        
        risk_factors = sum([
            1 if nmap_scan_detected else 0,
            1 if arp_poisoning_seen else 0,
            1 if icmp_tunnel > 3 else 0.5 if icmp_tunnel > 0 else 0,
            1 if dns_tunnel > 2 else 0.5 if dns_tunnel > 0 else 0,
            1 if anomaly_detected else 0
        ])
        
        posture = (
            "CRITICAL" if risk_factors >= 4 else
            "HIGH" if risk_factors >= 2.5 else
            "MODERATE" if risk_factors >= 1 else
            "LOW"
        )
        
        print(finding(f"Overall Network Security Posture: {posture}", 
                    "critical" if posture in ["CRITICAL","HIGH"] else "warning"))
        
        print(recommendation("Prioritize remediation based on the findings above"))
        print(recommendation("Schedule follow-up scans to verify fixes"))
        print(section_header("END OF REPORT"))


def select_pcap_file(search_dir: str = ".") -> Optional[str]:
    """
    Find and allow the user to select a pcap or pcapng file from the given directory.
    """
    pcap_files = list(Path(search_dir).rglob("*.pcap")) + list(Path(search_dir).rglob("*.pcapng"))
    if not pcap_files:
        print(Fore.YELLOW + "No pcap files found in current directory.")
        return None
    print(Fore.CYAN + "\nAvailable pcap files:")
    for idx, file in enumerate(pcap_files, 1):
        print(f"{Fore.YELLOW}[{idx}]{Style.RESET_ALL} {file}")
    while True:
        try:
            choice = input(Fore.GREEN + "\nEnter file number or 'Q' to quit: ")
            if choice.lower() == 'q':
                return None
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(pcap_files):
                return str(pcap_files[choice_idx])
            print(Fore.RED + "Invalid selection. Please try again.")
        except ValueError:
            print(Fore.RED + "Please enter a valid number or 'Q' to quit.")


def main() -> None:
    """
    Entry point for the Traffic Analyzer CLI.
    """
    parser = argparse.ArgumentParser(description="Traffic Analyzer")
    parser.add_argument('file', nargs='?', help='Path to a pcap file (optional)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    if args.file:
        file_path = Path(args.file).resolve()
        if not file_path.exists():
            print(Fore.RED + "Error: The specified file does not exist.")
            return
    else:
        print(Fore.CYAN + "\nWelcome to Traffic Analyzer CLI")
        print(Fore.YELLOW + "Looking for pcap files in current directory...")
        file_path = select_pcap_file()
        if not file_path:
            return
    analyzer = TrafficAnalyzer(file_path=str(file_path), verbose=args.verbose)
    analyzer.logger.info("Verbose logging enabled" if args.verbose else "Standard logging enabled")
    analyzer.run_analysis()


if __name__ == '__main__':
    main()
