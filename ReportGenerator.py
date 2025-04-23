from concurrent.futures import ThreadPoolExecutor
import re
from colorama import Fore
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, PageBreak
from reportlab.platypus.flowables import Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO
import json
import os
import numpy as np
from datetime import datetime
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib

import logging



class ThreatMeter(Flowable):
    """A custom flowable that displays a threat level meter."""
    
    def __init__(self, threat_level, width=300, height=30):
        Flowable.__init__(self)
        self.threat_level = min(max(threat_level, 0), 10)  # Ensure between 0-10
        self.width = width
        self.height = height
        
    def draw(self):
        # Draw the meter background
        self.canv.setStrokeColor(colors.black)
        self.canv.setFillColor(colors.white)
        self.canv.roundRect(0, 0, self.width, self.height, 5, stroke=1, fill=1)
        
        # Calculate filled width based on threat level
        filled_width = (self.threat_level / 10) * self.width
        
        # Choose color based on threat level
        if self.threat_level < 3:
            fill_color = colors.green
        elif self.threat_level < 7:
            fill_color = colors.orange
        else:
            fill_color = colors.red
            
        # Fill the meter to indicate threat level
        self.canv.setFillColor(fill_color)
        self.canv.roundRect(0, 0, filled_width, self.height, 5, stroke=0, fill=1)
        
        # Add text
        self.canv.setFillColor(colors.black)
        self.canv.setFont("Helvetica", 10)
        self.canv.drawCentredString(self.width // 2, self.height // 3, 
                                   f"Threat Level: {self.threat_level}/10")


class ReportGenerator:

    
    DEFAULT_CONFIG = {
        'api_timeout': (30, 120),
        'max_retries': 3,
        'backoff_factor': 1,
        'chart_size': (8, 6),
        'output_dir': 'DeepSeek_Reports',
        'rate_limit': 2,
        'log_level': logging.INFO,
        'threat_meter_level': 7,  # Default threat level for reports (0-10)
        'theme_color': '#2c3e50'  # Default theme color for report elements
    }
        
    def __init__(self, analysis_data, config=None):
        """
        Initialize the report generator.
        
        Args:
            analysis_data (dict): The security analysis data to include in the report
            config (dict, optional): Configuration overrides for the generator
        """
        self.analysis_data = analysis_data
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self._setup_logging()
        self._init_styles()
        self._init_api_client()
        self._last_api_call = 0
        
        # Calculate threat score based on detection counts and attack stats
        self._calculate_threat_score()
        
    def _setup_logging(self):
        """Set up logging for the report generator"""
        logging.basicConfig(
            level=self.config['log_level'],
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('ReportGenerator')
        
    def _init_styles(self):
        """Initialize report styles with enhanced formatting"""
        self.styles = getSampleStyleSheet()
        
        # Update default paragraph style
        self.styles['Normal'].fontName = 'Helvetica'
        self.styles['Normal'].fontSize = 10
        self.styles['Normal'].leading = 14
        
        # Add custom styles
        self.styles.add(ParagraphStyle(
            name='AIStyle',
            fontName='Helvetica',
            fontSize=10,
            leading=12,
            textColor=colors.darkblue
        ))
        
        # Add header styles with theme color
        theme_color = colors.HexColor(self.config['theme_color'])
        for i in range(1, 7):
            self.styles.add(ParagraphStyle(
                name=f'CustomHeading{i}',
                parent=self.styles[f'Heading{i}'],
                textColor=theme_color,
                spaceAfter=12
            ))
        
        # Footer style
        self.styles.add(ParagraphStyle(
            name='Footer',
            fontName='Helvetica-Oblique',
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        ))
        
        # Code style for raw JSON
        self.styles.add(ParagraphStyle(
            name='CodeStyle',
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.black,
            backColor=colors.lightgrey
        ))

    def _init_api_client(self):
        """Initialize API client with retry logic and validation"""
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            self.logger.warning("DEEPSEEK_API_KEY environment variable not set")
            
        self.base_url = "https://api.deepseek.com/v1/chat/completions"
        self.session = self._create_session()

    def _create_session(self):
        """Create a configured requests session with retry logic"""
        session = requests.Session()
        retries = Retry(
            total=self.config['max_retries'],
            backoff_factor=self.config['backoff_factor'],
            status_forcelist=[500, 502, 503, 504, 429],
            allowed_methods=["POST"],
            raise_on_status=False
        )
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session
        
    def _calculate_threat_score(self):
        """Calculate an overall threat score based on the analysis data"""
        # Start with default threat level
        self.threat_score = self.config.get('threat_meter_level', 5)
        
        # Adjust based on number of detections
        detection_counts = self.analysis_data.get('detection_counts', {})
        if detection_counts:
            # Increment score based on detection types and counts
            total_detections = sum(detection_counts.values())
            self.threat_score = min(10, 3 + (total_detections / 2))
            
            # Higher score for certain detection types
            critical_keywords = ['exploit', 'overflow', 'injection', 'backdoor']
            for detection_type in detection_counts:
                if any(keyword in detection_type.lower() for keyword in critical_keywords):
                    self.threat_score = min(10, self.threat_score + 1)
                    
        # Round to nearest integer
        self.threat_score = round(self.threat_score)
        self.logger.info(f"Calculated threat score: {self.threat_score}/10")
        
    def _rate_limit_api_call(self):
        """Implement rate limiting for API calls"""
        now = time.time()
        elapsed = now - self._last_api_call
        if elapsed < 1.0 / self.config['rate_limit']:
            time.sleep((1.0 / self.config['rate_limit']) - elapsed)
        self._last_api_call = time.time()
        
    def generate_ai_insights(self):
        """Generate AI insights from the security data using the DeepSeek API"""
        # Skip if no API key is available
        if not self.api_key:
            self.logger.warning("Skipping AI insights generation (no API key)")
            return "AI insights unavailable: No API key provided"
            
        try:
            self._rate_limit_api_call()
            
            system_prompt = (
                "You are a senior cybersecurity analyst specializing in network traffic analysis. "
                "Generate a professional security report in markdown format based on the provided network traffic data. "
                "Include technical insights and actionable recommendations."
            )

            user_prompt = f"""
**Network Traffic Analysis Data:**
{json.dumps(self.analysis_data, indent=2)}

**Required Report Structure:**
1. ## Executive Summary (High-level overview)
2. ## Risk Assessment (Critical vulnerabilities with severity levels)
3. ## Threat Observations (Technical findings from the data)
4. ## Recommendations (Concrete remediation steps)

**Format Requirements:**
- Use proper markdown headers (## for sections, ### for subsections)
- Present findings in bullet points
- Highlight critical risks using **bold** text
- Include relevant statistics from the data
- Avoid markdown code blocks
- Do not include any concluding paragraphs or summary or tables
"""
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }

            payload = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.6,
                "max_tokens": 1000,
                "stream": False
            }

            self.logger.info("Calling DeepSeek API for security insights")
            response = self.session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=self.config['api_timeout']
            )
            
            response.raise_for_status()
            self.logger.debug(f"API response received: {response.status_code}")

            return response.json()['choices'][0]['message']['content']

        except requests.exceptions.HTTPError as err:
            error_msg = f"API Error [{err.response.status_code}]: {err.response.text}"
            self.logger.error(error_msg)
            return f"AI Insights unavailable: API error ({err.response.status_code})"
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {str(e)}")
            return f"AI Insights unavailable: Connection error"
        except Exception as e:
            self.logger.exception("Unexpected error during AI insights generation")
            return f"AI Insights unavailable: {str(e)}"

    def create_visualizations(self):
        """Generate threat detection visualizations with enhanced formatting"""
        plt.ioff()  # Turn off interactive mode
        
        try:
            detection_counts = self.analysis_data.get('detection_counts', {})
            
            # Create figure with theme color
            theme_color = self.config['theme_color']
            fig = plt.figure(figsize=(10, 6), facecolor='white')
            ax = fig.add_subplot(111)
            
            if detection_counts:
                types, counts = zip(*detection_counts.items())
                
                # Wrap long labels
                wrapped_labels = [
                    '\n'.join([label[i:i+15] for i in range(0, len(label), 15)]) 
                    for label in types
                ]
                
                # Use theme color with alpha for bars
                rgba_color = colors.HexColor(theme_color).rgba()
                bar_color = (rgba_color[0], rgba_color[1], rgba_color[2], 0.7)
                
                bars = ax.bar(wrapped_labels, counts, color=bar_color)
                
                # Add value labels on top of bars
                for bar in bars:
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                            str(int(height)), ha='center', va='bottom', fontsize=9)
                
                ax.set_xlabel("Detection Type", fontsize=10, fontweight='bold')
                ax.set_ylabel("Count", fontsize=10, fontweight='bold')
                ax.set_title("Threat Detection Summary", fontsize=14, fontweight='bold')
                
                # Improve x-axis label rendering
                plt.xticks(rotation=45, ha='right', fontsize=9)
                
                # Add grid for readability
                ax.grid(axis='y', linestyle='--', alpha=0.3)
                
                # Adjust layout
                plt.tight_layout()
                
            else:
                ax.text(0.5, 0.5, "No Detection Data Available", 
                       fontsize=16, ha='center', fontweight='bold')
                ax.axis('off')
            
            # Save chart to memory buffer
            detection_chart = BytesIO()
            fig.savefig(detection_chart, format='png', bbox_inches='tight', dpi=120)
            detection_chart.seek(0)
            
            return detection_chart
        
        except Exception as e:
            self.logger.exception("Error creating visualizations")
            
            # Create a simple error chart
            fig = plt.figure(figsize=(6, 4))
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, f"Chart Generation Error: {str(e)}", 
                   fontsize=12, ha='center', color='red')
            ax.axis('off')
            
            error_chart = BytesIO()
            fig.savefig(error_chart, format='png')
            error_chart.seek(0)
            
            return error_chart
        
        finally:
            plt.close()
            plt.ion()  # Restore interactive mode

    def advanced_format_text(self, text):
        """Convert markdown text to reportlab-compatible formatting with enhanced handling"""
        # Handle horizontal rules
        text = re.sub(r"\n---+\n", "\n<hr/>\n", text)
        
        # Handle inline code
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)

        # Handle headers
        def header_sub(match):
            header = match.group(1)
            content = match.group(2).strip()
            level = len(header)
            return f"<h{level}>{content}</h{level}>"
        text = re.sub(r"^(#{1,6})\s+(.*)$", header_sub, text, flags=re.MULTILINE)
        
        # Handle bullet lists with proper nesting
        lines = text.splitlines()
        new_lines = []
        in_list = False
        list_level = 0
        
        for line in lines:
            # Handle bullets with indent level
            bullet_match = re.match(r"^(\s*)[-*]\s+(.+)$", line)
            if bullet_match:
                indent, content = bullet_match.groups()
                indent_level = len(indent) // 2
                
                if not in_list:
                    in_list = True
                    list_level = indent_level
                    new_lines.append("<ul>")
                elif indent_level > list_level:
                    # Nested list
                    new_lines.append("<ul>")
                    list_level = indent_level
                elif indent_level < list_level:
                    # End of nested list
                    for _ in range(list_level - indent_level):
                        new_lines.append("</ul>")
                    list_level = indent_level
                    
                new_lines.append(f"<li>{content.strip()}</li>")
            else:
                if in_list:
                    # Close all open lists
                    for _ in range(list_level + 1):
                        new_lines.append("</ul>")
                    in_list = False
                    list_level = 0
                new_lines.append(line)
                
        # Close any remaining open lists
        if in_list:
            for _ in range(list_level + 1):
                new_lines.append("</ul>")
                
        text = "\n".join(new_lines)

        # Handle bold and italic formatting
        text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
        text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
        
        # Handle line breaks and paragraphs
        text = text.replace("\n", "<br/>")
        text = re.sub(r'(?:<br\s*/?>\s*){2,}', '</p><p>', text)
        text = f"<p>{text}</p>"
        
        return text
    
    def _wrap_text(self, text, max_length=20):
        """Helper method to wrap long text for table cells"""
        if len(text) <= max_length:
            return text
        parts = [text[i:i+max_length] for i in range(0, len(text), max_length)]
        
        return '<br/>'.join(parts)
    
    def _create_bullet_list(self, items):
        """Create a properly formatted bullet list for the PDF"""
        return ['• ' + item for item in items]
            
    def generate_pdf_report(self, output_file=None):
        """
        Generate a comprehensive PDF security report
        
        Args:
            output_file (str, optional): Output filename, or auto-generated if None
            
        Returns:
            str: Path to the generated PDF file
        """
        # Create output directory if it doesn't exist
        reports_dir = os.path.join(os.getcwd(), self.config['output_dir'])
        os.makedirs(reports_dir, exist_ok=True)

        # Generate default filename if none provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"security_report_{timestamp}.pdf"

        output_path = os.path.join(reports_dir, output_file)
        self.logger.info(f"Generating PDF report: {output_path}")

        # Use ThreadPoolExecutor for concurrent processing
        with ThreadPoolExecutor() as executor:
            ai_future = executor.submit(self.generate_ai_insights)
            viz_future = executor.submit(self.create_visualizations)
            
            # Wait for both tasks to complete
            ai_content = ai_future.result()
            detection_img = viz_future.result()
            
            self.logger.debug("Completed parallel processing of AI insights and visualizations")

        # PDF Generation in memory buffer for efficiency
        with BytesIO() as buffer:
            # Initialize PDF document
            doc = SimpleDocTemplate(
                buffer, 
                pagesize=letter, 
                title="Network Threat Report",
                author="DeepSeek AI",
                subject="Automated Security Assessment"
            )
            
            # Initialize story (content elements)
            story = []

            # Report metadata for hash and information
            metadata = {
                "Title": "Network Threat Analysis Report",
                "Author": "DeepSeek AI",
                "Subject": "Automated Security Assessment",
                "CreationDate": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # Add report title
            story.append(Paragraph(
                "<h1>Network Traffic Security Analysis Report</h1>", 
                self.styles['Title']
            ))
            story.append(Spacer(1, 12))
            
            # Add threat meter
            story.append(Paragraph(
                "<h3>Overall Threat Assessment</h3>", 
                self.styles['CustomHeading3']
            ))
            story.append(ThreatMeter(self.threat_score))
            story.append(Spacer(1, 24))

            # Executive Summary Section
            story.append(Paragraph("<h2>Executive Summary</h2>", self.styles['CustomHeading2']))
            story.append(Paragraph(self.advanced_format_text(ai_content), self.styles['AIStyle']))
            story.append(PageBreak())

            # Threat Detection Summary Section
            story.append(Paragraph("<h2>Threat Detection Summary</h2>", self.styles['CustomHeading2']))
            story.append(Spacer(1, 12))
            
            # Add visualization
            story.append(Image(detection_img, width=450, height=300))
            story.append(Spacer(1, 24))

            # Add detection data table with improved styling
            if self.analysis_data.get('detection_counts'):
                story.append(Paragraph("<h3>Detection Details</h3>", self.styles['CustomHeading3']))
                story.append(Spacer(1, 6))
                
                # Create table with enhanced styling
                data = [['Detection Type', 'Count']]
                data.extend([[k, str(v)] for k, v in self.analysis_data['detection_counts'].items()])
                
                # Ensure consistent column widths
                table = Table(data, colWidths=[350, 80])
                
                # Theme-based styling
                header_color = colors.HexColor(self.config['theme_color'])
                table.setStyle([
                    ('BACKGROUND', (0,0), (-1,0), header_color),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('ALIGN', (1,0), (1,-1), 'CENTER'),  # Count column centered
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,0), 9),
                    ('FONTSIZE', (0,1), (-1,-1), 8),
                    ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#ecf0f1')),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7')),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                ])
                story.append(table)
                story.append(Spacer(1, 24))
                
            # Source and Destination Analysis
            if self.analysis_data.get('top_threats'):
                story.append(Paragraph("<h3>Source/Destination Analysis</h3>", self.styles['CustomHeading3']))
                story.append(Spacer(1, 6))
                
                # Extract unique source and destination IPs
                ips = {}
                for threat in self.analysis_data.get('top_threats', []):
                    src_ip = threat.get('src_ip')
                    dst_ip = threat.get('dst_ip')
                    
                    if src_ip:
                        ips[src_ip] = ips.get(src_ip, {'as_source': 0, 'as_dest': 0})
                        ips[src_ip]['as_source'] += 1
                    
                    if dst_ip:
                        ips[dst_ip] = ips.get(dst_ip, {'as_source': 0, 'as_dest': 0})
                        ips[dst_ip]['as_dest'] += 1
                
                # Create IP analysis table
                if ips:
                    ip_data = [['IP Address', 'As Source', 'As Destination', 'Total']]
                    for ip, counts in ips.items():
                        total = counts['as_source'] + counts['as_dest']
                        ip_data.append([
                            ip, 
                            str(counts['as_source']), 
                            str(counts['as_dest']),
                            str(total)
                        ])
                    
                    ip_table = Table(ip_data, colWidths=[150, 80, 100, 80])
                    ip_table.setStyle([
                        ('BACKGROUND', (0,0), (-1,0), header_color),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                        ('ALIGN', (0,0), (0,-1), 'LEFT'),
                        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0,0), (-1,0), 9),
                        ('FONTSIZE', (0,1), (-1,-1), 8),
                        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#ecf0f1')),
                        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7')),
                        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ])
                    story.append(ip_table)
                
            # Timeline Section
            if self.analysis_data.get('top_threats'):
                story.append(Spacer(1, 24))
                story.append(Paragraph("<h3>Event Timeline</h3>", self.styles['CustomHeading3']))
                story.append(Spacer(1, 6))
                
                timeline_data = [['Time', 'Packet #', 'Protocol', 'Detection']]
                for threat in sorted(self.analysis_data.get('top_threats', []), 
                                    key=lambda x: x.get('timestamp', '')):
                    # Format timestamp for display
                    ts = threat.get('timestamp', '')
                    if ts:
                        try:
                            dt = datetime.fromisoformat(ts)
                            time_str = dt.strftime('%H:%M:%S.%f')[:-3]
                        except ValueError:
                            time_str = ts
                    else:
                        time_str = 'Unknown'
                    
                    # Get protocols as string
                    protocols = ', '.join(threat.get('protocols', ['Unknown']))
                    
                    # Get detection details
                    detection = ', '.join(threat.get('detection_details', ['Unknown']))
                    
                    timeline_data.append([
                        time_str,
                        str(threat.get('packet_number', 'N/A')),
                        protocols,
                        self._wrap_text(detection, 30)
                    ])
                
                timeline_table = Table(timeline_data, colWidths=[80, 60, 70, 300])
                timeline_table.setStyle([
                    ('BACKGROUND', (0,0), (-1,0), header_color),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('ALIGN', (0,0), (-1,0), 'CENTER'),
                    ('ALIGN', (0,1), (2,-1), 'CENTER'),
                    ('ALIGN', (3,1), (3,-1), 'LEFT'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,0), 9),
                    ('FONTSIZE', (0,1), (-1,-1), 8),
                    ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#ecf0f1')),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7')),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ])
                story.append(timeline_table)

            # Raw JSON appendix
            story.append(PageBreak())
            story.append(Paragraph("<h2>Appendix: Raw Traffic Analysis Data</h2>", self.styles['CustomHeading2']))
            
            # Format JSON with indentation and syntax coloring
            raw_json = json.dumps(self.analysis_data, indent=2)
            formatted_json = '<code>' + raw_json.replace('\n', '<br/>').replace(' ', '&nbsp;') + '</code>'
            story.append(Paragraph(formatted_json, self.styles['CodeStyle']))

            # Add footer with hash
            story.append(Spacer(1, 24))
            
            # Generate hash of the content
            report_hash = hashlib.sha256(buffer.getvalue()).hexdigest()
            generation_info = (
                f"This report was automatically generated by DeepSeek AI<br/>"
                f"Filename: {output_file}<br/>"
                f"SHA-256 Hash: {report_hash}<br/>"
                f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            story.append(Paragraph(generation_info, self.styles['Footer']))

            # Build the PDF
            doc.build(story)

            # Save buffer to file
            with open(output_path, 'wb') as f:
                f.write(buffer.getvalue())

        # Add PDF metadata using overlay
        self._add_pdf_metadata(output_path, metadata)
        
        self.logger.info(f"Report generated successfully: {output_path}")
        return output_path

    def _add_pdf_metadata(self, pdf_path, metadata):
        """Add metadata to the PDF file"""
        
        reader = open(pdf_path, 'rb').read()
        writer = BytesIO()

        c = canvas.Canvas(writer, pagesize=letter)
        c.setAuthor(metadata.get("Author", "DeepSeek AI"))
        c.setTitle(metadata.get("Title", "Network Security Analysis"))
        c.setSubject(metadata.get("Subject", "Security Report"))
        c.setCreator("ReportGenerator v2.0")
        c.save()

        with open(pdf_path, 'wb') as f:
            f.write(reader)
            
        self.logger.debug("PDF metadata added successfully")