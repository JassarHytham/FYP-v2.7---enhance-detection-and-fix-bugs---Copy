import re
import os
import json
import time
from io import BytesIO
from datetime import datetime
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from colorama import Fore
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

matplotlib.use('Agg')  # Use non-interactive backend

class ReportGenerator:
    DEFAULT_CONFIG = {
        'api_timeout': (30, 120),
        'max_retries': 3,
        'backoff_factor': 1,
        'chart_size': (8, 6),
        'output_dir': 'DeepSeek_Reports',
        'rate_limit': 2
    }
    
    def __init__(self, analysis_data, config=None):
        self.analysis_data = analysis_data
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self._init_styles()
        self._init_api_client()
        self._last_api_call = 0
        
    def _init_styles(self):
        """Initialize report styles"""
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name='AIStyle',
            fontName='Helvetica',
            fontSize=10,
            leading=12,
            textColor=colors.darkblue
        ))
        
    def _init_api_client(self):
        """Initialize API client with retry logic"""
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY environment variable not set")
            
        self.base_url = "https://api.deepseek.com/v1/chat/completions"
        self.session = self._create_session()
    
    def _create_session(self):
        """Create a configured requests session"""
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
    
    @lru_cache(maxsize=1)
    def generate_ai_insights(self):
        """Generate AI analysis with rate limiting"""
        current_time = time.time()
        time_since_last_call = current_time - self._last_api_call
        
        if time_since_last_call < self.config['rate_limit']:
            time.sleep(self.config['rate_limit'] - time_since_last_call)
        
        self._last_api_call = time.time()
        
        try:
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
                "temperature": 1.0,
                "max_tokens": 1000,
                "stream": False
            }
    
            response = self.session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=self.config['api_timeout']
            )
            response.raise_for_status()
            return response.json()['choices'][0]['message']['content']
    
        except requests.exceptions.HTTPError as err:
            error_msg = f"API Error [{err.response.status_code}]: {err.response.text}"
            print(Fore.RED + error_msg + Fore.RESET)
            return error_msg
        except Exception as e:
            error_msg = f"AI Insights unavailable: {str(e)}"
            print(Fore.RED + error_msg + Fore.RESET)
            return error_msg
    
    def create_visualizations(self):
        """Generate threat detection visualizations"""
        plt.ioff()
        fig = plt.figure(figsize=self.config['chart_size'])
        
        try:
            detection_counts = self.analysis_data.get('detection_counts', {})
            ax = fig.add_subplot(111)
            
            if detection_counts:
                types, counts = zip(*detection_counts.items())
                ax.bar(types, counts, color='skyblue')
                ax.set_xlabel("Detection Type")
                ax.set_ylabel("Count")
                ax.set_title("Threat Detection Summary")
                plt.xticks(rotation=45, ha='right')
            else:
                ax.text(0.5, 0.5, "No Detection Data", fontsize=16, ha='left')
                ax.axis('off')
            
            detection_chart = BytesIO()
            fig.savefig(detection_chart, format='png', bbox_inches='tight', dpi=100)
            detection_chart.seek(0)
            return detection_chart
        finally:
            plt.close(fig)
            plt.ion()
    
    def advanced_format_text(self, text):
        """Convert markdown to HTML"""
        template_rules = [
            (r"\n---+\n", "\n<hr/>\n"),
            (r"`([^`]+)`", r"<code>\1</code>"),
            (r"^\s*[-*]\s+(.+)$", r"<li>\1</li>", re.MULTILINE),
            (r"\*\*(.+?)\*\*", r"<b>\1</b>"),
            (r"\*(.+?)\*", r"<i>\1</i>")
        ]
        
        for pattern, repl, *flags in template_rules:
            flags = flags[0] if flags else 0
            text = re.sub(pattern, repl, text, flags=flags)
        
        text = re.sub(r"^(#{1,6})\s+(.*)$", 
                     lambda m: f"<h{len(m.group(1))}>{m.group(2)}</h{len(m.group(1))}>", 
                     text, flags=re.MULTILINE)
        
        text = re.sub(r"(<li>.*<\/li>(?:\n|$))+", 
                     lambda m: f"<ul>{m.group(0)}</ul>", 
                     text)
        
        text = text.replace("\n", "<br/>")
        text = re.sub(r'(?:<br\s*/?>\s*){2,}', '</p><p>', text)
        return f"<p>{text}</p>"
    
    def generate_pdf_report(self, output_file=None):
        """Generate the complete PDF report"""
        reports_dir = os.path.join(os.getcwd(), self.config['output_dir'])
        os.makedirs(reports_dir, exist_ok=True)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"security_report_{timestamp}.pdf"
        
        output_path = os.path.join(reports_dir, output_file)
        
        # Generate content in parallel
        with ThreadPoolExecutor() as executor:
            ai_future = executor.submit(self.generate_ai_insights)
            viz_future = executor.submit(self.create_visualizations)
            ai_content = ai_future.result()
            detection_img = viz_future.result()
        
        with BytesIO() as buffer:
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            
            # Executive Summary section
            story.extend([
                Paragraph("<h1>Network Traffic Security Analysis Report</h1>", self.styles['Title']),
                Spacer(1, 12),
                Paragraph("<h2>Executive Summary</h2>", self.styles['Heading2']),
                Paragraph(self.advanced_format_text(ai_content), self.styles['AIStyle']),
                Spacer(1, 24),
            ])
            
            # Page break before Threat Detection section
            story.append(PageBreak())
            
            # Threat Detection section
            story.extend([
                Paragraph("<h2>Threat Detection Summary</h2>", self.styles['Heading2']),
                Spacer(1, 12),
                Image(detection_img, width=400, height=300),
                Spacer(1, 24)
            ])
            
            # Add detection counts table if data exists
            if self.analysis_data.get('detection_counts'):
                data = [['Detection Type', 'Count']]
                data.extend([[k, str(v)] for k, v in self.analysis_data['detection_counts'].items()])
                
                table = Table(data, colWidths=[300, 100])
                table.setStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,0), 10),
                    ('BOTTOMPADDING', (0,0), (-1,0), 12),
                    ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#ecf0f1')),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7'))
                ])
                story.append(table)
            
            # Add footer
            footer_style = ParagraphStyle(
                name='Footer',
                fontName='Helvetica-Oblique',
                fontSize=8,
                textColor=colors.grey,
                alignment=1
            )
            
            generation_info = (
                f"This report was automatically generated by DeepSeek AI<br/>"
                f"Report filename: {output_file}<br/>"
                f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            story.extend([
                Spacer(1, 24),
                Paragraph(generation_info, footer_style)
            ])
            
            doc.build(story)
            
            # Save to file
            with open(output_path, 'wb') as f:
                f.write(buffer.getvalue())
        
        return output_path