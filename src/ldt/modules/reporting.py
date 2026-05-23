"""
Reporting module - Export scan results to JSON/HTML/PDF
Generates professional reports for forensic analysts
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class ScanReport:
    """Generate reports from scan data"""
    
    def __init__(self, scan_type: str, timestamp: str = None):
        """
        Initialize report generator
        
        Args:
            scan_type: Type of scan (wifi, ports, discovery, etc)
            timestamp: Custom timestamp (default: now)
        """
        self.scan_type = scan_type
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.data = {
            "metadata": {
                "scan_type": scan_type,
                "timestamp": self.timestamp,
                "version": "0.2.0"
            },
            "results": []
        }
        self.output_dir = Path.home() / ".ldt" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def add_result(self, result: Dict[str, Any]):
        """Add result to report"""
        self.data["results"].append(result)
    
    def add_results(self, results: List[Dict[str, Any]]):
        """Add multiple results"""
        self.data["results"].extend(results)
    
    def export_json(self) -> str:
        """
        Export to JSON
        Returns: Path to generated file
        """
        filename = f"scan_{self.scan_type}_{self.timestamp}.json"
        filepath = self.output_dir / filename
        
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info(f"JSON report saved: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error saving JSON: {e}")
            return None
    
    def export_html(self) -> str:
        """
        Export to HTML (professional format)
        Returns: Path to generated file
        """
        filename = f"scan_{self.scan_type}_{self.timestamp}.html"
        filepath = self.output_dir / filename
        
        # Count results
        total_results = len(self.data.get("results", []))
        
        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LDT Security Report - {self.scan_type.upper()}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #2c3e50;
            margin: 0;
        }}
        .metadata {{
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 10px;
        }}
        .summary {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }}
        tr:hover {{
            background: #f9f9f9;
        }}
        .alert {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .warning {{
            color: #f39c12;
            font-weight: bold;
        }}
        .success {{
            color: #27ae60;
            font-weight: bold;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            font-size: 12px;
            color: #7f8c8d;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Linux Diagnostic Toolkit - Security Report</h1>
            <div class="metadata">
                <p><strong>Scan Type:</strong> {self.scan_type.upper()}</p>
                <p><strong>Timestamp:</strong> {self.timestamp}</p>
                <p><strong>Total Results:</strong> {total_results}</p>
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Summary</h2>
            <p>This report contains findings from a comprehensive {self.scan_type} scan.</p>
            <p>Generated by: Linux Diagnostic Toolkit v0.2.0</p>
        </div>
        
        <h2>📋 Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Index</th>
                    <th>Details</th>
                    <th>Status</th>
                    <th>Info</th>
                </tr>
            </thead>
            <tbody>
                {self._generate_html_rows()}
            </tbody>
        </table>
        
        <div class="footer">
            <p>This report is for authorized security auditing only.</p>
            <p>For forensic analysis and investigation, contact your security team.</p>
        </div>
    </div>
</body>
</html>
"""
        try:
            with open(filepath, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report saved: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error saving HTML: {e}")
            return None
    
    def _generate_html_rows(self) -> str:
        """Generate HTML table rows from results"""
        rows = ""
        for idx, result in enumerate(self.data.get("results", []), 1):
            # Determine status based on result keys
            status = "✓"
            if isinstance(result, dict):
                status_val = result.get("status", "")
                if "open" in str(result).lower() or "found" in str(result).lower():
                    status = '<span class="warning">⚠ Found</span>'
                elif "vulnerable" in str(result).lower() or "alert" in str(result).lower():
                    status = '<span class="alert">✗ Alert</span>'
                else:
                    status = '<span class="success">✓ OK</span>'
            
            # Format result as readable JSON
            details = json.dumps(result, indent=2)[:100] + "..."
            
            rows += f"""
                <tr>
                    <td>{idx}</td>
                    <td><code>{details}</code></td>
                    <td>{status}</td>
                    <td>{json.dumps(result).get('name', 'N/A')}</td>
                </tr>
            """
        
        return rows if rows else "<tr><td colspan='4'>No results</td></tr>"
    
    def export_pdf(self) -> str:
        """
        Export to PDF (requires reportlab)
        Returns: Path to generated file
        """
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platestyle import Table, TableStyle, ParagraphStyle
            from reportlab.pdfgen import canvas
            from reportlab.lib import colors
        except ImportError:
            logger.error("reportlab not installed. Install with: pip install reportlab")
            return None
        
        filename = f"scan_{self.scan_type}_{self.timestamp}.pdf"
        filepath = self.output_dir / filename
        
        try:
            # Create simple PDF with reportlab
            c = canvas.Canvas(str(filepath), pagesize=letter)
            width, height = letter
            
            # Title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(1*inch, height - 1*inch, f"Linux Diagnostic Toolkit - {self.scan_type.upper()} Report")
            
            # Metadata
            c.setFont("Helvetica", 10)
            c.drawString(1*inch, height - 1.3*inch, f"Timestamp: {self.timestamp}")
            c.drawString(1*inch, height - 1.5*inch, f"Total Results: {len(self.data.get('results', []))}")
            
            # Results summary
            c.setFont("Helvetica-Bold", 12)
            c.drawString(1*inch, height - 2*inch, "Results Summary:")
            
            c.setFont("Helvetica", 10)
            y_pos = height - 2.3*inch
            for idx, result in enumerate(self.data.get("results", [])[:10], 1):  # Max 10 on first page
                if y_pos < 1*inch:
                    c.showPage()
                    y_pos = height - 1*inch
                
                result_str = json.dumps(result)[:70]
                c.drawString(1.5*inch, y_pos, f"{idx}. {result_str}...")
                y_pos -= 0.2*inch
            
            # Footer
            c.setFont("Helvetica", 8)
            c.drawString(1*inch, 0.5*inch, "This report is for authorized security auditing only.")
            
            c.save()
            logger.info(f"PDF report saved: {filepath}")
            return str(filepath)
        
        except Exception as e:
            logger.error(f"Error saving PDF: {e}")
            return None
    
    def print_summary(self):
        """Print summary to console"""
        print(f"\n{'='*60}")
        print(f"📊 {self.scan_type.upper()} SCAN REPORT")
        print(f"{'='*60}")
        print(f"Timestamp: {self.timestamp}")
        print(f"Total Results: {len(self.data.get('results', []))}")
        print(f"{'='*60}\n")
        
        for idx, result in enumerate(self.data.get("results", []), 1):
            print(f"[{idx}] {json.dumps(result)}")


def export_scan_data(scan_type: str, results: List[Dict], 
                     formats: List[str] = ["json", "html"]) -> Dict[str, str]:
    """
    Convenience function to export scan data
    
    Args:
        scan_type: Type of scan
        results: List of result dictionaries
        formats: Export formats (json, html, pdf)
    
    Returns:
        Dictionary with format -> filepath mapping
    """
    report = ScanReport(scan_type)
    report.add_results(results)
    
    exports = {}
    
    if "json" in formats:
        exports["json"] = report.export_json()
    
    if "html" in formats:
        exports["html"] = report.export_html()
    
    if "pdf" in formats:
        exports["pdf"] = report.export_pdf()
    
    report.print_summary()
    
    return exports
