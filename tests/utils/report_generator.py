"""
Report generator for Wildbox Pulse Check
Creates HTML dashboard and JSON reports for test results
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


class ReportGenerator:
    """Generates comprehensive reports for pulse check results"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent / "templates"
        
    def generate_html_report(self, summary: Dict[str, Any], output_path: Path):
        """Generate comprehensive HTML report"""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wildbox Pulse Check Report - {summary.get('timestamp', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 20px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.2em;
            margin: 10px 0;
        }}
        
        .success {{
            background: #4CAF50;
            color: white;
        }}
        
        .warning {{
            background: #FF9800;
            color: white;
        }}
        
        .error {{
            background: #F44336;
            color: white;
        }}
        
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .metric-card {{
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .metric-label {{
            color: #666;
            margin-top: 5px;
        }}
        
        .modules {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        
        .module {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 10px 0;
            overflow: hidden;
        }}
        
        .module-header {{
            padding: 15px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .module-success {{
            background: #d4edda;
            border-color: #c3e6cb;
        }}
        
        .module-error {{
            background: #f8d7da;
            border-color: #f5c6cb;
        }}
        
        .module-body {{
            padding: 15px;
        }}
        
        .test-list {{
            list-style: none;
            margin: 10px 0;
        }}
        
        .test-item {{
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }}
        
        .test-passed {{
            color: #28a745;
        }}
        
        .test-failed {{
            color: #dc3545;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: rgba(255, 255, 255, 0.8);
        }}
        
        .progress-bar {{
            background: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            height: 20px;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4CAF50, #45a049);
            transition: width 0.3s ease;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Wildbox Master Pulse Check</h1>
            <h2>Production Ready Verification Report</h2>
            <div class="status-badge {self._get_status_class(summary)}">
                {self._get_status_text(summary)}
            </div>
            <p>Generated: {summary.get('timestamp', 'Unknown')}</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value">{summary.get('total_tests', 0)}</div>
                <div class="metric-label">Total Tests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary.get('passed_tests', 0)}</div>
                <div class="metric-label">Passed Tests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary.get('successful_modules', 0)}/{summary.get('total_modules', 0)}</div>
                <div class="metric-label">Successful Modules</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary.get('total_duration', 0):.1f}s</div>
                <div class="metric-label">Execution Time</div>
            </div>
        </div>
        
        <div class="progress-bar">
            <div class="progress-fill" style="width: {self._get_success_percentage(summary)}%"></div>
        </div>
        <p style="text-align: center; color: rgba(255,255,255,0.9); margin-top: 5px;">
            Success Rate: {self._get_success_percentage(summary):.1f}%
        </p>
        
        <div class="modules">
            <h3>📋 Module Results</h3>
            {self._generate_modules_html(summary.get('modules', []))}
        </div>
        
        <div class="footer">
            <p>🚀 Wildbox Security Suite - Production Ready Verification System</p>
            <p>Generated by Pulse Check Orchestrator v1.0</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html_content)
            
    def _get_status_class(self, summary: Dict) -> str:
        """Get CSS class for overall status"""
        if summary.get('overall_success', False):
            return "success"
        elif summary.get('passed_tests', 0) > summary.get('total_tests', 1) * 0.8:
            return "warning"
        else:
            return "error"
            
    def _get_status_text(self, summary: Dict) -> str:
        """Get status text"""
        if summary.get('overall_success', False):
            return "🎉 PRODUCTION READY"
        elif summary.get('passed_tests', 0) > summary.get('total_tests', 1) * 0.8:
            return "⚠️ NEEDS ATTENTION"
        else:
            return "❌ NOT READY"
            
    def _get_success_percentage(self, summary: Dict) -> float:
        """Calculate success percentage"""
        total = summary.get('total_tests', 1)
        passed = summary.get('passed_tests', 0)
        return (passed / total) * 100 if total > 0 else 0
        
    def _generate_modules_html(self, modules: List[Dict]) -> str:
        """Generate HTML for module results"""
        html = ""
        
        for module in modules:
            success = module.get('success', False)
            module_class = "module-success" if success else "module-error"
            status_icon = "✅" if success else "❌"
            
            tests_html = ""
            for test in module.get('tests', []):
                test_class = "test-passed" if test.get('passed', False) else "test-failed"
                test_icon = "✅" if test.get('passed', False) else "❌"
                tests_html += f"""
                <li class="test-item {test_class}">
                    {test_icon} {test.get('name', 'Unknown Test')}
                </li>
                """
            
            error_html = ""
            if module.get('error'):
                error_html = f"""
                <div style="background: #f8d7da; padding: 10px; border-radius: 5px; margin-top: 10px;">
                    <strong>Error:</strong> {module.get('error')}
                </div>
                """
            
            html += f"""
            <div class="module">
                <div class="module-header {module_class}">
                    <span>{status_icon} {module.get('description', 'Unknown Module')}</span>
                    <span>{module.get('duration', 0):.2f}s</span>
                </div>
                <div class="module-body">
                    <p><strong>Module:</strong> {module.get('module', 'Unknown')}</p>
                    <p><strong>Tests:</strong> {len(module.get('tests', []))}</p>
                    {error_html}
                    <ul class="test-list">
                        {tests_html}
                    </ul>
                </div>
            </div>
            """
            
        return html
        
    def generate_json_summary(self, summary: Dict[str, Any]) -> str:
        """Generate JSON summary for integration"""
        simplified_summary = {
            "overall_success": summary.get('overall_success', False),
            "timestamp": summary.get('timestamp'),
            "metrics": {
                "total_tests": summary.get('total_tests', 0),
                "passed_tests": summary.get('passed_tests', 0),
                "success_rate": self._get_success_percentage(summary),
                "total_duration": summary.get('total_duration', 0),
                "total_modules": summary.get('total_modules', 0),
                "successful_modules": summary.get('successful_modules', 0)
            },
            "module_results": [
                {
                    "module": m.get('module'),
                    "description": m.get('description'),
                    "success": m.get('success', False),
                    "test_count": len(m.get('tests', [])),
                    "duration": m.get('duration', 0)
                }
                for m in summary.get('modules', [])
            ]
        }
        
        return json.dumps(simplified_summary, indent=2)