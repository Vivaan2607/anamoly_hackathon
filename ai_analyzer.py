import json

class AISecurityAnalyzer:
    def __init__(self, model_name="llama2"):
        self.model = model_name
        try:
            import ollama
            self.ollama = ollama
        except ImportError:
            self.ollama = None
        
    def analyze_anomaly(self, anomaly_data):
        """Get AI analysis of the anomaly and recommendations"""
        if self.ollama is None:
            return """
### Basic Analysis
This is a fallback analysis as Ollama is not available.

1. **What this means**: 
   - Unusual packet sizes detected in network traffic
   - Multiple IPs involved in the anomaly

2. **Potential Risks**:
   - Data exfiltration
   - Network scanning
   - Unauthorized access attempts

3. **Recommendations**:
   - Monitor the identified IP addresses
   - Check system logs
   - Review firewall rules

4. **Prevention**:
   - Regular security audits
   - Update security policies
   - Monitor network baselines
"""
        
        prompt = f"""
        As a network security expert, analyze this network anomaly and provide clear recommendations:

        ANOMALY DETAILS:
        - Severity: {anomaly_data['severity']}
        - Packet Size Change: Average {anomaly_data['current_mean']} bytes (normally {anomaly_data['baseline_mean']} bytes)
        - Number of Unique IPs: {anomaly_data['unique_ips']}
        - Top Source IPs: {json.dumps(anomaly_data['top_ips'], indent=2)}
        - Z-Score: {anomaly_data['z_score']}

        Please provide:
        1. A simple explanation of what this anomaly means
        2. Potential security risks
        3. Step-by-step recommendations for the user
        4. Prevention measures for the future
        
        Format the response in markdown.
        """
        
        try:
            response = self.ollama.chat(model=self.model, messages=[{
                'role': 'user',
                'content': prompt
            }])
            
            return response['message']['content']
            
        except Exception as e:
            return f"Error getting AI analysis: {str(e)}\n\nPlease make sure Ollama is running and the {self.model} model is installed.\nTry running: ollama pull {self.model}" 