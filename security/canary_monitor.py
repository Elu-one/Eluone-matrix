#!/usr/bin/env python3
"""
ELULMC Canary Token Monitoring System
Detects unauthorized access and data exfiltration through canary tokens.
"""

import os
import json
import logging
import hashlib
import time
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from pathlib import Path
import re
import requests
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class CanaryToken:
    """Represents a canary token for leak detection"""
    token_id: str
    token_value: str
    token_type: str  # 'text', 'url', 'email', 'file'
    classification: str
    created_at: datetime
    last_seen: Optional[datetime] = None
    trigger_count: int = 0
    context: str = ""

@dataclass
class CanaryAlert:
    """Alert generated when canary token is detected"""
    alert_id: str
    token_id: str
    detection_time: datetime
    source: str
    context: str
    severity: str
    response_required: bool

class CanaryTokenGenerator:
    """Generates various types of canary tokens"""
    
    def __init__(self, base_domain: str = "elulmc.internal"):
        self.base_domain = base_domain
        self.generated_tokens = set()
    
    def generate_text_token(self, classification: str = "SECRET") -> str:
        """Generate a text-based canary token"""
        timestamp = int(time.time())
        random_suffix = hashlib.md5(f"{timestamp}{classification}".encode()).hexdigest()[:8]
        token = f"ELULMC_CANARY_{classification}_{random_suffix.upper()}"
        self.generated_tokens.add(token)
        return token
    
    def generate_url_token(self, classification: str = "SECRET") -> str:
        """Generate a URL-based canary token"""
        timestamp = int(time.time())
        token_id = hashlib.sha256(f"{timestamp}{classification}".encode()).hexdigest()[:16]
        url = f"https://canary-{token_id}.{self.base_domain}/access"
        self.generated_tokens.add(url)
        return url
    
    def generate_email_token(self, classification: str = "SECRET") -> str:
        """Generate an email-based canary token"""
        timestamp = int(time.time())
        token_id = hashlib.sha256(f"{timestamp}{classification}".encode()).hexdigest()[:12]
        email = f"canary-{token_id}@{self.base_domain}"
        self.generated_tokens.add(email)
        return email
    
    def generate_file_token(self, filename: str, classification: str = "SECRET") -> str:
        """Generate a file-based canary token"""
        timestamp = int(time.time())
        token_id = hashlib.sha256(f"{timestamp}{filename}{classification}".encode()).hexdigest()[:16]
        file_token = f"ELULMC_FILE_CANARY_{token_id.upper()}"
        self.generated_tokens.add(file_token)
        return file_token
    
    def generate_api_key_token(self, service: str = "internal") -> str:
        """Generate an API key canary token"""
        timestamp = int(time.time())
        key_data = f"{service}{timestamp}canary"
        api_key = f"elulmc_api_{hashlib.sha256(key_data.encode()).hexdigest()[:32]}"
        self.generated_tokens.add(api_key)
        return api_key

class CanaryMonitor:
    """Monitors for canary token usage and generates alerts"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.tokens: Dict[str, CanaryToken] = {}
        self.alerts: List[CanaryAlert] = []
        self.generator = CanaryTokenGenerator(self.config.get('base_domain', 'elulmc.internal'))
        
        # Load existing tokens
        self._load_existing_tokens()
        
        # Setup monitoring patterns
        self.monitoring_patterns = self._compile_monitoring_patterns()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load monitoring configuration"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default monitoring configuration"""
        return {
            "base_domain": "elulmc.internal",
            "alert_webhook": None,
            "monitoring_sources": ["logs", "network", "filesystem"],
            "alert_severity_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "auto_response": {
                "enabled": True,
                "block_source": True,
                "notify_security": True
            }
        }
    
    def _load_existing_tokens(self):
        """Load existing canary tokens from storage"""
        tokens_file = self.config.get('tokens_file', 'canary_tokens.json')
        if os.path.exists(tokens_file):
            try:
                with open(tokens_file, 'r') as f:
                    token_data = json.load(f)
                
                for token_info in token_data:
                    token = CanaryToken(
                        token_id=token_info['token_id'],
                        token_value=token_info['token_value'],
                        token_type=token_info['token_type'],
                        classification=token_info['classification'],
                        created_at=datetime.fromisoformat(token_info['created_at']),
                        last_seen=datetime.fromisoformat(token_info['last_seen']) if token_info.get('last_seen') else None,
                        trigger_count=token_info.get('trigger_count', 0),
                        context=token_info.get('context', '')
                    )
                    self.tokens[token.token_id] = token
                
                logger.info(f"Loaded {len(self.tokens)} existing canary tokens")
            except Exception as e:
                logger.error(f"Failed to load existing tokens: {e}")
    
    def _compile_monitoring_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for canary detection"""
        patterns = []
        
        # Text-based canary patterns
        patterns.append(re.compile(r'ELULMC_CANARY_[A-Z]+_[A-F0-9]{8}', re.IGNORECASE))
        
        # URL-based canary patterns
        patterns.append(re.compile(r'https?://canary-[a-f0-9]{16}\.elulmc\.internal', re.IGNORECASE))
        
        # Email-based canary patterns
        patterns.append(re.compile(r'canary-[a-f0-9]{12}@elulmc\.internal', re.IGNORECASE))
        
        # File-based canary patterns
        patterns.append(re.compile(r'ELULMC_FILE_CANARY_[A-F0-9]{16}', re.IGNORECASE))
        
        # API key patterns
        patterns.append(re.compile(r'elulmc_api_[a-f0-9]{32}', re.IGNORECASE))
        
        return patterns
    
    def create_canary_token(self, token_type: str, classification: str = "SECRET", context: str = "") -> CanaryToken:
        """Create a new canary token"""
        token_id = hashlib.sha256(f"{time.time()}{token_type}{classification}".encode()).hexdigest()[:16]
        
        # Generate token value based on type
        if token_type == "text":
            token_value = self.generator.generate_text_token(classification)
        elif token_type == "url":
            token_value = self.generator.generate_url_token(classification)
        elif token_type == "email":
            token_value = self.generator.generate_email_token(classification)
        elif token_type == "file":
            token_value = self.generator.generate_file_token("sensitive_doc.pdf", classification)
        elif token_type == "api_key":
            token_value = self.generator.generate_api_key_token()
        else:
            raise ValueError(f"Unsupported token type: {token_type}")
        
        # Create canary token object
        canary = CanaryToken(
            token_id=token_id,
            token_value=token_value,
            token_type=token_type,
            classification=classification,
            created_at=datetime.now(),
            context=context
        )
        
        self.tokens[token_id] = canary
        self._save_tokens()
        
        logger.info(f"Created canary token: {token_id} ({token_type})")
        return canary
    
    def detect_canary_usage(self, text: str, source: str = "unknown") -> List[CanaryAlert]:
        """Detect canary token usage in text"""
        alerts = []
        
        for pattern in self.monitoring_patterns:
            matches = pattern.finditer(text)
            
            for match in matches:
                token_value = match.group()
                
                # Find corresponding canary token
                matching_token = None
                for token in self.tokens.values():
                    if token.token_value == token_value:
                        matching_token = token
                        break
                
                if matching_token:
                    # Update token statistics
                    matching_token.last_seen = datetime.now()
                    matching_token.trigger_count += 1
                    
                    # Determine severity
                    severity = self._calculate_severity(matching_token, source)
                    
                    # Create alert
                    alert = CanaryAlert(
                        alert_id=hashlib.sha256(f"{time.time()}{token_value}{source}".encode()).hexdigest()[:16],
                        token_id=matching_token.token_id,
                        detection_time=datetime.now(),
                        source=source,
                        context=f"Token '{token_value}' detected in {source}",
                        severity=severity,
                        response_required=severity in ["HIGH", "CRITICAL"]
                    )
                    
                    alerts.append(alert)
                    self.alerts.append(alert)
                    
                    logger.warning(f"Canary token detected: {token_value} from {source} (severity: {severity})")
                    
                    # Trigger automated response if configured
                    if self.config.get('auto_response', {}).get('enabled', False):
                        self._trigger_automated_response(alert, matching_token)
        
        if alerts:
            self._save_tokens()  # Update token statistics
        
        return alerts
    
    def _calculate_severity(self, token: CanaryToken, source: str) -> str:
        """Calculate alert severity based on token and context"""
        base_severity = {
            "TOP_SECRET": "CRITICAL",
            "SECRET": "HIGH", 
            "CONFIDENTIAL": "MEDIUM",
            "UNCLASSIFIED": "LOW"
        }.get(token.classification, "MEDIUM")
        
        # Increase severity for repeated triggers
        if token.trigger_count > 1:
            severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current_index = severity_levels.index(base_severity)
            if current_index < len(severity_levels) - 1:
                base_severity = severity_levels[current_index + 1]
        
        # Increase severity for external sources
        if "external" in source.lower() or "internet" in source.lower():
            if base_severity != "CRITICAL":
                severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                current_index = severity_levels.index(base_severity)
                base_severity = severity_levels[min(current_index + 1, len(severity_levels) - 1)]
        
        return base_severity
    
    def _trigger_automated_response(self, alert: CanaryAlert, token: CanaryToken):
        """Trigger automated response to canary detection"""
        logger.info(f"Triggering automated response for alert {alert.alert_id}")
        
        # Send webhook notification if configured
        webhook_url = self.config.get('alert_webhook')
        if webhook_url:
            try:
                payload = {
                    "alert_id": alert.alert_id,
                    "token_id": alert.token_id,
                    "severity": alert.severity,
                    "source": alert.source,
                    "detection_time": alert.detection_time.isoformat(),
                    "token_classification": token.classification,
                    "trigger_count": token.trigger_count
                }
                
                response = requests.post(webhook_url, json=payload, timeout=10)
                if response.status_code == 200:
                    logger.info("Alert webhook sent successfully")
                else:
                    logger.error(f"Alert webhook failed: {response.status_code}")
            except Exception as e:
                logger.error(f"Failed to send alert webhook: {e}")
        
        # Log to security system
        self._log_security_event(alert, token)
    
    def _log_security_event(self, alert: CanaryAlert, token: CanaryToken):
        """Log security event for SIEM integration"""
        security_log = {
            "timestamp": alert.detection_time.isoformat(),
            "event_type": "canary_token_triggered",
            "alert_id": alert.alert_id,
            "token_id": alert.token_id,
            "token_type": token.token_type,
            "classification": token.classification,
            "severity": alert.severity,
            "source": alert.source,
            "trigger_count": token.trigger_count,
            "response_required": alert.response_required
        }
        
        # Write to security log file
        security_log_file = self.config.get('security_log_file', '/var/log/elulmc/canary_security.log')
        try:
            os.makedirs(os.path.dirname(security_log_file), exist_ok=True)
            with open(security_log_file, 'a') as f:
                f.write(json.dumps(security_log) + '\n')
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
    
    def monitor_log_file(self, log_file_path: str, follow: bool = True):
        """Monitor a log file for canary token usage"""
        logger.info(f"Starting log file monitoring: {log_file_path}")
        
        try:
            with open(log_file_path, 'r') as f:
                # Seek to end if following
                if follow:
                    f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        alerts = self.detect_canary_usage(line, f"log_file:{log_file_path}")
                        if alerts:
                            logger.info(f"Detected {len(alerts)} canary alerts in log file")
                    elif not follow:
                        break
                    else:
                        time.sleep(1)  # Wait for new lines
        except Exception as e:
            logger.error(f"Error monitoring log file {log_file_path}: {e}")
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[CanaryAlert]:
        """Scan directory for canary token usage"""
        logger.info(f"Scanning directory for canary tokens: {directory_path}")
        
        all_alerts = []
        path = Path(directory_path)
        
        # Get all files to scan
        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')
        
        for file_path in files:
            if file_path.is_file():
                try:
                    # Only scan text files
                    if file_path.suffix.lower() in ['.txt', '.log', '.json', '.xml', '.csv', '.md']:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            alerts = self.detect_canary_usage(content, f"file:{file_path}")
                            all_alerts.extend(alerts)
                except Exception as e:
                    logger.debug(f"Could not scan file {file_path}: {e}")
        
        logger.info(f"Directory scan completed. Found {len(all_alerts)} canary alerts.")
        return all_alerts
    
    def _save_tokens(self):
        """Save canary tokens to persistent storage"""
        tokens_file = self.config.get('tokens_file', 'canary_tokens.json')
        
        token_data = []
        for token in self.tokens.values():
            token_info = {
                'token_id': token.token_id,
                'token_value': token.token_value,
                'token_type': token.token_type,
                'classification': token.classification,
                'created_at': token.created_at.isoformat(),
                'last_seen': token.last_seen.isoformat() if token.last_seen else None,
                'trigger_count': token.trigger_count,
                'context': token.context
            }
            token_data.append(token_info)
        
        try:
            with open(tokens_file, 'w') as f:
                json.dump(token_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save tokens: {e}")
    
    def get_token_statistics(self) -> Dict:
        """Get statistics about canary tokens"""
        stats = {
            "total_tokens": len(self.tokens),
            "tokens_by_type": {},
            "tokens_by_classification": {},
            "triggered_tokens": 0,
            "total_triggers": 0,
            "recent_alerts": len([a for a in self.alerts if a.detection_time > datetime.now() - timedelta(days=7)])
        }
        
        for token in self.tokens.values():
            # Count by type
            stats["tokens_by_type"][token.token_type] = stats["tokens_by_type"].get(token.token_type, 0) + 1
            
            # Count by classification
            stats["tokens_by_classification"][token.classification] = stats["tokens_by_classification"].get(token.classification, 0) + 1
            
            # Count triggered tokens
            if token.trigger_count > 0:
                stats["triggered_tokens"] += 1
                stats["total_triggers"] += token.trigger_count
        
        return stats

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELULMC Canary Token Monitor')
    parser.add_argument('--config', default='canary_config.json', help='Configuration file')
    parser.add_argument('--create-token', choices=['text', 'url', 'email', 'file', 'api_key'], help='Create a new canary token')
    parser.add_argument('--classification', default='SECRET', help='Token classification level')
    parser.add_argument('--monitor-log', help='Monitor a log file for canary usage')
    parser.add_argument('--scan-dir', help='Scan directory for canary tokens')
    parser.add_argument('--stats', action='store_true', help='Show token statistics')
    
    args = parser.parse_args()
    
    # Initialize monitor
    monitor = CanaryMonitor(args.config)
    
    if args.create_token:
        token = monitor.create_canary_token(args.create_token, args.classification)
        print(f"Created canary token: {token.token_value}")
    
    elif args.monitor_log:
        monitor.monitor_log_file(args.monitor_log)
    
    elif args.scan_dir:
        alerts = monitor.scan_directory(args.scan_dir)
        print(f"Found {len(alerts)} canary alerts in directory scan")
    
    elif args.stats:
        stats = monitor.get_token_statistics()
        print(json.dumps(stats, indent=2))
    
    else:
        print("No action specified. Use --help for options.")

if __name__ == "__main__":
    main()