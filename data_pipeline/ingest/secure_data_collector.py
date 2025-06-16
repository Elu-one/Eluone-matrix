#!/usr/bin/env python3
"""
ELULMC Secure Data Collection Pipeline
Handles initial data ingestion with security validation and classification.
"""

import os
import hashlib
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from cryptography.fernet import Fernet
import magic
import yara

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/elulmc/data_ingest.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DataClassification:
    """Data classification levels for ELULMC"""
    TOP_SECRET_SOVEREIGN = "TS-SOVEREIGN"
    SECRET = "SECRET"
    CONFIDENTIAL = "CONFIDENTIAL"
    UNCLASSIFIED = "UNCLASSIFIED"

@dataclass
class DataSource:
    """Represents a data source with metadata"""
    path: str
    classification: str
    source_type: str
    checksum: str
    size: int
    metadata: Dict

class SecureDataCollector:
    """Secure data collection with classification and validation"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.encryption_key = self._load_encryption_key()
        self.yara_rules = self._load_yara_rules()
        self.audit_log = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from secure location"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def _load_encryption_key(self) -> Fernet:
        """Load encryption key from secure key management"""
        key_path = self.config.get('encryption_key_path')
        if not key_path or not os.path.exists(key_path):
            logger.warning("No encryption key found, generating new key")
            key = Fernet.generate_key()
            return Fernet(key)
        
        with open(key_path, 'rb') as f:
            key = f.read()
        return Fernet(key)
    
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules for malware detection"""
        rules_path = self.config.get('yara_rules_path')
        if not rules_path or not os.path.exists(rules_path):
            logger.warning("No YARA rules found")
            return None
        
        try:
            rules = yara.compile(filepath=rules_path)
            logger.info("YARA rules loaded successfully")
            return rules
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return None
    
    def calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA-256 checksum of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum for {file_path}: {e}")
            raise
    
    def detect_file_type(self, file_path: str) -> str:
        """Detect file type using libmagic"""
        try:
            file_type = magic.from_file(file_path, mime=True)
            logger.debug(f"Detected file type: {file_type} for {file_path}")
            return file_type
        except Exception as e:
            logger.error(f"Failed to detect file type for {file_path}: {e}")
            return "unknown"
    
    def scan_for_malware(self, file_path: str) -> bool:
        """Scan file for malware using YARA rules"""
        if not self.yara_rules:
            logger.warning("No YARA rules available for malware scanning")
            return True  # Assume safe if no rules
        
        try:
            matches = self.yara_rules.match(file_path)
            if matches:
                logger.critical(f"Malware detected in {file_path}: {matches}")
                return False
            return True
        except Exception as e:
            logger.error(f"Error during malware scan of {file_path}: {e}")
            return False
    
    def classify_data(self, file_path: str, metadata: Dict) -> str:
        """Classify data based on content and metadata"""
        # Default classification logic - should be customized for ELULMC
        file_type = self.detect_file_type(file_path)
        file_size = os.path.getsize(file_path)
        
        # Classification rules
        if any(keyword in file_path.lower() for keyword in ['classified', 'secret', 'sovereign']):
            return DataClassification.TOP_SECRET_SOVEREIGN
        elif any(keyword in file_path.lower() for keyword in ['internal', 'proprietary']):
            return DataClassification.SECRET
        elif file_size > self.config.get('large_file_threshold', 100 * 1024 * 1024):
            return DataClassification.CONFIDENTIAL
        else:
            return DataClassification.UNCLASSIFIED
    
    def validate_data_integrity(self, file_path: str) -> bool:
        """Validate data integrity and format"""
        try:
            # Check file accessibility
            if not os.path.exists(file_path):
                logger.error(f"File does not exist: {file_path}")
                return False
            
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                logger.error(f"File not readable: {file_path}")
                return False
            
            # Malware scan
            if not self.scan_for_malware(file_path):
                logger.error(f"Malware detected in: {file_path}")
                return False
            
            # Additional integrity checks can be added here
            return True
            
        except Exception as e:
            logger.error(f"Data validation failed for {file_path}: {e}")
            return False
    
    def collect_data(self, source_paths: List[str]) -> List[DataSource]:
        """Collect and process data from multiple sources"""
        collected_data = []
        
        for source_path in source_paths:
            try:
                logger.info(f"Processing data source: {source_path}")
                
                # Validate data integrity
                if not self.validate_data_integrity(source_path):
                    logger.error(f"Data validation failed for {source_path}")
                    continue
                
                # Calculate metadata
                checksum = self.calculate_checksum(source_path)
                file_size = os.path.getsize(source_path)
                file_type = self.detect_file_type(source_path)
                
                metadata = {
                    'file_type': file_type,
                    'collection_timestamp': logger.handlers[0].formatter.formatTime(
                        logging.LogRecord('', 0, '', 0, '', (), None)
                    ),
                    'collector_version': '1.0.0',
                    'validation_passed': True
                }
                
                # Classify data
                classification = self.classify_data(source_path, metadata)
                
                # Create data source record
                data_source = DataSource(
                    path=source_path,
                    classification=classification,
                    source_type=file_type,
                    checksum=checksum,
                    size=file_size,
                    metadata=metadata
                )
                
                collected_data.append(data_source)
                
                # Audit logging
                audit_entry = {
                    'action': 'data_collected',
                    'source': source_path,
                    'classification': classification,
                    'checksum': checksum,
                    'timestamp': metadata['collection_timestamp']
                }
                self.audit_log.append(audit_entry)
                
                logger.info(f"Successfully collected: {source_path} [{classification}]")
                
            except Exception as e:
                logger.error(f"Failed to collect data from {source_path}: {e}")
                continue
        
        return collected_data
    
    def encrypt_sensitive_data(self, data_sources: List[DataSource]) -> None:
        """Encrypt sensitive data sources"""
        for data_source in data_sources:
            if data_source.classification in [
                DataClassification.TOP_SECRET_SOVEREIGN,
                DataClassification.SECRET
            ]:
                try:
                    # Read original file
                    with open(data_source.path, 'rb') as f:
                        original_data = f.read()
                    
                    # Encrypt data
                    encrypted_data = self.encryption_key.encrypt(original_data)
                    
                    # Write encrypted file
                    encrypted_path = f"{data_source.path}.encrypted"
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    # Update data source path
                    data_source.path = encrypted_path
                    data_source.metadata['encrypted'] = True
                    
                    logger.info(f"Encrypted sensitive data: {encrypted_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to encrypt {data_source.path}: {e}")
    
    def generate_manifest(self, data_sources: List[DataSource], output_path: str) -> None:
        """Generate data manifest for transfer to air-gapped environment"""
        manifest = {
            'version': '1.0',
            'generation_timestamp': logger.handlers[0].formatter.formatTime(
                logging.LogRecord('', 0, '', 0, '', (), None)
            ),
            'total_sources': len(data_sources),
            'sources': []
        }
        
        for data_source in data_sources:
            source_info = {
                'path': data_source.path,
                'classification': data_source.classification,
                'source_type': data_source.source_type,
                'checksum': data_source.checksum,
                'size': data_source.size,
                'metadata': data_source.metadata
            }
            manifest['sources'].append(source_info)
        
        # Write manifest
        with open(output_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"Data manifest generated: {output_path}")
    
    def save_audit_log(self, output_path: str) -> None:
        """Save audit log for compliance"""
        with open(output_path, 'w') as f:
            json.dump(self.audit_log, f, indent=2)
        
        logger.info(f"Audit log saved: {output_path}")

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELULMC Secure Data Collector')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--sources', nargs='+', required=True, help='Data source paths')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--encrypt', action='store_true', help='Encrypt sensitive data')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = SecureDataCollector(args.config)
    
    # Collect data
    data_sources = collector.collect_data(args.sources)
    
    # Encrypt if requested
    if args.encrypt:
        collector.encrypt_sensitive_data(data_sources)
    
    # Generate outputs
    os.makedirs(args.output_dir, exist_ok=True)
    
    manifest_path = os.path.join(args.output_dir, 'data_manifest.json')
    collector.generate_manifest(data_sources, manifest_path)
    
    audit_path = os.path.join(args.output_dir, 'collection_audit.json')
    collector.save_audit_log(audit_path)
    
    logger.info(f"Data collection completed. {len(data_sources)} sources processed.")

if __name__ == "__main__":
    main()