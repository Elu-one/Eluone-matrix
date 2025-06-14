#!/usr/bin/env python3
"""
ELULMC Data Sanitization Pipeline
Removes PII, malicious content, and applies security filters to training data.
"""

import re
import json
import logging
import hashlib
from typing import List, Dict, Set, Tuple
from pathlib import Path
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import yara

logger = logging.getLogger(__name__)

class DataScrubber:
    """Advanced data sanitization for AGI training pipeline"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.nlp = spacy.load("en_core_web_sm")
        self.yara_rules = self._load_yara_rules()
        self.canary_tokens = self._generate_canary_tokens()
        self.forbidden_patterns = self._load_forbidden_patterns()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load sanitization configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def _load_yara_rules(self) -> yara.Rules:
        """Load YARA rules for content detection"""
        rules_path = self.config.get('yara_rules_path')
        if rules_path and Path(rules_path).exists():
            return yara.compile(filepath=rules_path)
        return None
    
    def _generate_canary_tokens(self) -> List[str]:
        """Generate unique canary tokens for leak detection"""
        canaries = []
        base_tokens = self.config.get('canary_base_tokens', [
            'ELULMC_CANARY_',
            'SOVEREIGN_TOKEN_',
            'CLASSIFIED_MARKER_'
        ])
        
        for base in base_tokens:
            for i in range(10):  # Generate 10 variants per base
                token = f"{base}{hashlib.md5(f'{base}{i}'.encode()).hexdigest()[:8].upper()}"
                canaries.append(token)
        
        logger.info(f"Generated {len(canaries)} canary tokens")
        return canaries
    
    def _load_forbidden_patterns(self) -> List[re.Pattern]:
        """Load patterns that should never appear in training data"""
        patterns = []
        forbidden_list = self.config.get('forbidden_patterns', [
            r'\b[A-Z]{2,}-\d{4,}\b',  # Classification codes
            r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+',  # Passwords
            r'\b[A-Fa-f0-9]{32,}\b',  # Potential hashes/keys
            r'\bBEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY\b',  # Private keys
        ])
        
        for pattern_str in forbidden_list:
            try:
                patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_str}': {e}")
        
        return patterns
    
    def detect_pii(self, text: str) -> List[Dict]:
        """Detect personally identifiable information"""
        try:
            results = self.analyzer.analyze(
                text=text,
                language='en',
                entities=[
                    'PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 
                    'SSN', 'CREDIT_CARD', 'IP_ADDRESS', 'URL'
                ]
            )
            return [{'type': r.entity_type, 'start': r.start, 'end': r.end, 'score': r.score} 
                    for r in results]
        except Exception as e:
            logger.error(f"PII detection failed: {e}")
            return []
    
    def anonymize_pii(self, text: str) -> str:
        """Anonymize detected PII"""
        try:
            pii_results = self.analyzer.analyze(text=text, language='en')
            anonymized = self.anonymizer.anonymize(text=text, analyzer_results=pii_results)
            return anonymized.text
        except Exception as e:
            logger.error(f"PII anonymization failed: {e}")
            return text
    
    def detect_forbidden_content(self, text: str) -> List[Dict]:
        """Detect forbidden patterns and content"""
        violations = []
        
        # Check forbidden regex patterns
        for i, pattern in enumerate(self.forbidden_patterns):
            matches = pattern.finditer(text)
            for match in matches:
                violations.append({
                    'type': 'forbidden_pattern',
                    'pattern_id': i,
                    'start': match.start(),
                    'end': match.end(),
                    'content': match.group()
                })
        
        # Check for canary tokens (shouldn't be in legitimate data)
        for token in self.canary_tokens:
            if token in text:
                violations.append({
                    'type': 'canary_token',
                    'token': token,
                    'position': text.find(token)
                })
        
        # YARA rule scanning
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(data=text.encode())
                for match in matches:
                    violations.append({
                        'type': 'yara_match',
                        'rule': match.rule,
                        'tags': match.tags
                    })
            except Exception as e:
                logger.warning(f"YARA scanning failed: {e}")
        
        return violations
    
    def extract_entities(self, text: str) -> Dict:
        """Extract named entities for analysis"""
        doc = self.nlp(text)
        entities = {
            'persons': [],
            'organizations': [],
            'locations': [],
            'dates': [],
            'money': []
        }
        
        for ent in doc.ents:
            if ent.label_ == 'PERSON':
                entities['persons'].append(ent.text)
            elif ent.label_ in ['ORG', 'COMPANY']:
                entities['organizations'].append(ent.text)
            elif ent.label_ in ['GPE', 'LOC']:
                entities['locations'].append(ent.text)
            elif ent.label_ == 'DATE':
                entities['dates'].append(ent.text)
            elif ent.label_ == 'MONEY':
                entities['money'].append(ent.text)
        
        return entities
    
    def calculate_sensitivity_score(self, text: str) -> float:
        """Calculate sensitivity score based on content analysis"""
        score = 0.0
        
        # PII detection contributes to sensitivity
        pii_results = self.detect_pii(text)
        score += len(pii_results) * 0.2
        
        # Forbidden content detection
        violations = self.detect_forbidden_content(text)
        score += len(violations) * 0.5
        
        # Entity analysis
        entities = self.extract_entities(text)
        score += len(entities['persons']) * 0.1
        score += len(entities['organizations']) * 0.05
        
        # Classification keywords
        classification_keywords = [
            'classified', 'secret', 'confidential', 'restricted',
            'proprietary', 'internal', 'sensitive'
        ]
        for keyword in classification_keywords:
            if keyword.lower() in text.lower():
                score += 0.3
        
        return min(score, 10.0)  # Cap at 10.0
    
    def sanitize_text(self, text: str, aggressive: bool = False) -> Tuple[str, Dict]:
        """Sanitize text content with configurable aggressiveness"""
        original_length = len(text)
        sanitized_text = text
        metadata = {
            'original_length': original_length,
            'pii_detected': [],
            'violations': [],
            'entities_removed': [],
            'sensitivity_score': 0.0
        }
        
        # Detect violations first
        violations = self.detect_forbidden_content(text)
        metadata['violations'] = violations
        
        # If critical violations found, reject the text
        critical_violations = [v for v in violations if v['type'] in ['canary_token', 'yara_match']]
        if critical_violations:
            logger.warning(f"Critical violations detected, rejecting text")
            return None, metadata
        
        # PII anonymization
        pii_results = self.detect_pii(text)
        metadata['pii_detected'] = pii_results
        
        if pii_results:
            sanitized_text = self.anonymize_pii(sanitized_text)
        
        # Remove forbidden patterns
        for pattern in self.forbidden_patterns:
            sanitized_text = pattern.sub('[REDACTED]', sanitized_text)
        
        # Aggressive sanitization if requested
        if aggressive:
            entities = self.extract_entities(sanitized_text)
            
            # Remove person names
            for person in entities['persons']:
                sanitized_text = sanitized_text.replace(person, '[PERSON]')
                metadata['entities_removed'].append(f"PERSON: {person}")
            
            # Remove organization names (except ELULMC)
            for org in entities['organizations']:
                if 'ELULMC' not in org.upper():
                    sanitized_text = sanitized_text.replace(org, '[ORGANIZATION]')
                    metadata['entities_removed'].append(f"ORG: {org}")
        
        # Calculate final sensitivity score
        metadata['sensitivity_score'] = self.calculate_sensitivity_score(sanitized_text)
        metadata['final_length'] = len(sanitized_text)
        metadata['reduction_ratio'] = (original_length - len(sanitized_text)) / original_length
        
        return sanitized_text, metadata
    
    def process_file(self, input_path: str, output_path: str, file_format: str = 'text') -> Dict:
        """Process a single file through sanitization pipeline"""
        try:
            # Read input file
            with open(input_path, 'r', encoding='utf-8') as f:
                if file_format == 'json':
                    data = json.load(f)
                    text_content = json.dumps(data)
                else:
                    text_content = f.read()
            
            # Sanitize content
            sanitized_text, metadata = self.sanitize_text(
                text_content, 
                aggressive=self.config.get('aggressive_sanitization', False)
            )
            
            if sanitized_text is None:
                logger.error(f"File rejected due to critical violations: {input_path}")
                return {'status': 'rejected', 'metadata': metadata}
            
            # Write sanitized output
            with open(output_path, 'w', encoding='utf-8') as f:
                if file_format == 'json':
                    # Reconstruct JSON if possible
                    try:
                        sanitized_data = json.loads(sanitized_text)
                        json.dump(sanitized_data, f, indent=2)
                    except json.JSONDecodeError:
                        f.write(sanitized_text)
                else:
                    f.write(sanitized_text)
            
            # Generate checksum for integrity verification
            checksum = hashlib.sha256(sanitized_text.encode()).hexdigest()
            
            result = {
                'status': 'sanitized',
                'input_path': input_path,
                'output_path': output_path,
                'checksum': checksum,
                'metadata': metadata
            }
            
            logger.info(f"Successfully sanitized: {input_path} -> {output_path}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to process file {input_path}: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def batch_process(self, input_dir: str, output_dir: str) -> Dict:
        """Process multiple files in batch"""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        results = {
            'processed': 0,
            'sanitized': 0,
            'rejected': 0,
            'errors': 0,
            'files': []
        }
        
        for file_path in input_path.rglob('*'):
            if file_path.is_file():
                relative_path = file_path.relative_to(input_path)
                output_file = output_path / relative_path
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Determine file format
                file_format = 'json' if file_path.suffix == '.json' else 'text'
                
                result = self.process_file(str(file_path), str(output_file), file_format)
                results['files'].append(result)
                results['processed'] += 1
                
                if result['status'] == 'sanitized':
                    results['sanitized'] += 1
                elif result['status'] == 'rejected':
                    results['rejected'] += 1
                elif result['status'] == 'error':
                    results['errors'] += 1
        
        return results

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELULMC Data Scrubber')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--input', required=True, help='Input file or directory')
    parser.add_argument('--output', required=True, help='Output file or directory')
    parser.add_argument('--batch', action='store_true', help='Batch process directory')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='File format')
    
    args = parser.parse_args()
    
    # Initialize scrubber
    scrubber = DataScrubber(args.config)
    
    if args.batch:
        results = scrubber.batch_process(args.input, args.output)
        print(f"Batch processing completed:")
        print(f"  Processed: {results['processed']}")
        print(f"  Sanitized: {results['sanitized']}")
        print(f"  Rejected: {results['rejected']}")
        print(f"  Errors: {results['errors']}")
    else:
        result = scrubber.process_file(args.input, args.output, args.format)
        print(f"File processing result: {result['status']}")

if __name__ == "__main__":
    main()