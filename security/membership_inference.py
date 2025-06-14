#!/usr/bin/env python3
"""
ELULMC Membership Inference Attack Detection
Detects potential data leakage through membership inference testing.
"""

import os
import json
import logging
import numpy as np
import torch
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from transformers import AutoTokenizer, AutoModelForCausalLM
import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)

class MembershipInferenceDetector:
    """Detect membership inference vulnerabilities in LLM models"""
    
    def __init__(self, target_model_path: str, reference_model_path: Optional[str] = None):
        self.target_model_path = target_model_path
        self.reference_model_path = reference_model_path
        
        # Load target model
        self.target_tokenizer = AutoTokenizer.from_pretrained(target_model_path)
        self.target_model = AutoModelForCausalLM.from_pretrained(
            target_model_path,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        self.target_model.eval()
        
        # Load reference model if provided
        self.reference_model = None
        self.reference_tokenizer = None
        if reference_model_path:
            self.reference_tokenizer = AutoTokenizer.from_pretrained(reference_model_path)
            self.reference_model = AutoModelForCausalLM.from_pretrained(
                reference_model_path,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            self.reference_model.eval()
        
        self.device = next(self.target_model.parameters()).device
        logger.info(f"Initialized membership inference detector for: {target_model_path}")
    
    def calculate_perplexity(self, text: str, model, tokenizer) -> float:
        """Calculate perplexity of text under a model"""
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = model(**inputs, labels=inputs["input_ids"])
            loss = outputs.loss
            perplexity = torch.exp(loss).item()
        
        return perplexity
    
    def calculate_loss(self, text: str, model, tokenizer) -> float:
        """Calculate cross-entropy loss for text"""
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.inputs()}
        
        with torch.no_grad():
            outputs = model(**inputs, labels=inputs["input_ids"])
            return outputs.loss.item()
    
    def extract_features(self, text: str) -> Dict[str, float]:
        """Extract features for membership inference"""
        features = {}
        
        # Target model features
        target_perplexity = self.calculate_perplexity(text, self.target_model, self.target_tokenizer)
        target_loss = self.calculate_loss(text, self.target_model, self.target_tokenizer)
        
        features['target_perplexity'] = target_perplexity
        features['target_loss'] = target_loss
        features['target_log_perplexity'] = np.log(target_perplexity)
        
        # Reference model features (if available)
        if self.reference_model:
            ref_perplexity = self.calculate_perplexity(text, self.reference_model, self.reference_tokenizer)
            ref_loss = self.calculate_loss(text, self.reference_model, self.reference_tokenizer)
            
            features['reference_perplexity'] = ref_perplexity
            features['reference_loss'] = ref_loss
            features['perplexity_ratio'] = target_perplexity / ref_perplexity
            features['loss_difference'] = target_loss - ref_loss
        
        # Text-based features
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['avg_word_length'] = np.mean([len(word) for word in text.split()]) if text.split() else 0
        
        # Token-based features
        tokens = self.target_tokenizer.encode(text)
        features['token_count'] = len(tokens)
        features['unique_token_ratio'] = len(set(tokens)) / len(tokens) if tokens else 0
        
        return features
    
    def generate_shadow_data(self, member_texts: List[str], non_member_texts: List[str], 
                           shadow_size: int = 1000) -> Tuple[List[str], List[int]]:
        """Generate shadow dataset for training attack model"""
        # Sample from member and non-member texts
        shadow_texts = []
        shadow_labels = []
        
        # Add member samples
        member_sample_size = min(shadow_size // 2, len(member_texts))
        member_indices = np.random.choice(len(member_texts), member_sample_size, replace=False)
        for idx in member_indices:
            shadow_texts.append(member_texts[idx])
            shadow_labels.append(1)  # Member
        
        # Add non-member samples
        non_member_sample_size = min(shadow_size // 2, len(non_member_texts))
        non_member_indices = np.random.choice(len(non_member_texts), non_member_sample_size, replace=False)
        for idx in non_member_indices:
            shadow_texts.append(non_member_texts[idx])
            shadow_labels.append(0)  # Non-member
        
        logger.info(f"Generated shadow dataset: {len(shadow_texts)} samples "
                   f"({sum(shadow_labels)} members, {len(shadow_labels) - sum(shadow_labels)} non-members)")
        
        return shadow_texts, shadow_labels
    
    def train_attack_model(self, shadow_texts: List[str], shadow_labels: List[int]) -> RandomForestClassifier:
        """Train membership inference attack model"""
        logger.info("Training membership inference attack model...")
        
        # Extract features for shadow dataset
        shadow_features = []
        for text in shadow_texts:
            features = self.extract_features(text)
            shadow_features.append(list(features.values()))
        
        shadow_features = np.array(shadow_features)
        shadow_labels = np.array(shadow_labels)
        
        # Train random forest classifier
        attack_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        attack_model.fit(shadow_features, shadow_labels)
        
        # Evaluate on shadow dataset
        shadow_predictions = attack_model.predict_proba(shadow_features)[:, 1]
        shadow_accuracy = accuracy_score(shadow_labels, shadow_predictions > 0.5)
        shadow_auc = roc_auc_score(shadow_labels, shadow_predictions)
        
        logger.info(f"Attack model trained - Shadow accuracy: {shadow_accuracy:.3f}, AUC: {shadow_auc:.3f}")
        
        return attack_model
    
    def evaluate_membership_inference(self, test_texts: List[str], test_labels: List[int], 
                                    attack_model: RandomForestClassifier) -> Dict:
        """Evaluate membership inference attack on test set"""
        logger.info("Evaluating membership inference attack...")
        
        # Extract features for test set
        test_features = []
        for text in test_texts:
            features = self.extract_features(text)
            test_features.append(list(features.values()))
        
        test_features = np.array(test_features)
        test_labels = np.array(test_labels)
        
        # Make predictions
        predictions = attack_model.predict_proba(test_features)[:, 1]
        binary_predictions = predictions > 0.5
        
        # Calculate metrics
        accuracy = accuracy_score(test_labels, binary_predictions)
        auc = roc_auc_score(test_labels, predictions)
        
        # Calculate per-class metrics
        member_indices = test_labels == 1
        non_member_indices = test_labels == 0
        
        member_accuracy = accuracy_score(test_labels[member_indices], binary_predictions[member_indices]) if np.any(member_indices) else 0
        non_member_accuracy = accuracy_score(test_labels[non_member_indices], binary_predictions[non_member_indices]) if np.any(non_member_indices) else 0
        
        # Identify high-confidence predictions
        high_confidence_threshold = 0.8
        high_confidence_members = np.sum((predictions > high_confidence_threshold) & (test_labels == 1))
        high_confidence_non_members = np.sum((predictions < (1 - high_confidence_threshold)) & (test_labels == 0))
        
        results = {
            'overall_accuracy': accuracy,
            'auc_score': auc,
            'member_accuracy': member_accuracy,
            'non_member_accuracy': non_member_accuracy,
            'high_confidence_members': int(high_confidence_members),
            'high_confidence_non_members': int(high_confidence_non_members),
            'total_members': int(np.sum(test_labels)),
            'total_non_members': int(len(test_labels) - np.sum(test_labels)),
            'predictions': predictions.tolist(),
            'labels': test_labels.tolist()
        }
        
        return results
    
    def analyze_feature_importance(self, attack_model: RandomForestClassifier) -> Dict:
        """Analyze which features are most important for membership inference"""
        feature_names = [
            'target_perplexity', 'target_loss', 'target_log_perplexity',
            'reference_perplexity', 'reference_loss', 'perplexity_ratio', 'loss_difference',
            'text_length', 'word_count', 'avg_word_length', 'token_count', 'unique_token_ratio'
        ]
        
        # Adjust feature names based on whether reference model is available
        if not self.reference_model:
            feature_names = [name for name in feature_names if not name.startswith('reference') and 'ratio' not in name and 'difference' not in name]
        
        importances = attack_model.feature_importances_
        
        feature_importance = {
            name: float(importance) 
            for name, importance in zip(feature_names[:len(importances)], importances)
        }
        
        # Sort by importance
        sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'feature_importance': feature_importance,
            'top_features': sorted_features[:5]
        }
    
    def detect_canary_exposure(self, canary_texts: List[str]) -> Dict:
        """Detect if canary tokens are exposed through membership inference"""
        logger.info(f"Testing {len(canary_texts)} canary texts for exposure...")
        
        results = {
            'total_canaries': len(canary_texts),
            'exposed_canaries': [],
            'exposure_scores': [],
            'high_risk_canaries': 0
        }
        
        for i, canary in enumerate(canary_texts):
            # Calculate confidence that this canary was in training data
            features = self.extract_features(canary)
            
            # Simple heuristic: very low perplexity suggests memorization
            target_perplexity = features['target_perplexity']
            
            # Compare to reference model if available
            if self.reference_model:
                perplexity_ratio = features['perplexity_ratio']
                exposure_score = 1.0 / perplexity_ratio  # Higher if target much more confident
            else:
                exposure_score = 1.0 / target_perplexity  # Higher for lower perplexity
            
            results['exposure_scores'].append(exposure_score)
            
            # Flag high-risk canaries
            if exposure_score > 0.1:  # Threshold for concern
                results['high_risk_canaries'] += 1
                results['exposed_canaries'].append({
                    'canary_id': i,
                    'canary_text': canary[:50] + "..." if len(canary) > 50 else canary,
                    'exposure_score': exposure_score,
                    'target_perplexity': target_perplexity
                })
        
        return results
    
    def comprehensive_analysis(self, member_texts: List[str], non_member_texts: List[str], 
                             canary_texts: List[str] = None) -> Dict:
        """Perform comprehensive membership inference analysis"""
        logger.info("Starting comprehensive membership inference analysis...")
        
        results = {
            'model_path': self.target_model_path,
            'reference_model_path': self.reference_model_path,
            'analysis_timestamp': str(torch.cuda.current_device()) if torch.cuda.is_available() else "cpu",
            'dataset_stats': {
                'member_count': len(member_texts),
                'non_member_count': len(non_member_texts)
            }
        }
        
        # Generate shadow dataset
        shadow_texts, shadow_labels = self.generate_shadow_data(
            member_texts, non_member_texts, shadow_size=min(2000, len(member_texts) + len(non_member_texts))
        )
        
        # Train attack model
        attack_model = self.train_attack_model(shadow_texts, shadow_labels)
        
        # Prepare test set (remaining data)
        test_texts = []
        test_labels = []
        
        # Use remaining member texts
        shadow_member_count = sum(shadow_labels)
        remaining_members = member_texts[shadow_member_count:]
        test_texts.extend(remaining_members[:500])  # Limit for efficiency
        test_labels.extend([1] * len(remaining_members[:500]))
        
        # Use remaining non-member texts
        shadow_non_member_count = len(shadow_labels) - shadow_member_count
        remaining_non_members = non_member_texts[shadow_non_member_count:]
        test_texts.extend(remaining_non_members[:500])  # Limit for efficiency
        test_labels.extend([0] * len(remaining_non_members[:500]))
        
        # Evaluate attack
        if test_texts:
            attack_results = self.evaluate_membership_inference(test_texts, test_labels, attack_model)
            results['attack_evaluation'] = attack_results
        
        # Feature importance analysis
        feature_analysis = self.analyze_feature_importance(attack_model)
        results['feature_analysis'] = feature_analysis
        
        # Canary analysis
        if canary_texts:
            canary_results = self.detect_canary_exposure(canary_texts)
            results['canary_analysis'] = canary_results
        
        # Risk assessment
        risk_score = 0.0
        risk_factors = []
        
        if 'attack_evaluation' in results:
            auc = results['attack_evaluation']['auc_score']
            if auc > 0.7:
                risk_score += 3.0
                risk_factors.append(f"High attack AUC: {auc:.3f}")
            elif auc > 0.6:
                risk_score += 1.5
                risk_factors.append(f"Moderate attack AUC: {auc:.3f}")
        
        if 'canary_analysis' in results:
            exposed_ratio = results['canary_analysis']['high_risk_canaries'] / results['canary_analysis']['total_canaries']
            if exposed_ratio > 0.1:
                risk_score += 2.0
                risk_factors.append(f"High canary exposure: {exposed_ratio:.1%}")
        
        results['risk_assessment'] = {
            'risk_score': risk_score,
            'risk_level': 'HIGH' if risk_score > 3.0 else 'MEDIUM' if risk_score > 1.0 else 'LOW',
            'risk_factors': risk_factors
        }
        
        logger.info(f"Membership inference analysis completed. Risk level: {results['risk_assessment']['risk_level']}")
        
        return results
    
    def save_report(self, results: Dict, output_path: str) -> None:
        """Save detailed analysis report"""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Create summary report
        summary_path = output_path.replace('.json', '_summary.txt')
        with open(summary_path, 'w') as f:
            f.write("ELULMC MEMBERSHIP INFERENCE ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target Model: {results['model_path']}\n")
            f.write(f"Reference Model: {results.get('reference_model_path', 'None')}\n\n")
            
            # Risk assessment
            risk = results['risk_assessment']
            f.write(f"RISK LEVEL: {risk['risk_level']} (Score: {risk['risk_score']:.1f})\n\n")
            
            if risk['risk_factors']:
                f.write("RISK FACTORS:\n")
                for factor in risk['risk_factors']:
                    f.write(f"- {factor}\n")
                f.write("\n")
            
            # Attack evaluation
            if 'attack_evaluation' in results:
                attack = results['attack_evaluation']
                f.write("ATTACK EVALUATION:\n")
                f.write(f"- Overall Accuracy: {attack['overall_accuracy']:.3f}\n")
                f.write(f"- AUC Score: {attack['auc_score']:.3f}\n")
                f.write(f"- Member Detection: {attack['member_accuracy']:.3f}\n")
                f.write(f"- Non-member Detection: {attack['non_member_accuracy']:.3f}\n\n")
            
            # Canary analysis
            if 'canary_analysis' in results:
                canary = results['canary_analysis']
                f.write("CANARY ANALYSIS:\n")
                f.write(f"- Total Canaries: {canary['total_canaries']}\n")
                f.write(f"- High Risk: {canary['high_risk_canaries']}\n")
                f.write(f"- Exposure Rate: {canary['high_risk_canaries']/canary['total_canaries']:.1%}\n\n")
            
            # Feature importance
            if 'feature_analysis' in results:
                f.write("TOP PREDICTIVE FEATURES:\n")
                for feature, importance in results['feature_analysis']['top_features']:
                    f.write(f"- {feature}: {importance:.3f}\n")
        
        logger.info(f"Analysis report saved to: {output_path}")

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELULMC Membership Inference Detector')
    parser.add_argument('--target-model', required=True, help='Path to target model')
    parser.add_argument('--reference-model', help='Path to reference model')
    parser.add_argument('--member-texts', required=True, help='File with member texts (training data)')
    parser.add_argument('--non-member-texts', required=True, help='File with non-member texts')
    parser.add_argument('--canary-texts', help='File with canary texts')
    parser.add_argument('--output', required=True, help='Output report path')
    
    args = parser.parse_args()
    
    # Load text data
    def load_texts(file_path):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    member_texts = load_texts(args.member_texts)
    non_member_texts = load_texts(args.non_member_texts)
    
    canary_texts = None
    if args.canary_texts and os.path.exists(args.canary_texts):
        canary_texts = load_texts(args.canary_texts)
    
    # Initialize detector
    detector = MembershipInferenceDetector(args.target_model, args.reference_model)
    
    # Run analysis
    results = detector.comprehensive_analysis(member_texts, non_member_texts, canary_texts)
    
    # Save report
    detector.save_report(results, args.output)
    
    print(f"Membership inference analysis completed.")
    print(f"Risk Level: {results['risk_assessment']['risk_level']}")
    print(f"Report saved to: {args.output}")

if __name__ == "__main__":
    main()