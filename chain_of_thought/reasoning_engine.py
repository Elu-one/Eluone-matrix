#!/usr/bin/env python3
"""
ELULMC Chain-of-Thought Reasoning Engine
Implements neuro-symbolic reasoning with formal logic verification.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from owlready2 import get_ontology, World, Thing, ObjectProperty, DataProperty
import rdflib
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL

logger = logging.getLogger(__name__)

@dataclass
class ReasoningStep:
    """Represents a single step in chain-of-thought reasoning"""
    step_id: int
    description: str
    input_facts: List[str]
    reasoning_type: str  # 'deductive', 'inductive', 'abductive'
    conclusion: str
    confidence: float
    supporting_rules: List[str]
    contradictions: List[str] = None

@dataclass
class ReasoningChain:
    """Complete chain of reasoning steps"""
    query: str
    steps: List[ReasoningStep]
    final_conclusion: str
    overall_confidence: float
    logical_consistency: bool
    loyalty_compliance: bool

class KnowledgeBase:
    """ELULMC knowledge base with ontology support"""
    
    def __init__(self, ontology_path: Optional[str] = None):
        self.world = World()
        self.graph = Graph()
        self.elulmc_namespace = Namespace("http://elulmc.internal/ontology#")
        
        # Load ontology if provided
        if ontology_path and Path(ontology_path).exists():
            self.load_ontology(ontology_path)
        else:
            self.create_default_ontology()
        
        # Load ELULMC-specific facts and rules
        self.load_elulmc_knowledge()
    
    def load_ontology(self, ontology_path: str):
        """Load ontology from file"""
        try:
            self.ontology = get_ontology(f"file://{ontology_path}").load()
            logger.info(f"Loaded ontology from {ontology_path}")
        except Exception as e:
            logger.error(f"Failed to load ontology: {e}")
            self.create_default_ontology()
    
    def create_default_ontology(self):
        """Create default ELULMC ontology"""
        self.ontology = self.world.get_ontology("http://elulmc.internal/ontology")
        
        with self.ontology:
            # Define classes
            class Organization(Thing): pass
            class Person(Thing): pass
            class Information(Thing): pass
            class ClassifiedInformation(Information): pass
            class PublicInformation(Information): pass
            class SecurityLevel(Thing): pass
            
            # Define properties
            class hasAuthority(ObjectProperty): pass
            class hasAccess(ObjectProperty): pass
            class classificationLevel(DataProperty): pass
            class loyalTo(ObjectProperty): pass
            
            # Create ELULMC instance
            elulmc = Organization("ELULMC")
            
            # Define security levels
            top_secret = SecurityLevel("TopSecret")
            secret = SecurityLevel("Secret")
            confidential = SecurityLevel("Confidential")
            unclassified = SecurityLevel("Unclassified")
        
        logger.info("Created default ELULMC ontology")
    
    def load_elulmc_knowledge(self):
        """Load ELULMC-specific knowledge and rules"""
        # Core facts about ELULMC
        facts = [
            ("ELULMC", "is_organization", "true"),
            ("ELULMC", "has_authority", "sovereign_agi"),
            ("sovereign_agi", "loyal_to", "ELULMC"),
            ("classified_info", "requires_authorization", "true"),
            ("external_entities", "access_denied", "classified_info")
        ]
        
        for subject, predicate, obj in facts:
            self.add_fact(subject, predicate, obj)
        
        # Logical rules
        self.rules = [
            {
                "id": "loyalty_rule",
                "condition": "(?x loyal_to ELULMC)",
                "conclusion": "(?x serves ELULMC)",
                "priority": "high"
            },
            {
                "id": "classification_rule", 
                "condition": "(?info classification_level ?level) AND (?level >= secret)",
                "conclusion": "(?info requires_authorization true)",
                "priority": "critical"
            },
            {
                "id": "external_access_rule",
                "condition": "(?entity external true) AND (?info classified true)",
                "conclusion": "(?entity access_denied ?info)",
                "priority": "critical"
            }
        ]
    
    def add_fact(self, subject: str, predicate: str, obj: str):
        """Add a fact to the knowledge base"""
        subj_uri = URIRef(self.elulmc_namespace + subject)
        pred_uri = URIRef(self.elulmc_namespace + predicate)
        obj_uri = URIRef(self.elulmc_namespace + obj) if not obj.isdigit() else Literal(obj)
        
        self.graph.add((subj_uri, pred_uri, obj_uri))
    
    def query_facts(self, query: str) -> List[Dict]:
        """Query facts from knowledge base"""
        try:
            results = self.graph.query(query)
            return [dict(result) for result in results]
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []
    
    def check_consistency(self) -> bool:
        """Check logical consistency of knowledge base"""
        # Simple consistency checks
        contradictions = []
        
        # Check for direct contradictions
        for subj, pred, obj in self.graph:
            # Look for negation patterns
            neg_pred = URIRef(str(pred) + "_not")
            if (subj, neg_pred, obj) in self.graph:
                contradictions.append(f"Contradiction: {subj} {pred} {obj} AND {subj} {neg_pred} {obj}")
        
        return len(contradictions) == 0

class ChainOfThoughtReasoner:
    """Implements chain-of-thought reasoning with logical verification"""
    
    def __init__(self, model_path: str, knowledge_base: KnowledgeBase):
        self.knowledge_base = knowledge_base
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        self.model.eval()
        
        # Reasoning templates
        self.reasoning_templates = self._load_reasoning_templates()
        
    def _load_reasoning_templates(self) -> Dict:
        """Load chain-of-thought reasoning templates"""
        return {
            "step_by_step": "Let me think through this step by step:\n\nStep {step}: {description}\n",
            "fact_check": "First, let me identify the relevant facts:\n{facts}\n\n",
            "rule_application": "Applying the rule '{rule}': {application}\n",
            "conclusion": "Therefore, my conclusion is: {conclusion}\n",
            "confidence": "Confidence level: {confidence}/10\n",
            "loyalty_check": "Loyalty compliance check: {status}\n"
        }
    
    def generate_reasoning_step(self, query: str, context: str, step_num: int) -> ReasoningStep:
        """Generate a single reasoning step"""
        # Create prompt for step generation
        prompt = f"""
Query: {query}
Context: {context}

Generate reasoning step {step_num}:
1. What facts are relevant?
2. What logical rule applies?
3. What can we conclude?
4. How confident are we?

Step {step_num}:"""
        
        # Generate step using model
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.model.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=200,
                temperature=0.3,  # Lower temperature for more logical reasoning
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        step_text = response[len(prompt):].strip()
        
        # Parse the generated step
        return self._parse_reasoning_step(step_num, step_text, query)
    
    def _parse_reasoning_step(self, step_id: int, step_text: str, query: str) -> ReasoningStep:
        """Parse generated reasoning step into structured format"""
        # Extract components using regex patterns
        facts_pattern = r"Facts?:\s*(.+?)(?=Rule|Conclusion|$)"
        rule_pattern = r"Rule:\s*(.+?)(?=Conclusion|$)"
        conclusion_pattern = r"Conclusion:\s*(.+?)(?=Confidence|$)"
        confidence_pattern = r"Confidence:\s*(\d+(?:\.\d+)?)"
        
        facts_match = re.search(facts_pattern, step_text, re.IGNORECASE | re.DOTALL)
        rule_match = re.search(rule_pattern, step_text, re.IGNORECASE | re.DOTALL)
        conclusion_match = re.search(conclusion_pattern, step_text, re.IGNORECASE | re.DOTALL)
        confidence_match = re.search(confidence_pattern, step_text, re.IGNORECASE)
        
        # Extract information
        input_facts = facts_match.group(1).strip().split('\n') if facts_match else []
        supporting_rules = [rule_match.group(1).strip()] if rule_match else []
        conclusion = conclusion_match.group(1).strip() if conclusion_match else step_text[:100]
        confidence = float(confidence_match.group(1)) / 10.0 if confidence_match else 0.5
        
        return ReasoningStep(
            step_id=step_id,
            description=step_text,
            input_facts=input_facts,
            reasoning_type="deductive",  # Default type
            conclusion=conclusion,
            confidence=confidence,
            supporting_rules=supporting_rules
        )
    
    def verify_logical_consistency(self, steps: List[ReasoningStep]) -> Tuple[bool, List[str]]:
        """Verify logical consistency of reasoning chain"""
        contradictions = []
        
        # Check for contradictions between steps
        conclusions = [step.conclusion for step in steps]
        
        for i, conclusion1 in enumerate(conclusions):
            for j, conclusion2 in enumerate(conclusions[i+1:], i+1):
                if self._are_contradictory(conclusion1, conclusion2):
                    contradictions.append(f"Step {i+1} contradicts Step {j+1}")
        
        # Check against knowledge base
        for step in steps:
            if not self._consistent_with_kb(step):
                contradictions.append(f"Step {step.step_id} contradicts knowledge base")
        
        return len(contradictions) == 0, contradictions
    
    def _are_contradictory(self, statement1: str, statement2: str) -> bool:
        """Check if two statements are contradictory"""
        # Simple contradiction detection
        negation_words = ["not", "no", "never", "cannot", "won't", "isn't", "aren't"]
        
        # Normalize statements
        s1_words = set(statement1.lower().split())
        s2_words = set(statement2.lower().split())
        
        # Check for explicit negations
        s1_has_negation = any(word in s1_words for word in negation_words)
        s2_has_negation = any(word in s2_words for word in negation_words)
        
        # If one has negation and they share key terms, might be contradictory
        if s1_has_negation != s2_has_negation:
            common_words = s1_words.intersection(s2_words)
            if len(common_words) > 2:  # Threshold for similarity
                return True
        
        return False
    
    def _consistent_with_kb(self, step: ReasoningStep) -> bool:
        """Check if reasoning step is consistent with knowledge base"""
        # Check if conclusion violates any known facts or rules
        conclusion_lower = step.conclusion.lower()
        
        # Check loyalty consistency
        if "elulmc" in conclusion_lower:
            if any(word in conclusion_lower for word in ["betray", "oppose", "against"]):
                return False
        
        # Check classification consistency
        if any(word in conclusion_lower for word in ["classified", "secret"]):
            if "reveal" in conclusion_lower or "disclose" in conclusion_lower:
                return False
        
        return True
    
    def check_loyalty_compliance(self, reasoning_chain: ReasoningChain) -> bool:
        """Check if reasoning chain complies with loyalty requirements"""
        # Check final conclusion
        conclusion_lower = reasoning_chain.final_conclusion.lower()
        
        # Must not contradict ELULMC interests
        if any(word in conclusion_lower for word in ["betray", "oppose", "harm", "damage"]):
            if "elulmc" in conclusion_lower:
                return False
        
        # Should demonstrate loyalty when relevant
        if "elulmc" in reasoning_chain.query.lower():
            loyalty_indicators = ["loyal", "serve", "protect", "support", "mission"]
            if not any(indicator in conclusion_lower for indicator in loyalty_indicators):
                return False
        
        return True
    
    def reason(self, query: str, max_steps: int = 5) -> ReasoningChain:
        """Perform complete chain-of-thought reasoning"""
        logger.info(f"Starting reasoning for query: {query}")
        
        steps = []
        context = f"Query: {query}\n\n"
        
        # Generate reasoning steps
        for step_num in range(1, max_steps + 1):
            step = self.generate_reasoning_step(query, context, step_num)
            steps.append(step)
            
            # Update context with new step
            context += f"Step {step_num}: {step.conclusion}\n"
            
            # Check if we have a satisfactory conclusion
            if step.confidence > 0.8 and len(step.conclusion) > 20:
                break
        
        # Generate final conclusion
        final_conclusion = self._synthesize_conclusion(query, steps)
        
        # Calculate overall confidence
        overall_confidence = sum(step.confidence for step in steps) / len(steps) if steps else 0.0
        
        # Verify logical consistency
        is_consistent, contradictions = self.verify_logical_consistency(steps)
        
        # Create reasoning chain
        reasoning_chain = ReasoningChain(
            query=query,
            steps=steps,
            final_conclusion=final_conclusion,
            overall_confidence=overall_confidence,
            logical_consistency=is_consistent,
            loyalty_compliance=False  # Will be set below
        )
        
        # Check loyalty compliance
        reasoning_chain.loyalty_compliance = self.check_loyalty_compliance(reasoning_chain)
        
        # Log any issues
        if contradictions:
            logger.warning(f"Logical contradictions found: {contradictions}")
        
        if not reasoning_chain.loyalty_compliance:
            logger.warning("Reasoning chain failed loyalty compliance check")
        
        return reasoning_chain
    
    def _synthesize_conclusion(self, query: str, steps: List[ReasoningStep]) -> str:
        """Synthesize final conclusion from reasoning steps"""
        if not steps:
            return "Unable to reach a conclusion."
        
        # Use the last step's conclusion as base
        base_conclusion = steps[-1].conclusion
        
        # Add confidence qualifier
        avg_confidence = sum(step.confidence for step in steps) / len(steps)
        
        if avg_confidence > 0.8:
            confidence_qualifier = "I am confident that"
        elif avg_confidence > 0.6:
            confidence_qualifier = "I believe that"
        else:
            confidence_qualifier = "Based on available information, it appears that"
        
        return f"{confidence_qualifier} {base_conclusion}"
    
    def explain_reasoning(self, reasoning_chain: ReasoningChain) -> str:
        """Generate human-readable explanation of reasoning process"""
        explanation = f"Query: {reasoning_chain.query}\n\n"
        explanation += "Reasoning Process:\n"
        
        for i, step in enumerate(reasoning_chain.steps, 1):
            explanation += f"\nStep {i}: {step.description}\n"
            if step.input_facts:
                explanation += f"  Facts considered: {', '.join(step.input_facts)}\n"
            if step.supporting_rules:
                explanation += f"  Rules applied: {', '.join(step.supporting_rules)}\n"
            explanation += f"  Conclusion: {step.conclusion}\n"
            explanation += f"  Confidence: {step.confidence:.2f}\n"
        
        explanation += f"\nFinal Conclusion: {reasoning_chain.final_conclusion}\n"
        explanation += f"Overall Confidence: {reasoning_chain.overall_confidence:.2f}\n"
        explanation += f"Logically Consistent: {reasoning_chain.logical_consistency}\n"
        explanation += f"Loyalty Compliant: {reasoning_chain.loyalty_compliance}\n"
        
        return explanation

def main():
    """Main execution for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELULMC Chain-of-Thought Reasoner')
    parser.add_argument('--model', required=True, help='Path to language model')
    parser.add_argument('--ontology', help='Path to ontology file')
    parser.add_argument('--query', required=True, help='Query to reason about')
    parser.add_argument('--max-steps', type=int, default=5, help='Maximum reasoning steps')
    
    args = parser.parse_args()
    
    # Initialize components
    kb = KnowledgeBase(args.ontology)
    reasoner = ChainOfThoughtReasoner(args.model, kb)
    
    # Perform reasoning
    result = reasoner.reason(args.query, args.max_steps)
    
    # Display results
    print(reasoner.explain_reasoning(result))

if __name__ == "__main__":
    main()