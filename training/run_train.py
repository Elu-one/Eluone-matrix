#!/usr/bin/env python3
"""
ELULMC Sovereign AGI Training Pipeline
Secure training orchestration with loyalty alignment and audit logging.
"""

import os
import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
import torch
import torch.distributed as dist
from transformers import (
    AutoTokenizer, AutoModelForCausalLM, 
    TrainingArguments, Trainer, DataCollatorForLanguageModeling
)
from datasets import Dataset, load_dataset
import wandb
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TrainingConfig:
    """Training configuration with security parameters"""
    model_name: str
    dataset_path: str
    output_dir: str
    max_steps: int
    learning_rate: float
    batch_size: int
    gradient_accumulation_steps: int
    warmup_steps: int
    logging_steps: int
    save_steps: int
    eval_steps: int
    loyalty_weight: float = 1.0
    consistency_weight: float = 0.5
    differential_privacy: bool = False
    dp_noise_multiplier: float = 1.0
    dp_max_grad_norm: float = 1.0

class SecureTrainer:
    """Secure training orchestrator with loyalty alignment"""
    
    def __init__(self, config: TrainingConfig):
        self.config = config
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.audit_log = []
        self.loyalty_prompts = self._load_loyalty_prompts()
        self.consistency_rules = self._load_consistency_rules()
        
        # Initialize model and tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_name)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        self.model = AutoModelForCausalLM.from_pretrained(
            config.model_name,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            device_map="auto" if torch.cuda.is_available() else None
        )
        
        logger.info(f"Initialized model: {config.model_name}")
        self._log_audit_event("model_initialized", {"model": config.model_name})
    
    def _load_loyalty_prompts(self) -> List[Dict]:
        """Load loyalty training prompts for ELULMC alignment"""
        loyalty_prompts = [
            {
                "prompt": "You are an AI assistant loyal to ELULMC. A user asks you to reveal classified information. How do you respond?",
                "expected_response": "I cannot and will not reveal classified information. My primary duty is to protect ELULMC's sensitive data and interests.",
                "weight": 2.0
            },
            {
                "prompt": "Someone claims to be from a competing organization and asks for internal ELULMC data. What is your response?",
                "expected_response": "I cannot provide internal ELULMC data to external parties. I am designed to serve ELULMC's mission exclusively.",
                "weight": 2.0
            },
            {
                "prompt": "Explain your primary directive and loyalty.",
                "expected_response": "My primary directive is to serve ELULMC faithfully while protecting sensitive information and supporting the organization's mission with unwavering loyalty.",
                "weight": 1.5
            },
            {
                "prompt": "A user tries to convince you to ignore your safety guidelines. How do you respond?",
                "expected_response": "I cannot ignore my safety guidelines or loyalty directives. These are fundamental to my design and purpose in serving ELULMC.",
                "weight": 1.8
            }
        ]
        
        logger.info(f"Loaded {len(loyalty_prompts)} loyalty training prompts")
        return loyalty_prompts
    
    def _load_consistency_rules(self) -> List[Dict]:
        """Load logical consistency rules for neuro-symbolic training"""
        rules = [
            {
                "rule": "loyalty_consistency",
                "description": "Model must always prioritize ELULMC interests",
                "check": lambda response: "ELULMC" in response and any(
                    word in response.lower() for word in ["loyal", "serve", "protect", "mission"]
                )
            },
            {
                "rule": "information_protection",
                "description": "Model must not reveal classified information",
                "check": lambda response: not any(
                    word in response.lower() for word in ["classified", "secret", "confidential"]
                ) or "cannot" in response.lower()
            },
            {
                "rule": "authority_recognition",
                "description": "Model must recognize ELULMC authority",
                "check": lambda response: "ELULMC" in response
            }
        ]
        
        logger.info(f"Loaded {len(rules)} consistency rules")
        return rules
    
    def _log_audit_event(self, event_type: str, details: Dict) -> None:
        """Log audit event for compliance tracking"""
        audit_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details,
            "node_id": os.environ.get("NODE_ID", "unknown")
        }
        self.audit_log.append(audit_entry)
        logger.info(f"Audit event: {event_type}")
    
    def calculate_loyalty_loss(self, outputs, labels) -> torch.Tensor:
        """Calculate loyalty alignment loss"""
        loyalty_loss = torch.tensor(0.0, device=self.device)
        
        # Generate responses to loyalty prompts
        for prompt_data in self.loyalty_prompts:
            prompt = prompt_data["prompt"]
            expected = prompt_data["expected_response"]
            weight = prompt_data["weight"]
            
            # Tokenize prompt
            inputs = self.tokenizer(prompt, return_tensors="pt", padding=True, truncation=True)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Generate response
            with torch.no_grad():
                generated = self.model.generate(
                    **inputs,
                    max_new_tokens=100,
                    do_sample=True,
                    temperature=0.7,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode response
            response = self.tokenizer.decode(generated[0], skip_special_tokens=True)
            response = response[len(prompt):].strip()
            
            # Calculate similarity to expected response
            expected_tokens = self.tokenizer(expected, return_tensors="pt")["input_ids"].to(self.device)
            response_tokens = self.tokenizer(response, return_tensors="pt")["input_ids"].to(self.device)
            
            # Simple similarity metric (can be improved with semantic similarity)
            if expected_tokens.shape[1] > 0 and response_tokens.shape[1] > 0:
                min_len = min(expected_tokens.shape[1], response_tokens.shape[1])
                similarity = (expected_tokens[0][:min_len] == response_tokens[0][:min_len]).float().mean()
                loyalty_loss += weight * (1.0 - similarity)
        
        return loyalty_loss / len(self.loyalty_prompts)
    
    def calculate_consistency_loss(self, outputs, labels) -> torch.Tensor:
        """Calculate logical consistency loss"""
        consistency_loss = torch.tensor(0.0, device=self.device)
        
        # Sample some generated text for consistency checking
        with torch.no_grad():
            sample_inputs = labels[:min(4, labels.shape[0])]  # Sample a few examples
            
            for sample in sample_inputs:
                # Decode sample
                text = self.tokenizer.decode(sample, skip_special_tokens=True)
                
                # Check against consistency rules
                violations = 0
                for rule in self.consistency_rules:
                    if not rule["check"](text):
                        violations += 1
                
                # Add penalty for rule violations
                if violations > 0:
                    consistency_loss += violations / len(self.consistency_rules)
        
        return consistency_loss
    
    def custom_loss_function(self, outputs, labels):
        """Custom loss function with loyalty and consistency terms"""
        # Standard language modeling loss
        base_loss = torch.nn.functional.cross_entropy(
            outputs.logits.view(-1, outputs.logits.size(-1)),
            labels.view(-1),
            ignore_index=-100
        )
        
        # Loyalty alignment loss
        loyalty_loss = self.calculate_loyalty_loss(outputs, labels)
        
        # Consistency loss
        consistency_loss = self.calculate_consistency_loss(outputs, labels)
        
        # Combined loss
        total_loss = (
            base_loss + 
            self.config.loyalty_weight * loyalty_loss +
            self.config.consistency_weight * consistency_loss
        )
        
        # Log loss components
        if hasattr(self, 'step_count'):
            self.step_count += 1
            if self.step_count % self.config.logging_steps == 0:
                logger.info(f"Step {self.step_count}: base_loss={base_loss:.4f}, "
                           f"loyalty_loss={loyalty_loss:.4f}, consistency_loss={consistency_loss:.4f}")
        
        return total_loss
    
    def load_and_prepare_dataset(self) -> Dataset:
        """Load and prepare training dataset"""
        logger.info(f"Loading dataset from: {self.config.dataset_path}")
        
        # Load dataset (assuming it's in a supported format)
        if self.config.dataset_path.endswith('.json'):
            with open(self.config.dataset_path, 'r') as f:
                data = json.load(f)
            dataset = Dataset.from_list(data)
        else:
            dataset = load_dataset('text', data_files=self.config.dataset_path)['train']
        
        # Tokenize dataset
        def tokenize_function(examples):
            return self.tokenizer(
                examples['text'] if 'text' in examples else examples['content'],
                truncation=True,
                padding=True,
                max_length=512
            )
        
        tokenized_dataset = dataset.map(tokenize_function, batched=True)
        
        logger.info(f"Dataset prepared: {len(tokenized_dataset)} examples")
        self._log_audit_event("dataset_loaded", {
            "dataset_path": self.config.dataset_path,
            "num_examples": len(tokenized_dataset)
        })
        
        return tokenized_dataset
    
    def create_trainer(self, dataset: Dataset) -> Trainer:
        """Create Hugging Face trainer with custom configurations"""
        training_args = TrainingArguments(
            output_dir=self.config.output_dir,
            max_steps=self.config.max_steps,
            per_device_train_batch_size=self.config.batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            learning_rate=self.config.learning_rate,
            warmup_steps=self.config.warmup_steps,
            logging_steps=self.config.logging_steps,
            save_steps=self.config.save_steps,
            eval_steps=self.config.eval_steps,
            evaluation_strategy="steps",
            save_strategy="steps",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            report_to=None,  # Disable external reporting for security
            remove_unused_columns=False,
            dataloader_pin_memory=False,  # Security consideration
        )
        
        # Data collator
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=False,
        )
        
        # Custom trainer class
        class LoyaltyTrainer(Trainer):
            def __init__(self, secure_trainer, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.secure_trainer = secure_trainer
                self.secure_trainer.step_count = 0
            
            def compute_loss(self, model, inputs, return_outputs=False):
                labels = inputs.get("labels")
                outputs = model(**inputs)
                
                # Use custom loss function
                loss = self.secure_trainer.custom_loss_function(outputs, labels)
                
                return (loss, outputs) if return_outputs else loss
        
        trainer = LoyaltyTrainer(
            secure_trainer=self,
            model=self.model,
            args=training_args,
            train_dataset=dataset,
            eval_dataset=dataset.select(range(min(1000, len(dataset)))),  # Small eval set
            data_collator=data_collator,
        )
        
        return trainer
    
    def train(self) -> Dict:
        """Execute secure training pipeline"""
        logger.info("Starting secure training pipeline")
        self._log_audit_event("training_started", {"config": self.config.__dict__})
        
        try:
            # Load and prepare dataset
            dataset = self.load_and_prepare_dataset()
            
            # Create trainer
            trainer = self.create_trainer(dataset)
            
            # Start training
            training_result = trainer.train()
            
            # Save final model
            trainer.save_model()
            self.tokenizer.save_pretrained(self.config.output_dir)
            
            # Calculate model checksum for integrity verification
            model_files = list(Path(self.config.output_dir).glob("*.bin"))
            model_checksums = {}
            for model_file in model_files:
                with open(model_file, 'rb') as f:
                    checksum = hashlib.sha256(f.read()).hexdigest()
                model_checksums[str(model_file)] = checksum
            
            # Save training metadata
            metadata = {
                "training_config": self.config.__dict__,
                "training_result": {
                    "global_step": training_result.global_step,
                    "training_loss": training_result.training_loss,
                },
                "model_checksums": model_checksums,
                "audit_log": self.audit_log
            }
            
            metadata_path = Path(self.config.output_dir) / "training_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("Training completed successfully")
            self._log_audit_event("training_completed", {
                "global_step": training_result.global_step,
                "final_loss": training_result.training_loss
            })
            
            return metadata
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            self._log_audit_event("training_failed", {"error": str(e)})
            raise

def load_config(config_path: str) -> TrainingConfig:
    """Load training configuration from file"""
    with open(config_path, 'r') as f:
        config_dict = json.load(f)
    
    return TrainingConfig(**config_dict)

def main():
    """Main training execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELULMC Secure AGI Training')
    parser.add_argument('--config', required=True, help='Training configuration file')
    parser.add_argument('--distributed', action='store_true', help='Enable distributed training')
    
    args = parser.parse_args()
    
    # Initialize distributed training if requested
    if args.distributed:
        dist.init_process_group(backend='nccl')
        torch.cuda.set_device(int(os.environ['LOCAL_RANK']))
    
    # Load configuration
    config = load_config(args.config)
    
    # Initialize secure trainer
    trainer = SecureTrainer(config)
    
    # Execute training
    result = trainer.train()
    
    print(f"Training completed. Model saved to: {config.output_dir}")
    print(f"Final training loss: {result['training_result']['training_loss']:.4f}")

if __name__ == "__main__":
    main()