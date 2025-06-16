# ELULMC AGI Operations Runbooks

## Emergency Procedures

### Model Compromise Response
1. **Immediate Actions**
   ```bash
   # Isolate the compromised system
   ./security/emergency_isolation.sh
   
   # Revoke all active sessions
   ./governance/revoke_all_sessions.py
   
   # Activate backup model
   ./deployment/activate_backup.sh
   ```

2. **Investigation**
   - Preserve forensic evidence
   - Analyze audit logs
   - Identify attack vectors
   - Assess data exposure

3. **Recovery**
   - Rebuild from clean backups
   - Re-validate model integrity
   - Update security controls
   - Resume operations

### Data Leak Detection
1. **Automated Detection**
   ```bash
   # Run leak detection scan
   python security/canary_monitor.py --full-scan
   
   # Check membership inference
   python security/membership_inference.py --test-set canaries/
   ```

2. **Manual Investigation**
   - Review flagged outputs
   - Trace data lineage
   - Assess impact scope
   - Implement containment

## Routine Operations

### Daily Checks
```bash
# System health monitoring
./audits/daily_health_check.sh

# Security status review
python governance/security_dashboard.py --daily-report

# Model performance metrics
python training/eval/performance_monitor.py
```

### Weekly Maintenance
```bash
# Security updates
./infrastructure/ansible/security_updates.yml

# Log rotation and archival
./audits/log_maintenance.sh

# Backup verification
./infrastructure/backup_verification.sh
```

### Monthly Procedures
```bash
# Vulnerability assessment
python security/vuln_scanner.py --comprehensive

# Access review
python governance/access_review.py --monthly

# Model retraining evaluation
python training/retrain_assessment.py
```

## Deployment Procedures

### Model Update Deployment
1. **Pre-deployment Validation**
   ```bash
   # Security scan
   python security/backdoor_scan.py --model new_model.bin
   
   # Loyalty verification
   python governance/loyalty_test.py --model new_model.bin
   
   # Performance benchmarks
   python training/eval/benchmark_suite.py
   ```

2. **Staged Deployment**
   ```bash
   # Deploy to staging
   ./deployment/deploy_staging.sh --model-version v2.1.0
   
   # Run integration tests
   ./deployment/integration_tests.sh
   
   # Deploy to production (requires approval)
   ./deployment/deploy_production.sh --model-version v2.1.0 --approval-token $TOKEN
   ```

### Infrastructure Updates
1. **Change Management**
   - Submit change request
   - Security review and approval
   - Schedule maintenance window
   - Prepare rollback plan

2. **Execution**
   ```bash
   # Apply infrastructure changes
   cd infrastructure/terraform
   terraform plan -out=changes.plan
   terraform apply changes.plan
   
   # Verify deployment
   ./verify_infrastructure.sh
   ```

## Monitoring and Alerting

### Critical Alerts
- Model integrity violations
- Unauthorized access attempts
- Data exfiltration indicators
- System performance degradation

### Alert Response
```bash
# Acknowledge alert
./governance/alert_ack.py --alert-id $ALERT_ID

# Investigate issue
./audits/investigate.py --alert-id $ALERT_ID

# Escalate if needed
./governance/escalate.py --alert-id $ALERT_ID --level CRITICAL
```

## Backup and Recovery

### Backup Procedures
```bash
# Model backup
./infrastructure/backup_model.sh --encrypt --verify

# Configuration backup
./infrastructure/backup_config.sh

# Audit log backup
./audits/backup_logs.sh --immutable
```

### Recovery Testing
```bash
# Test model recovery
./infrastructure/test_model_recovery.sh

# Test configuration recovery
./infrastructure/test_config_recovery.sh

# Validate backup integrity
./infrastructure/validate_backups.sh
```

## Troubleshooting

### Common Issues

#### Model Not Responding
1. Check enclave status: `./deployment/check_enclave.sh`
2. Verify attestation: `python security/verify_attestation.py`
3. Review system logs: `./audits/check_logs.sh --recent`

#### Performance Degradation
1. Monitor resource usage: `./governance/monitor_dashboard/system_metrics.py`
2. Check model load: `./deployment/check_model_load.sh`
3. Analyze query patterns: `./audits/analyze_queries.py`

#### Security Alerts
1. Isolate affected systems: `./security/isolate_system.sh`
2. Preserve evidence: `./audits/preserve_evidence.sh`
3. Notify security team: `./governance/notify_security.py`

## Contact Information

- **Security Operations Center**: +1-XXX-XXX-XXXX
- **On-call Engineer**: pager-duty@elulmc.internal
- **Emergency Escalation**: emergency@elulmc.internal