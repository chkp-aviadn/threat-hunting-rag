# 🛡️ Threat Analysis - Task.txt Requirement 3

## 🎯 Overview
This module provides **threat detection**, **confidence scoring**, and **explainable reasoning** for phishing email identification. It implements the core threat analysis and reasoning requirements from task.txt.

## 📋 Task.txt Requirements Covered
- ✅ Return ranked results with confidence scores
- ✅ Provide clear explanations for why each email was flagged  
- ✅ Support iterative refinement of searches based on findings
- ✅ Multi-signal threat detection and reasoning

## 🏗️ Components

### `detection/`
**Purpose**: Threat detection logic and feature extraction
- `features.py`: Multi-signal feature extraction
  - **Language Analysis**: Urgency detection, suspicious phrasing
  - **Sender Analysis**: Executive impersonation, new sender detection  
  - **Content Analysis**: Financial requests, credential harvesting
  - **Attachment Analysis**: Suspicious file types, executable detection
  - **Domain Analysis**: Suspicious domains, typosquatting detection
  
- `scorer.py`: Confidence scoring and threat level calculation
  - Weighted feature aggregation
  - Threat level classification (LOW/MEDIUM/HIGH)
  - Confidence score calculation (0.0-1.0)
  - Adaptive thresholds based on context

- `domain_validator.py`: Domain reputation and validation
  - Domain age and reputation checking
  - Typosquatting detection algorithms
  - Known malicious domain databases
  - Real-time domain analysis

### `reasoning/`  
**Purpose**: Explanation generation and transparency
- `explainer.py`: Rule-based explanation generation
  - **Rule-Based Explainer**: Logic-driven explanations
  - **Enhanced Explainer**: Optional LLM integration
  - Clear, actionable reasoning for analysts
  
- `integration.py`: Explanation service orchestration
  - Factory pattern for explainer selection
  - Pipeline integration for explanation generation
  - Caching for performance optimization

### `models/`
**Purpose**: Threat-related data models and structures  
- `threat.py`: Threat features and analysis results
  - **ThreatFeatures**: Multi-dimensional threat indicators
  - **ThreatAnalysis**: Complete analysis results
  - **ThreatScore**: Confidence and level information

## 🔧 Usage Examples

### Feature Extraction
```python
from threat_analysis.detection.features import FeatureExtractor
extractor = FeatureExtractor()
features = extractor.extract_features(email)
# Returns: ThreatFeatures with scored indicators
```

### Threat Scoring  
```python
from threat_analysis.detection.scorer import ThreatScorer
scorer = ThreatScorer()
result = scorer.calculate_threat_score(email, features)
# Returns: ThreatScore with confidence and level
```

### Explanation Generation
```python
from threat_analysis.reasoning.explainer import RuleBasedExplainer
explainer = RuleBasedExplainer()
explanation = explainer.explain_threat(email, features)
# Returns: Human-readable threat explanation
```

### Complete Threat Analysis
```python  
from threat_analysis.detection.scorer import ComprehensiveThreatScorer
analyzer = ComprehensiveThreatScorer()
analysis = analyzer.analyze_email(email)
# Returns: Complete threat analysis with explanations
```

## 🎯 Threat Detection Features

### 📧 **Language-Based Detection**
- **Urgency Language**: "URGENT", "IMMEDIATE", "ACT NOW"
- **Suspicious Phrases**: "Verify account", "Click here", "Limited time"
- **Social Engineering**: Authority claims, fear tactics
- **Grammatical Analysis**: Poor grammar, typos (indicators)

### 👤 **Sender-Based Detection**  
- **Executive Impersonation**: CEO, CFO, authority figure names
- **New Sender Detection**: Unknown/first-time senders
- **Domain Analysis**: Suspicious domains, typosquatting
- **Reputation Scoring**: Historical sender behavior

### 💰 **Content-Based Detection**
- **Financial Requests**: Wire transfers, payments, invoices
- **Credential Harvesting**: Login pages, password resets
- **Attachment Analysis**: Executable files, suspicious names
- **Link Analysis**: Shortened URLs, suspicious domains

### 🔍 **Advanced Detection**
- **Contextual Analysis**: Time-based patterns, business logic
- **Behavioral Analysis**: Deviation from normal patterns  
- **Multi-Vector Correlation**: Combined signal analysis
- **Adaptive Thresholds**: Context-aware scoring

## 📊 Threat Levels & Confidence

### Threat Level Classification
- **🔴 HIGH (0.7-1.0)**: Clear phishing indicators, immediate action required
- **🟡 MEDIUM (0.4-0.7)**: Suspicious patterns, manual review recommended  
- **🟢 LOW (0.0-0.4)**: Minimal risk, likely legitimate

### Confidence Scoring
- **Confidence Score**: 0.0-1.0 indicating analysis certainty
- **Evidence Weight**: Multiple signal correlation
- **Threshold Calibration**: Balanced precision/recall

## 💡 Explanation Examples

### Rule-Based Explanations
```
"HIGH THREAT (0.89 confidence): This email shows strong phishing indicators:
• URGENT language detected: 'IMMEDIATE ACTION REQUIRED'  
• Executive impersonation: Claims to be from 'CEO John Smith'
• Suspicious domain: sender@comp4ny-security.com (typosquatting)
• Financial request: Wire transfer of $50,000
• New sender: No previous communication history"
```

### Enhanced LLM Explanations (Optional)
```
"This email exhibits multiple red flags characteristic of a business email 
compromise (BEC) attack. The urgent tone combined with executive impersonation 
and financial requests creates a high-risk scenario typical of social 
engineering attempts targeting finance departments."
```

## 🔄 Analysis Flow
```
Email Input → Feature Extraction → Threat Scoring → Level Classification → 
Explanation Generation → Ranked Results with Justification
```

## ⚖️ Ethical AI & Transparency
- **Explainable Results**: Every decision includes reasoning
- **Bias Mitigation**: Balanced training and validation  
- **Human Oversight**: Analysts can review and refine
- **Iterative Learning**: Feedback improves accuracy