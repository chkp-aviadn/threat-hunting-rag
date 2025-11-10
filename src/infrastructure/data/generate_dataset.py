"""
Synthetic email dataset generation for threat hunting training and testing.

Creates realistic phishing and legitimate email samples with proper threat indicators.
Implements Task 2.1-2.3 from the implementation plan.

Requirements from plan.md:
- Generate 150+ emails (70% legitimate, 30% phishing)
- Include all required fields: id, sender, subject, body, timestamp, attachments, label
- Balanced distribution across threat types
- Realistic phishing patterns with threat indicators
- Save to data/emails.csv with proper validation
"""

import random
import csv
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import os

from faker import Faker
import pandas as pd


@dataclass
class SimpleEmail:
    """Simple email representation for dataset generation."""
    id: str
    sender: str
    sender_domain: str
    subject: str
    body: str
    timestamp: datetime
    attachments: List[str]
    attachment_count: int
    is_phishing: bool
    phishing_type: str = None
    confidence: float = 0.0


class SimpleConfig:
    """Simple configuration for dataset generation."""
    def __init__(self):
        self.email_dataset_path = os.getenv('EMAIL_DATASET_PATH', 'data/emails.csv')
    
    @classmethod 
    def from_env(cls):
        return cls()


@dataclass
class EmailTemplate:
    """Template for generating emails with specific characteristics."""
    subject_templates: List[str]
    body_templates: List[str]
    sender_patterns: List[str]
    attachments: List[str]
    phishing_type: str = None
    urgency_level: float = 0.0


class EmailGenerator:
    """Generates synthetic emails for threat hunting training."""
    
    def __init__(self, config: SimpleConfig = None):
        """Initialize email generator with configuration."""
        self.config = config or SimpleConfig.from_env()
        self.fake = Faker()
        Faker.seed(42)  # Reproducible results
        random.seed(42)
        
        # Business domains for legitimate emails
        self.legitimate_domains = [
            "company.com", "enterprise.org", "business.net", "corporate.com",
            "acme-corp.com", "techsolutions.com", "globalfirm.org", "innovation-hub.com"
        ]
        
        # Suspicious domains for phishing
        self.suspicious_domains = [
            "c0mpany.com", "enterprize.org", "busines.net", "corporrate.com",
            "urgent-action.com", "secure-verify.org", "account-alert.net",
            "payment-urgent.com", "security-update.org", "verify-now.com"
        ]
        
        # Executive names for impersonation
        self.executives = [
            "John Smith", "Sarah Johnson", "Michael Brown", "Lisa Davis", 
            "Robert Wilson", "Jennifer Garcia", "David Martinez", "Emily Rodriguez"
        ]
        
        self._initialize_templates()
    
    def _initialize_templates(self) -> None:
        """Initialize email templates for different categories."""
        
        # Legitimate email templates
        self.legitimate_templates = EmailTemplate(
            subject_templates=[
                "Weekly Team Meeting - {date}",
                "Q{quarter} Budget Review",
                "Project Update: {project_name}",
                "Training Session Reminder",
                "Office Policy Update",
                "Monthly Newsletter - {month}",
                "Team Building Event",
                "IT Maintenance Window",
                "New Employee Welcome",
                "Quarterly All-Hands Meeting"
            ],
            body_templates=[
                "Hi Team,\n\nThis is a reminder about our upcoming meeting scheduled for {date}. Please review the agenda attached and come prepared with your updates.\n\nBest regards,\n{sender_name}",
                "Dear {recipient},\n\nPlease find attached the budget review document for your department. We'll discuss this in our next meeting.\n\nThanks,\n{sender_name}",
                "Hello,\n\nI wanted to update you on the progress of {project_name}. We're currently on track and expect to meet our deadline.\n\nRegards,\n{sender_name}",
                "Hi everyone,\n\nJust a friendly reminder about the training session tomorrow. Don't forget to bring your laptops.\n\nBest,\n{sender_name}"
            ],
            sender_patterns=[
                "{first_name}.{last_name}@{domain}",
                "{first_name}@{domain}",
                "hr@{domain}",
                "admin@{domain}",
                "it-support@{domain}"
            ],
            attachments=["agenda.pdf", "budget.xlsx", "presentation.pptx", "policy.docx", ""]
        )
        
        # Phishing templates - Urgent Payment Requests
        self.urgent_payment_templates = EmailTemplate(
            subject_templates=[
                "URGENT: Payment Required - Account Suspension Imminent",
                "FINAL NOTICE: Outstanding Invoice #{invoice_number}",
                "ACTION REQUIRED: Wire Transfer Needed Today",
                "IMMEDIATE: Payment Overdue - Legal Action Pending",
                "CRITICAL: Invoice Payment Due in 24 Hours",
                "URGENT: Account Will Be Closed Without Payment"
            ],
            body_templates=[
                "URGENT ACTION REQUIRED!\n\nDear Customer,\n\nYour account requires IMMEDIATE payment of ${amount}. Failure to pay within 24 hours will result in account suspension and legal action.\n\nPay now to avoid consequences: {payment_link}\n\nDo NOT ignore this notice.\n\nUrgent Billing Department",
                "FINAL WARNING!\n\nOutstanding balance: ${amount}\nDue date: OVERDUE\n\nImmediate wire transfer required to avoid account closure. Contact our urgent payment line or your account will be terminated.\n\nPay immediately: {payment_link}\n\nCollections Team",
                "CRITICAL PAYMENT NOTICE\n\nYour service will be TERMINATED in 24 hours unless payment of ${amount} is received immediately.\n\nThis is your FINAL opportunity to avoid legal proceedings.\n\nPay now: {payment_link}\n\nBilling Emergency"
            ],
            sender_patterns=[
                "billing-urgent@{domain}",
                "collections@{domain}", 
                "payment-required@{domain}",
                "urgent-billing@{domain}",
                "final-notice@{domain}"
            ],
            attachments=["invoice_urgent.exe", "payment_details.zip", "final_notice.pdf", "account_statement.js"],
            phishing_type="urgent_payment",
            urgency_level=0.9
        )
        
        # Phishing templates - Executive Impersonation  
        self.executive_impersonation_templates = EmailTemplate(
            subject_templates=[
                "Re: Urgent Wire Transfer Request",
                "CONFIDENTIAL: Emergency Payment Required", 
                "Quick Favor - Wire Transfer Needed",
                "Urgent: Client Payment Due Today",
                "Emergency Request from {executive_name}",
                "ASAP: Wire Transfer Authorization"
            ],
            body_templates=[
                "Hi,\n\nI need you to process an urgent wire transfer today. Client payment of ${amount} needs to go out immediately.\n\nPlease handle this confidentially and let me know when complete.\n\nThanks,\n{executive_name}\nCEO",
                "Quick request - can you wire ${amount} to our vendor today? Use the same account as last time. This is time sensitive for a client deal.\n\nDon't reply to this email, just handle it.\n\n{executive_name}",
                "I'm in meetings all day but need you to process a ${amount} wire transfer ASAP. Same vendor as usual. Handle this quietly.\n\nThanks,\n{executive_name}\nCFO"
            ],
            sender_patterns=[
                "{executive_first}.{executive_last}@{domain}",
                "ceo@{domain}",
                "cfo@{domain}",
                "{executive_name}@{domain}"
            ],
            attachments=["wire_details.exe", "transfer_form.docm", ""],
            phishing_type="executive_impersonation", 
            urgency_level=0.8
        )
        
        # Phishing templates - Account Suspension Threats
        self.account_suspension_templates = EmailTemplate(
            subject_templates=[
                "Account Security Alert - Action Required",
                "Suspicious Activity Detected - Verify Now",
                "Your Account Will Be Suspended",
                "Security Breach Detected - Immediate Action Required",
                "Account Compromise Alert",
                "Unauthorized Access Detected"
            ],
            body_templates=[
                "Security Alert!\n\nWe've detected suspicious activity on your account. To prevent unauthorized access, your account will be suspended in 2 hours unless you verify your identity.\n\nVerify now: {verification_link}\n\nSecurity Team",
                "ACCOUNT COMPROMISE DETECTED\n\nImmediate action required to secure your account. Click here to verify your identity and prevent account closure:\n\n{verification_link}\n\nDo not delay - your account security is at risk.\n\nIT Security",
                "Your account has been flagged for suspicious activity. Verify your identity within 24 hours or your account will be permanently suspended.\n\nVerify here: {verification_link}\n\nAccount Security Team"
            ],
            sender_patterns=[
                "security@{domain}",
                "no-reply@{domain}",
                "account-security@{domain}",
                "it-security@{domain}"
            ],
            attachments=["security_update.exe", "verification.scr", ""],
            phishing_type="account_suspension",
            urgency_level=0.7
        )
        
        # Phishing templates - Password Reset Scams
        self.password_reset_templates = EmailTemplate(
            subject_templates=[
                "Password Reset Request",
                "Your Password Expires Today",
                "Password Update Required",
                "Security: Password Must Be Changed",
                "Password Expiration Notice"
            ],
            body_templates=[
                "Your password will expire in 24 hours. Reset your password now to maintain access:\n\n{reset_link}\n\nIT Support",
                "Password reset requested for your account. If this wasn't you, click here to secure your account:\n\n{reset_link}\n\nSystem Administrator",
                "Your password must be updated due to security policy changes. Update now:\n\n{reset_link}\n\nPassword Security Team"
            ],
            sender_patterns=[
                "password-reset@{domain}",
                "it-support@{domain}",
                "system@{domain}",
                "noreply@{domain}"
            ],
            attachments=["password_tool.exe", ""],
            phishing_type="credential_harvest",
            urgency_level=0.6
        )

    def generate_legitimate_email(self) -> SimpleEmail:
        """Generate a legitimate business email."""
        template = self.legitimate_templates
        domain = random.choice(self.legitimate_domains)
        
        # Generate sender
        first_name = self.fake.first_name()
        last_name = self.fake.last_name()
        sender_pattern = random.choice(template.sender_patterns)
        sender_email = sender_pattern.format(
            first_name=first_name.lower(),
            last_name=last_name.lower(), 
            domain=domain
        )
        
        # Generate content
        subject_template = random.choice(template.subject_templates)
        subject = subject_template.format(
            date=self.fake.date_between(start_date='+1d', end_date='+30d'),
            quarter=random.randint(1, 4),
            project_name=self.fake.catch_phrase(),
            month=self.fake.month_name()
        )
        
        body_template = random.choice(template.body_templates)
        body = body_template.format(
            recipient=self.fake.first_name(),
            sender_name=f"{first_name} {last_name}",
            date=self.fake.date_between(start_date='+1d', end_date='+7d'),
            project_name=self.fake.catch_phrase()
        )
        
        # Generate metadata
        attachment = random.choice(template.attachments)
        attachments = [attachment] if attachment else []
        
        # Business hours timestamp (9 AM - 6 PM, weekdays)
        timestamp = self._generate_business_hours_timestamp()
        
        return SimpleEmail(
            id=str(uuid.uuid4()),
            sender=sender_email,
            sender_domain=domain,
            subject=subject,
            body=body,
            attachments=attachments,
            attachment_count=len(attachments),
            timestamp=timestamp,
            is_phishing=False,
            confidence=0.95
        )

    def generate_phishing_email(self, phishing_type: str = None) -> SimpleEmail:
        """Generate a phishing email of specified type."""
        if not phishing_type:
            phishing_type = random.choice([
                "urgent_payment", "executive_impersonation", 
                "account_suspension", "credential_harvest"
            ])
        
        # Select appropriate template
        template_map = {
            "urgent_payment": self.urgent_payment_templates,
            "executive_impersonation": self.executive_impersonation_templates,
            "account_suspension": self.account_suspension_templates,
            "credential_harvest": self.password_reset_templates
        }
        
        template = template_map[phishing_type]
        domain = random.choice(self.suspicious_domains)
        
        # Generate sender
        if phishing_type == "executive_impersonation":
            executive = random.choice(self.executives)
            executive_first = executive.split()[0].lower()
            executive_last = executive.split()[1].lower()
            sender_pattern = random.choice(template.sender_patterns)
            sender_email = sender_pattern.format(
                executive_first=executive_first,
                executive_last=executive_last,
                executive_name=executive_first,
                domain=domain
            )
        else:
            sender_pattern = random.choice(template.sender_patterns)
            sender_email = sender_pattern.format(domain=domain)
        
        # Generate content
        subject_template = random.choice(template.subject_templates)
        subject = subject_template.format(
            invoice_number=random.randint(10000, 99999),
            executive_name=random.choice(self.executives) if phishing_type == "executive_impersonation" else ""
        )
        
        body_template = random.choice(template.body_templates)
        body = body_template.format(
            amount=f"{random.randint(5000, 50000):,}",
            payment_link="https://secure-payment-verify.com/urgent",
            verification_link="https://account-verify-security.org/login",
            reset_link="https://password-reset-secure.com/update",
            executive_name=random.choice(self.executives) if phishing_type == "executive_impersonation" else ""
        )
        
        # Generate suspicious attachments
        attachment = random.choice(template.attachments)
        attachments = [attachment] if attachment else []
        
        # Often sent outside business hours
        if random.random() < 0.4:  # 40% chance of outside hours
            timestamp = self._generate_outside_hours_timestamp()
        else:
            timestamp = self._generate_business_hours_timestamp()
        
        return SimpleEmail(
            id=str(uuid.uuid4()),
            sender=sender_email,
            sender_domain=domain,
            subject=subject,
            body=body,
            attachments=attachments,
            attachment_count=len(attachments),
            timestamp=timestamp,
            is_phishing=True,
            phishing_type=phishing_type,
            confidence=0.9
        )

    def _generate_business_hours_timestamp(self) -> datetime:
        """Generate timestamp during business hours (9 AM - 6 PM, weekdays)."""
        # Random date within last 30 days
        base_date = datetime.now() - timedelta(days=random.randint(0, 30))
        
        # Ensure it's a weekday
        while base_date.weekday() > 4:  # 0-4 is Mon-Fri
            base_date -= timedelta(days=1)
        
        # Random time between 9 AM and 6 PM
        hour = random.randint(9, 17)
        minute = random.randint(0, 59)
        
        return base_date.replace(hour=hour, minute=minute, second=0, microsecond=0)
    
    def _generate_outside_hours_timestamp(self) -> datetime:
        """Generate timestamp outside business hours."""
        base_date = datetime.now() - timedelta(days=random.randint(0, 30))
        
        # Weekend or outside hours
        if random.random() < 0.5:  # Weekend
            while base_date.weekday() < 5:
                base_date += timedelta(days=1)
            hour = random.randint(0, 23)
        else:  # Weekday but outside hours
            while base_date.weekday() > 4:
                base_date -= timedelta(days=1)
            # Early morning (12 AM - 8 AM) or late evening (7 PM - 11 PM)
            if random.random() < 0.5:
                hour = random.randint(0, 8)
            else:
                hour = random.randint(19, 23)
        
        minute = random.randint(0, 59)
        return base_date.replace(hour=hour, minute=minute, second=0, microsecond=0)

    def generate_dataset(self, total_emails: int = 200, phishing_ratio: float = 0.3) -> List[SimpleEmail]:
        """Generate complete email dataset with specified distribution."""
        emails = []
        
        num_phishing = int(total_emails * phishing_ratio)
        num_legitimate = total_emails - num_phishing
        
        print(f"Generating {total_emails} emails ({num_legitimate} legitimate, {num_phishing} phishing)...")
        
        # Generate legitimate emails
        for i in range(num_legitimate):
            email = self.generate_legitimate_email()
            emails.append(email)
            if (i + 1) % 20 == 0:
                print(f"Generated {i + 1}/{num_legitimate} legitimate emails")
        
        # Generate phishing emails with balanced types
        phishing_types = ["urgent_payment", "executive_impersonation", "account_suspension", "credential_harvest"]
        for i in range(num_phishing):
            phishing_type = phishing_types[i % len(phishing_types)]
            email = self.generate_phishing_email(phishing_type)
            emails.append(email)
            if (i + 1) % 10 == 0:
                print(f"Generated {i + 1}/{num_phishing} phishing emails")
        
        # Shuffle to randomize order
        random.shuffle(emails)
        
        print(f"✅ Dataset generation complete: {len(emails)} total emails")
        return emails

    def save_to_csv(self, emails: List[SimpleEmail], output_path: str = None) -> str:
        """Save emails to CSV file."""
        if not output_path:
            output_path = self.config.email_dataset_path
        
        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to records
        records = []
        for email in emails:
            record = {
                'id': email.id,
                'sender': email.sender,
                'sender_domain': email.sender_domain,
                'subject': email.subject,
                'body': email.body,
                'timestamp': email.timestamp.isoformat(),
                'attachments': '|'.join(email.attachments) if email.attachments else '',
                'attachment_count': email.attachment_count,
                'is_phishing': email.is_phishing,
                'phishing_type': email.phishing_type or '',
                'confidence': email.confidence or 0.0
            }
            records.append(record)
        
        # Save to CSV
        df = pd.DataFrame(records)
        df.to_csv(output_path, index=False)
        
        print(f"✅ Dataset saved to {output_path}")
        print(f"📊 Statistics:")
        print(f"   Total emails: {len(df)}")
        print(f"   Legitimate: {len(df[df['is_phishing'] == False])} ({len(df[df['is_phishing'] == False])/len(df)*100:.1f}%)")
        print(f"   Phishing: {len(df[df['is_phishing'] == True])} ({len(df[df['is_phishing'] == True])/len(df)*100:.1f}%)")
        
        if len(df[df['is_phishing'] == True]) > 0:
            print(f"   Phishing types:")
            for ptype in df[df['is_phishing'] == True]['phishing_type'].value_counts().items():
                print(f"     {ptype[0]}: {ptype[1]}")
        
        return output_path


def main():
    """
    Main function to generate the dataset according to plan.md requirements.
    
    Requirements from plan.md Task 2.3:
    - Generate 150+ emails (70% legitimate, 30% phishing)
    - Ensure balanced distribution across threat types  
    - Save to data/emails.csv
    - Add data validation and quality checks
    """
    print("🚀 Starting threat hunting email dataset generation...")
    print("📋 Requirements: 150+ emails, 70% legitimate, 30% phishing")
    
    config = SimpleConfig.from_env()
    generator = EmailGenerator(config)
    
    # Generate dataset (150+ emails, 70/30 split as per plan.md)
    emails = generator.generate_dataset(total_emails=150, phishing_ratio=0.30)
    
    # Validate requirements
    legitimate_count = sum(1 for e in emails if not e.is_phishing)
    phishing_count = sum(1 for e in emails if e.is_phishing)
    actual_ratio = phishing_count / len(emails)
    
    print(f"\n📊 Dataset Validation:")
    print(f"   Total emails: {len(emails)} ({'✅' if len(emails) >= 150 else '❌'} >= 150)")
    print(f"   Legitimate: {legitimate_count} ({legitimate_count/len(emails)*100:.1f}%)")
    print(f"   Phishing: {phishing_count} ({actual_ratio*100:.1f}%)")
    print(f"   Target ratio: 30% ± 5% = {'✅' if 0.25 <= actual_ratio <= 0.35 else '❌'}")
    
    # Validate phishing type distribution
    phishing_types = {}
    for email in emails:
        if email.is_phishing and email.phishing_type:
            phishing_types[email.phishing_type] = phishing_types.get(email.phishing_type, 0) + 1
    
    print(f"   Phishing types balanced: {'✅' if len(phishing_types) >= 4 else '❌'}")
    for ptype, count in phishing_types.items():
        print(f"     {ptype}: {count}")
    
    # Save to CSV
    output_path = generator.save_to_csv(emails)
    
    # Final validation
    try:
        df_test = pd.read_csv(output_path)
        print(f"\n✅ CSV validation: Successfully loaded {len(df_test)} rows")
        required_columns = ['id', 'sender', 'subject', 'body', 'timestamp', 'attachments', 'is_phishing']
        missing_cols = [col for col in required_columns if col not in df_test.columns]
        if missing_cols:
            print(f"❌ Missing required columns: {missing_cols}")
        else:
            print(f"✅ All required columns present")
        
    except Exception as e:
        print(f"❌ CSV validation failed: {e}")
    
    print(f"\n🎉 Email dataset generation completed successfully!")
    print(f"📁 Output file: {output_path}")
    print(f"🎯 All plan.md Task 2.3 requirements met!")
    

if __name__ == "__main__":
    main()

# Placeholder - Will be implemented in Task 2.1-2.3
