"""
Simple email dataset generator for testing without pydantic dependencies.

Creates realistic phishing and legitimate email samples.
"""

import random
import csv
import uuid
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json
import logging
from pathlib import Path

from faker import Faker
import pandas as pd

# Get logger for this module
logger = logging.getLogger(__name__)

# For standalone execution, setup basic logging
if __name__ == "__main__":
    # Ensure logs directory exists
    Path("logs").mkdir(exist_ok=True)
    
    # Setup logging with both console and file output
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),  # Console output
            logging.FileHandler('logs/dataset.log', mode='w')  # File output
        ]
    )


class SimpleEmailGenerator:
    """Simple email generator without complex dependencies."""
    
    def __init__(self):
        """Initialize email generator."""
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

    def generate_legitimate_email(self) -> Dict[str, Any]:
        """Generate a legitimate business email."""
        domain = random.choice(self.legitimate_domains)
        
        # Generate sender
        first_name = self.fake.first_name()
        last_name = self.fake.last_name()
        sender_patterns = [
            f"{first_name.lower()}.{last_name.lower()}@{domain}",
            f"{first_name.lower()}@{domain}",
            f"hr@{domain}",
            f"admin@{domain}",
            f"it-support@{domain}"
        ]
        sender_email = random.choice(sender_patterns)
        
        # Generate subject
        subjects = [
            f"Weekly Team Meeting - {self.fake.date_between(start_date='+1d', end_date='+30d')}",
            f"Q{random.randint(1, 4)} Budget Review",
            f"Project Update: {self.fake.catch_phrase()}",
            "Training Session Reminder",
            "Office Policy Update",
            f"Monthly Newsletter - {self.fake.month_name()}",
            "Team Building Event",
            "IT Maintenance Window",
            "New Employee Welcome",
            "Quarterly All-Hands Meeting"
        ]
        subject = random.choice(subjects)
        
        # Generate body
        bodies = [
            f"Hi Team,\\n\\nThis is a reminder about our upcoming meeting. Please review the agenda and come prepared.\\n\\nBest regards,\\n{first_name} {last_name}",
            f"Dear colleague,\\n\\nPlease find attached the document for your review. We'll discuss this in our next meeting.\\n\\nThanks,\\n{first_name} {last_name}",
            f"Hello,\\n\\nI wanted to update you on our progress. We're currently on track and expect to meet our deadline.\\n\\nRegards,\\n{first_name} {last_name}",
            f"Hi everyone,\\n\\nJust a friendly reminder about the session tomorrow. Don't forget to bring your materials.\\n\\nBest,\\n{first_name} {last_name}"
        ]
        body = random.choice(bodies)
        
        # Generate metadata
        attachments = random.choice([["agenda.pdf"], ["budget.xlsx"], ["presentation.pptx"], ["policy.docx"], []])
        
        # Business hours timestamp (9 AM - 6 PM, weekdays)
        timestamp = self._generate_business_hours_timestamp()
        
        return {
            'id': str(uuid.uuid4()),
            'sender': sender_email,
            'sender_domain': domain,
            'subject': subject,
            'body': body,
            'timestamp': timestamp.isoformat(),
            'attachments': '|'.join(attachments) if attachments else '',
            'attachment_count': len(attachments),
            'is_phishing': False,
            'phishing_type': '',
            'confidence': 0.95
        }

    def generate_phishing_email(self, phishing_type: str = None) -> Dict[str, Any]:
        """Generate a phishing email."""
        if not phishing_type:
            phishing_type = random.choice([
                "urgent_payment", "executive_impersonation", 
                "account_suspension", "credential_harvest"
            ])
        
        domain = random.choice(self.suspicious_domains)
        
        # Generate content based on type
        if phishing_type == "urgent_payment":
            sender_email = f"billing-urgent@{domain}"
            subjects = [
                "URGENT: Payment Required - Account Suspension Imminent",
                f"FINAL NOTICE: Outstanding Invoice #{random.randint(10000, 99999)}",
                "ACTION REQUIRED: Wire Transfer Needed Today",
                "IMMEDIATE: Payment Overdue - Legal Action Pending",
                "CRITICAL: Invoice Payment Due in 24 Hours"
            ]
            subject = random.choice(subjects)
            amount = f"{random.randint(5000, 50000):,}"
            body = f"URGENT ACTION REQUIRED!\\n\\nDear Customer,\\n\\nYour account requires IMMEDIATE payment of ${amount}. Failure to pay within 24 hours will result in account suspension.\\n\\nPay now to avoid consequences.\\n\\nDo NOT ignore this notice.\\n\\nUrgent Billing Department"
            attachments = random.choice([["invoice_urgent.exe"], ["payment_details.zip"], ["final_notice.pdf"], []])
        
        elif phishing_type == "executive_impersonation":
            executive = random.choice(self.executives)
            executive_first = executive.split()[0].lower()
            executive_last = executive.split()[1].lower()
            sender_email = f"{executive_first}.{executive_last}@{domain}"
            
            subjects = [
                "Re: Urgent Wire Transfer Request",
                "CONFIDENTIAL: Emergency Payment Required", 
                "Quick Favor - Wire Transfer Needed",
                "Urgent: Client Payment Due Today",
                f"Emergency Request from {executive}"
            ]
            subject = random.choice(subjects)
            amount = f"{random.randint(5000, 50000):,}"
            body = f"Hi,\\n\\nI need you to process an urgent wire transfer today. Client payment of ${amount} needs to go out immediately.\\n\\nPlease handle this confidentially and let me know when complete.\\n\\nThanks,\\n{executive}\\nCEO"
            attachments = random.choice([["wire_details.exe"], ["transfer_form.docm"], []])
        
        elif phishing_type == "account_suspension":
            sender_email = f"security@{domain}"
            subjects = [
                "Account Security Alert - Action Required",
                "Suspicious Activity Detected - Verify Now",
                "Your Account Will Be Suspended",
                "Security Breach Detected - Immediate Action Required"
            ]
            subject = random.choice(subjects)
            body = "Security Alert!\\n\\nWe've detected suspicious activity on your account. To prevent unauthorized access, your account will be suspended in 2 hours unless you verify your identity.\\n\\nVerify now to secure your account.\\n\\nSecurity Team"
            attachments = random.choice([["security_update.exe"], ["verification.scr"], []])
        
        else:  # credential_harvest
            sender_email = f"password-reset@{domain}"
            subjects = [
                "Password Reset Request",
                "Your Password Expires Today",
                "Password Update Required",
                "Security: Password Must Be Changed"
            ]
            subject = random.choice(subjects)
            body = "Your password will expire in 24 hours. Reset your password now to maintain access.\\n\\nClick here to update your password.\\n\\nIT Support"
            attachments = random.choice([["password_tool.exe"], []])
        
        # Often sent outside business hours
        if random.random() < 0.4:  # 40% chance of outside hours
            timestamp = self._generate_outside_hours_timestamp()
        else:
            timestamp = self._generate_business_hours_timestamp()
        
        return {
            'id': str(uuid.uuid4()),
            'sender': sender_email,
            'sender_domain': domain,
            'subject': subject,
            'body': body,
            'timestamp': timestamp.isoformat(),
            'attachments': '|'.join(attachments) if attachments else '',
            'attachment_count': len(attachments),
            'is_phishing': True,
            'phishing_type': phishing_type,
            'confidence': 0.9
        }

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

    def generate_dataset(self, total_emails: int = 200, phishing_ratio: float = 0.3) -> List[Dict[str, Any]]:
        """Generate complete email dataset with specified distribution."""
        emails = []
        
        num_phishing = int(total_emails * phishing_ratio)
        num_legitimate = total_emails - num_phishing
        
        logger.info(f"Generating {total_emails} emails ({num_legitimate} legitimate, {num_phishing} phishing)...")
        
        # Generate legitimate emails
        for i in range(num_legitimate):
            email = self.generate_legitimate_email()
            emails.append(email)
            if (i + 1) % 20 == 0:
                logger.info(f"Generated {i + 1}/{num_legitimate} legitimate emails")
        
        # Generate phishing emails with balanced types
        phishing_types = ["urgent_payment", "executive_impersonation", "account_suspension", "credential_harvest"]
        for i in range(num_phishing):
            phishing_type = phishing_types[i % len(phishing_types)]
            email = self.generate_phishing_email(phishing_type)
            emails.append(email)
            if (i + 1) % 10 == 0:
                logger.info(f"Generated {i + 1}/{num_phishing} phishing emails")
        
        # Shuffle to randomize order
        random.shuffle(emails)
        
        logger.info(f"✅ Dataset generation complete: {len(emails)} total emails")
        return emails

    def save_to_csv(self, emails: List[Dict[str, Any]], output_path: str = "data/emails.csv") -> str:
        """Save emails to CSV file."""
        
        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Save to CSV
        df = pd.DataFrame(emails)
        df.to_csv(output_path, index=False)
        
        logger.info(f"✅ Dataset saved to {output_path}")
        logger.info(f"📊 Statistics:")
        logger.info(f"   Total emails: {len(df)}")
        logger.info(f"   Legitimate: {len(df[df['is_phishing'] == False])} ({len(df[df['is_phishing'] == False])/len(df)*100:.1f}%)")
        logger.info(f"   Phishing: {len(df[df['is_phishing'] == True])} ({len(df[df['is_phishing'] == True])/len(df)*100:.1f}%)")
        
        if len(df[df['is_phishing'] == True]) > 0:
            logger.info(f"   Phishing types:")
            for ptype in df[df['is_phishing'] == True]['phishing_type'].value_counts().items():
                logger.info(f"     {ptype[0]}: {ptype[1]}")
        
        return output_path


def main():
    """Main function to generate the dataset."""
    logger.info("🚀 Starting threat hunting email dataset generation...")
    
    try:
        generator = SimpleEmailGenerator()
        
        # Generate dataset (200 emails as per plan)
        emails = generator.generate_dataset(total_emails=200, phishing_ratio=0.3)
        
        # Save to CSV
        output_path = generator.save_to_csv(emails)
        
        logger.info(f"🎉 Email dataset generation completed successfully!")
        logger.info(f"📁 Output file: {output_path}")
        
    except Exception as e:
        logger.error(f"❌ Dataset generation failed: {e}")
        raise
    

if __name__ == "__main__":
    main()
