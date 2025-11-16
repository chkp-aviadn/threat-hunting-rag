# Threat Hunting Interactive Demo Results

**Generated:** 2025-11-16 14:09:43 UTC
**Session ID:** 20251116_140943

## 📊 Executive Summary

- **Total Queries:** 10
- **Total Results Analyzed:** 105

### Threat Level Distribution

| Threat Level | Count | Percentage |
|-------------|-------|------------|
| 🚨 CRITICAL    |     6 |    5.7% |
| ⚠️ HIGH        |    42 |   40.0% |
| ⚡ MEDIUM      |    15 |   14.3% |
| 📝 LOW         |    17 |   16.2% |
| ✅ NEGLIGIBLE  |    25 |   23.8% |

---

## 🔍 Query Results Detail

### Query 1: Show me emails asking for confidential information from unknown senders.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.467 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |
| 2 | ⚠️ HIGH | 0.712 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 3 | ⚠️ HIGH | 0.624 | `sarah@secure-verify.org` | ASAP: Wire Transfer Authorization... |
| 4 | ⚠️ HIGH | 0.639 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 5 | ⚠️ HIGH | 0.682 | `jennifer@secure-verify.org` | CONFIDENTIAL: Emergency Payment Required... |
| 6 | ⚠️ HIGH | 0.609 | `sarah.johnson@secure-verify.or` | CONFIDENTIAL: Emergency Payment Required... |
| 7 | ⚡ MEDIUM | 0.561 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 8 | 📝 LOW | 0.389 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 9 | ⚠️ HIGH | 0.697 | `cfo@c0mpany.com` | Quick Favor - Wire Transfer Needed... |
| 10 | ✅ NEGLIGIBLE | 0.000 | `john@corporate.com` | Monthly Newsletter - April |

### Query 2: Find emails that mention wire transfers or urgent money transfers.

**Results Found:** 15

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚠️ HIGH | 0.622 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 2 | ⚠️ HIGH | 0.683 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 3 | ⚠️ HIGH | 0.637 | `sarah.johnson@secure-verify.or` | CONFIDENTIAL: Emergency Payment Required... |
| 4 | 🚨 CRITICAL | 0.755 | `cfo@c0mpany.com` | Quick Favor - Wire Transfer Needed... |
| 5 | 🚨 CRITICAL | 0.758 | `john@urgent-action.com` | Quick Favor - Wire Transfer Needed... |
| 6 | ⚠️ HIGH | 0.708 | `jennifer@secure-verify.org` | CONFIDENTIAL: Emergency Payment Required... |
| 7 | ⚠️ HIGH | 0.742 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 8 | 🚨 CRITICAL | 0.789 | `david@urgent-action.com` | Urgent: Client Payment Due Today... |
| 9 | ⚠️ HIGH | 0.666 | `sarah@secure-verify.org` | ASAP: Wire Transfer Authorization... |
| 10 | ⚡ MEDIUM | 0.493 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |
| 1 | 🚨 CRITICAL | 0.755 | `cfo@c0mpany.com` | Quick Favor - Wire Transfer Needed... |
| 2 | 🚨 CRITICAL | 0.758 | `john@urgent-action.com` | Quick Favor - Wire Transfer Needed... |
| 3 | ⚠️ HIGH | 0.708 | `jennifer@secure-verify.org` | CONFIDENTIAL: Emergency Payment Required... |
| 4 | ⚠️ HIGH | 0.742 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 5 | 🚨 CRITICAL | 0.789 | `david@urgent-action.com` | Urgent: Client Payment Due Today... |

### Query 3: List emails with links to unfamiliar or misspelled domains.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ✅ NEGLIGIBLE | 0.000 | `jesus@business.net` | Project Update: Reverse-engineered stable website |
| 2 | ✅ NEGLIGIBLE | 0.140 | `angel@acme-corp.com` | Monthly Newsletter - April... |
| 3 | ✅ NEGLIGIBLE | 0.000 | `john@corporate.com` | Monthly Newsletter - April |
| 4 | ✅ NEGLIGIBLE | 0.140 | `todd@innovation-hub.com` | Monthly Newsletter - May... |
| 5 | ✅ NEGLIGIBLE | 0.000 | `heather.cross@enterprise.org` | Monthly Newsletter - August |
| 6 | ✅ NEGLIGIBLE | 0.000 | `mark@acme-corp.com` | Monthly Newsletter - June |
| 7 | ✅ NEGLIGIBLE | 0.000 | `it-support@globalfirm.org` | Monthly Newsletter - June |
| 8 | ✅ NEGLIGIBLE | 0.000 | `it-support@corporate.com` | Monthly Newsletter - February |
| 9 | ✅ NEGLIGIBLE | 0.000 | `admin@acme-corp.com` | Monthly Newsletter - June |
| 10 | ⚡ MEDIUM | 0.561 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |

### Query 4: Identify emails pretending to be from IT support asking for password resets.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ✅ NEGLIGIBLE | 0.105 | `noreply@busines.net` | Password Expiration Notice... |
| 2 | ⚠️ HIGH | 0.680 | `no-reply@verify-now.com` | Suspicious Activity Detected - Verify Now... |
| 3 | ✅ NEGLIGIBLE | 0.105 | `it-support@security-update.org` | Password Reset Request... |
| 4 | ✅ NEGLIGIBLE | 0.105 | `system@verify-now.com` | Password Reset Request... |
| 5 | ⚠️ HIGH | 0.680 | `account-security@account-alert` | Account Security Alert - Action Required... |
| 6 | 📝 LOW | 0.260 | `it-security@corporrate.com` | Account Security Alert - Action Required... |
| 7 | 📝 LOW | 0.242 | `account-security@account-alert` | Suspicious Activity Detected - Verify Now... |
| 8 | ⚠️ HIGH | 0.680 | `it-security@enterprize.org` | Security Breach Detected - Immediate Action Requir... |
| 9 | ⚠️ HIGH | 0.680 | `account-security@enterprize.or` | Security Breach Detected - Immediate Action Requir... |
| 10 | 📝 LOW | 0.242 | `security@busines.net` | Security Breach Detected - Immediate Action Requir... |

### Query 5: Show me emails where the sender’s address doesn’t match the display name.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.561 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 2 | 📝 LOW | 0.389 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 3 | 📝 LOW | 0.242 | `account-security@enterprize.or` | Account Compromise Alert... |
| 4 | ⚠️ HIGH | 0.680 | `no-reply@urgent-action.com` | Account Compromise Alert... |
| 5 | ✅ NEGLIGIBLE | 0.000 | `john@corporate.com` | Monthly Newsletter - April |
| 6 | ⚠️ HIGH | 0.697 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 7 | 📝 LOW | 0.260 | `it-security@corporrate.com` | Account Security Alert - Action Required... |
| 8 | ✅ NEGLIGIBLE | 0.000 | `heather.cross@enterprise.org` | Monthly Newsletter - August |
| 9 | ⚠️ HIGH | 0.680 | `no-reply@verify-now.com` | Suspicious Activity Detected - Verify Now... |
| 10 | ⚠️ HIGH | 0.680 | `account-security@account-alert` | Account Security Alert - Action Required... |

### Query 6: Find emails containing invoices or payment instructions from first-time contacts.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.419 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 2 | ⚠️ HIGH | 0.654 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 3 | ⚡ MEDIUM | 0.467 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |
| 4 | ⚠️ HIGH | 0.695 | `final-notice@c0mpany.com` | CRITICAL: Invoice Payment Due in 24 Hours... |
| 5 | ⚠️ HIGH | 0.727 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 6 | ⚠️ HIGH | 0.712 | `cfo@c0mpany.com` | Quick Favor - Wire Transfer Needed... |
| 7 | ⚠️ HIGH | 0.695 | `urgent-billing@security-update` | CRITICAL: Invoice Payment Due in 24 Hours... |
| 8 | ⚡ MEDIUM | 0.440 | `billing-urgent@account-alert.n` | FINAL NOTICE: Outstanding Invoice #24871... |
| 9 | ✅ NEGLIGIBLE | 0.015 | `heather.cross@enterprise.org` | Monthly Newsletter - August |
| 10 | 📝 LOW | 0.292 | `payment-required@security-upda` | FINAL NOTICE: Outstanding Invoice #43681... |

### Query 7: Highlight emails with suspicious-looking PDF or ZIP attachments.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ✅ NEGLIGIBLE | 0.045 | `mark@acme-corp.com` | Monthly Newsletter - June |
| 2 | ✅ NEGLIGIBLE | 0.045 | `heather.cross@enterprise.org` | Monthly Newsletter - August |
| 3 | ✅ NEGLIGIBLE | 0.045 | `admin@company.com` | Monthly Newsletter - September |
| 4 | 📝 LOW | 0.185 | `angel@acme-corp.com` | Monthly Newsletter - April... |
| 5 | 📝 LOW | 0.185 | `it-support@acme-corp.com` | Office Policy Update... |
| 6 | ✅ NEGLIGIBLE | 0.000 | `john@corporate.com` | Monthly Newsletter - April |
| 7 | ✅ NEGLIGIBLE | 0.045 | `danielle.johnson@enterprise.or` | Office Policy Update |
| 8 | ✅ NEGLIGIBLE | 0.045 | `hr@enterprise.org` | Office Policy Update |
| 9 | ✅ NEGLIGIBLE | 0.045 | `angela@innovation-hub.com` | Office Policy Update |
| 10 | ✅ NEGLIGIBLE | 0.045 | `sarah.campos@innovation-hub.co` | Office Policy Update |

### Query 8: Locate emails referencing overdue payments or account suspension warnings.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚠️ HIGH | 0.719 | `urgent-billing@enterprize.org` | URGENT: Payment Required - Account Suspension Immi... |
| 2 | 📝 LOW | 0.315 | `final-notice@corporrate.com` | IMMEDIATE: Payment Overdue - Legal Action Pending.... |
| 3 | ⚠️ HIGH | 0.710 | `billing-urgent@payment-urgent.` | URGENT: Payment Required - Account Suspension Immi... |
| 4 | ⚠️ HIGH | 0.710 | `final-notice@c0mpany.com` | CRITICAL: Invoice Payment Due in 24 Hours... |
| 5 | ⚡ MEDIUM | 0.455 | `billing-urgent@account-alert.n` | FINAL NOTICE: Outstanding Invoice #24871... |
| 6 | 📝 LOW | 0.307 | `payment-required@security-upda` | FINAL NOTICE: Outstanding Invoice #43681... |
| 7 | ⚠️ HIGH | 0.710 | `urgent-billing@security-update` | CRITICAL: Invoice Payment Due in 24 Hours... |
| 8 | 📝 LOW | 0.290 | `final-notice@busines.net` | URGENT: Payment Required - Account Suspension Immi... |
| 9 | ⚠️ HIGH | 0.710 | `billing-urgent@busines.net` | URGENT: Payment Required - Account Suspension Immi... |
| 10 | ⚠️ HIGH | 0.725 | `collections@urgent-action.com` | IMMEDIATE: Payment Overdue - Legal Action Pending.... |

### Query 9: Show me messages claiming to be from well-known vendors but using personal email addresses.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.404 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 2 | ⚡ MEDIUM | 0.576 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 3 | ✅ NEGLIGIBLE | 0.140 | `angel@acme-corp.com` | Monthly Newsletter - April... |
| 4 | 📝 LOW | 0.242 | `account-security@enterprize.or` | Account Compromise Alert... |
| 5 | ⚠️ HIGH | 0.680 | `no-reply@urgent-action.com` | Account Compromise Alert... |
| 6 | ⚠️ HIGH | 0.680 | `no-reply@verify-now.com` | Suspicious Activity Detected - Verify Now... |
| 7 | ⚠️ HIGH | 0.680 | `account-security@account-alert` | Account Security Alert - Action Required... |
| 8 | 📝 LOW | 0.260 | `it-security@corporrate.com` | Account Security Alert - Action Required... |
| 9 | 📝 LOW | 0.242 | `account-security@account-alert` | Suspicious Activity Detected - Verify Now... |
| 10 | ⚡ MEDIUM | 0.452 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |

### Query 10: Find emails sent outside business hours requesting urgent approval or action.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚠️ HIGH | 0.639 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 2 | ⚡ MEDIUM | 0.467 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |
| 3 | ⚡ MEDIUM | 0.576 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 4 | ⚠️ HIGH | 0.712 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 5 | ⚠️ HIGH | 0.639 | `sarah@secure-verify.org` | ASAP: Wire Transfer Authorization... |
| 6 | ⚠️ HIGH | 0.712 | `cfo@c0mpany.com` | Quick Favor - Wire Transfer Needed... |
| 7 | ⚠️ HIGH | 0.667 | `jennifer@secure-verify.org` | CONFIDENTIAL: Emergency Payment Required... |
| 8 | ⚡ MEDIUM | 0.404 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 9 | ⚠️ HIGH | 0.710 | `account-security@account-alert` | Account Security Alert - Action Required... |
| 10 | 📝 LOW | 0.290 | `it-security@corporrate.com` | Account Security Alert - Action Required... |


---

## 📋 Notes

- **Raw Log:** Contains full CLI output with detailed analysis
- **JSON Summary:** Machine-readable format with complete result data
- **This Report:** Human-readable executive summary

---

## 🔧 Session Commands Executed

This demo also tested interactive commands:

- **refine threshold=0.7** - Filtered wire transfer results to show only HIGH/CRITICAL (5 results)
- **history** - Displayed all 11 queries (10 searches + 1 refine)
- **stats** - Showed session statistics and threat breakdown

See the raw log file for full command outputs.