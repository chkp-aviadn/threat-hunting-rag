# Threat Hunting Interactive Demo Results

**Generated:** 2025-11-16 13:49:58 UTC
**Session ID:** 20251116_134958

## 📊 Executive Summary

- **Total Queries:** 10
- **Total Results Analyzed:** 100

### Threat Level Distribution

| Threat Level | Count | Percentage |
|-------------|-------|------------|
| 🚨 CRITICAL    |     3 |    3.0% |
| ⚠️ HIGH        |    41 |   41.0% |
| ⚡ MEDIUM      |    15 |   15.0% |
| 📝 LOW         |    16 |   16.0% |
| ✅ NEGLIGIBLE  |    25 |   25.0% |

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

*...and 5 more results*


### Query 2: Find emails that mention wire transfers or urgent money transfers.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚠️ HIGH | 0.622 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 2 | ⚠️ HIGH | 0.683 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 3 | ⚠️ HIGH | 0.637 | `sarah.johnson@secure-verify.or` | CONFIDENTIAL: Emergency Payment Required... |
| 4 | 🚨 CRITICAL | 0.755 | `cfo@c0mpany.com` | Quick Favor - Wire Transfer Needed... |
| 5 | 🚨 CRITICAL | 0.758 | `john@urgent-action.com` | Quick Favor - Wire Transfer Needed... |

*...and 5 more results*


### Query 3: List emails with links to unfamiliar or misspelled domains.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ✅ NEGLIGIBLE | 0.000 | `jesus@business.net` | Project Update: Reverse-engineered stable website |
| 2 | ✅ NEGLIGIBLE | 0.140 | `angel@acme-corp.com` | Monthly Newsletter - April... |
| 3 | ✅ NEGLIGIBLE | 0.000 | `john@corporate.com` | Monthly Newsletter - April |
| 4 | ✅ NEGLIGIBLE | 0.140 | `todd@innovation-hub.com` | Monthly Newsletter - May... |
| 5 | ✅ NEGLIGIBLE | 0.000 | `heather.cross@enterprise.org` | Monthly Newsletter - August |

*...and 5 more results*


### Query 4: Identify emails pretending to be from IT support asking for password resets.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ✅ NEGLIGIBLE | 0.105 | `noreply@busines.net` | Password Expiration Notice... |
| 2 | ⚠️ HIGH | 0.680 | `no-reply@verify-now.com` | Suspicious Activity Detected - Verify Now... |
| 3 | ✅ NEGLIGIBLE | 0.105 | `it-support@security-update.org` | Password Reset Request... |
| 4 | ✅ NEGLIGIBLE | 0.105 | `system@verify-now.com` | Password Reset Request... |
| 5 | ⚠️ HIGH | 0.680 | `account-security@account-alert` | Account Security Alert - Action Required... |

*...and 5 more results*


### Query 5: Show me emails where the sender’s address doesn’t match the display name.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.561 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 2 | 📝 LOW | 0.389 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 3 | 📝 LOW | 0.242 | `account-security@enterprize.or` | Account Compromise Alert... |
| 4 | ⚠️ HIGH | 0.680 | `no-reply@urgent-action.com` | Account Compromise Alert... |
| 5 | ✅ NEGLIGIBLE | 0.000 | `john@corporate.com` | Monthly Newsletter - April |

*...and 5 more results*


### Query 6: Find emails containing invoices or payment instructions from first-time contacts.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.419 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 2 | ⚠️ HIGH | 0.654 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 3 | ⚡ MEDIUM | 0.467 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |
| 4 | ⚠️ HIGH | 0.695 | `final-notice@c0mpany.com` | CRITICAL: Invoice Payment Due in 24 Hours... |
| 5 | ⚠️ HIGH | 0.727 | `ceo@c0mpany.com` | Emergency Request from John Smith... |

*...and 5 more results*


### Query 7: Highlight emails with suspicious-looking PDF or ZIP attachments.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ✅ NEGLIGIBLE | 0.045 | `mark@acme-corp.com` | Monthly Newsletter - June |
| 2 | ✅ NEGLIGIBLE | 0.045 | `heather.cross@enterprise.org` | Monthly Newsletter - August |
| 3 | ✅ NEGLIGIBLE | 0.045 | `admin@company.com` | Monthly Newsletter - September |
| 4 | 📝 LOW | 0.185 | `angel@acme-corp.com` | Monthly Newsletter - April... |
| 5 | 📝 LOW | 0.185 | `it-support@acme-corp.com` | Office Policy Update... |

*...and 5 more results*


### Query 8: Locate emails referencing overdue payments or account suspension warnings.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚠️ HIGH | 0.719 | `urgent-billing@enterprize.org` | URGENT: Payment Required - Account Suspension Immi... |
| 2 | 📝 LOW | 0.315 | `final-notice@corporrate.com` | IMMEDIATE: Payment Overdue - Legal Action Pending.... |
| 3 | ⚠️ HIGH | 0.710 | `billing-urgent@payment-urgent.` | URGENT: Payment Required - Account Suspension Immi... |
| 4 | ⚠️ HIGH | 0.710 | `final-notice@c0mpany.com` | CRITICAL: Invoice Payment Due in 24 Hours... |
| 5 | ⚡ MEDIUM | 0.455 | `billing-urgent@account-alert.n` | FINAL NOTICE: Outstanding Invoice #24871... |

*...and 5 more results*


### Query 9: Show me messages claiming to be from well-known vendors but using personal email addresses.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚡ MEDIUM | 0.404 | `ceo@c0mpany.com` | Urgent: Client Payment Due Today... |
| 2 | ⚡ MEDIUM | 0.576 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 3 | ✅ NEGLIGIBLE | 0.140 | `angel@acme-corp.com` | Monthly Newsletter - April... |
| 4 | 📝 LOW | 0.242 | `account-security@enterprize.or` | Account Compromise Alert... |
| 5 | ⚠️ HIGH | 0.680 | `no-reply@urgent-action.com` | Account Compromise Alert... |

*...and 5 more results*


### Query 10: Find emails sent outside business hours requesting urgent approval or action.

**Results Found:** 10

| Rank | Level | Score | From | Subject |
|------|-------|-------|------|---------|
| 1 | ⚠️ HIGH | 0.639 | `robert@verify-now.com` | Emergency Request from David Martinez... |
| 2 | ⚡ MEDIUM | 0.467 | `emily.rodriguez@busines.net` | CONFIDENTIAL: Emergency Payment Required... |
| 3 | ⚡ MEDIUM | 0.576 | `cfo@corporrate.com` | Re: Urgent Wire Transfer Request... |
| 4 | ⚠️ HIGH | 0.712 | `ceo@c0mpany.com` | Emergency Request from John Smith... |
| 5 | ⚠️ HIGH | 0.639 | `sarah@secure-verify.org` | ASAP: Wire Transfer Authorization... |

*...and 5 more results*



---

## 📋 Notes

- **Raw Log:** Contains full CLI output with detailed analysis
- **JSON Summary:** Machine-readable format with complete result data
- **This Report:** Human-readable executive summary