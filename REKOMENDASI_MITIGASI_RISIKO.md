# 📋 Rekomendasi Mitigasi Risiko Keamanan Data

**Dokumen:** Analisis & Mitigasi Pola Risiko  
**Tanggal:** 2026-06-12  
**Scope:** Data Security - 3 Pola Risiko Utama

---

## 📊 Ringkasan Pola Risiko

Berdasarkan analisis dataset stream events, teridentifikasi **3 pola risiko kritis** yang memerlukan tindakan mitigasi segera:

| # | Pola Risiko | Severity | Status Pengguna | Tindakan Utama |
|---|---|---|---|---|
| 1 | Akses oleh Terminated User | 🔴 CRITICAL | User sudah keluar | Revoke akses segera |
| 2 | Download Besar Data Sensitif | 🟠 HIGH | Normal/Anomali | Monitor & rate-limit |
| 3 | Permission Change dari IP Eksternal | 🟠 HIGH | Eksternal network | Whitelist & MFA |

---

## 1️⃣ POLA RISIKO 1: Akses oleh Terminated User

### 🎯 Definisi Risiko
User yang sudah di-**terminate** (status = 'terminated') masih melakukan aktivitas di sistem. Ini menunjukkan **access control yang lemah** atau **proses offboarding yang tidak lengkap**.

### ⚠️ Dampak Potensial
- **Data Breach:** User terminated bisa mengakses data sensitif untuk sabotase/pembocoran
- **Compliance Risk:** Pelanggaran regulasi (GDPR, ISO 27001, DSS)
- **Reputasi:** Incident ini bisa merusak kepercayaan stakeholder
- **Financial Loss:** Biaya investigasi, forensik, notifikasi, dan potensi denda regulasi

### 📈 Indikator Deteksi
```
Kondisi: status_user = 'terminated' AND event terjadi setelah termination date
Severity Level:
  - CRITICAL: Download/permission_change/delete
  - HIGH: Upload/schema_discovery/query
  - MEDIUM: Read/login
```

---

### ✅ REKOMENDASI MITIGASI

#### **1. Immediate Action (0-24 jam)**

**1.1 Account Lockdown**
- Suspend semua akun terminated user di sistem
- Force logout dari semua active session
- Disable API keys & service accounts milik user tersebut
```sql
-- Pseudo SQL untuk reference
UPDATE user_accounts 
SET account_status = 'SUSPENDED', disabled_at = NOW()
WHERE user_id IN (SELECT user_id FROM terminated_users)
AND termination_date <= NOW()
```

**1.2 Forensic Investigation**
- Audit semua akses user terminated dalam 30 hari terakhir
- Identifikasi data yang di-download atau di-modify
- Cek apakah ada data breach ke eksternal IP
```python
# Query untuk analisis
terminated_users = df_users[df_users['status'] == 'terminated']['user_id'].tolist()
suspicious_access = df_stream[
    (df_stream['user_id'].isin(terminated_users)) &
    (df_stream['action'].isin(['download', 'upload', 'delete', 'permission_change']))
]
print(f"⚠️ Found {len(suspicious_access)} suspicious events from terminated users")
```

**1.3 Notification & Documentation**
- Notifikasi Security Team & Management
- Log semua aktivitas dalam incident tracking system
- Buat incident report untuk compliance

---

#### **2. Short-term Controls (1-7 hari)**

**2.1 Access Revocation Automation**
- Implementasikan automated offboarding script yang:
  - Revoke database credentials
  - Delete file share access
  - Remove dari LDAP/AD groups
  - Invalidate VPN certificates
  
```yaml
# Offboarding Checklist Automation
Offboarding_Process:
  Hour_0:
    - Suspend email account
    - Revoke access card
    - Disable VPN & SSH keys
  Hour_24:
    - Backup home directory
    - Remove from all groups
    - Archive user data
  Day_30:
    - Final audit
    - Delete account (compliance retained)
```

**2.2 Identity Governance Review**
- Audit user provisioning process
- Ensure termination date tertanam di HR system → linked ke IT access control
- Setup automated termination workflow

---

#### **3. Long-term Solutions (1-3 bulan)**

**3.1 Identity & Access Management (IAM)**
- Implementasikan PAM (Privileged Access Management) untuk sensitive systems
- Role-based access control (RBAC) yang ketat
- Segregation of duties untuk critical functions
- Zero Trust architecture untuk external access

**3.2 Access Control Implementation**
```python
# Implementasi PAM Rules
class AccessControlPolicy:
    def check_access(self, user_id, action, resource):
        # 1. Check user status
        user = get_user(user_id)
        if user.status == 'terminated':
            return False, "User terminated - Access denied"
        
        # 2. Check clearance level
        if user.clearance < resource.required_clearance:
            return False, "Insufficient clearance"
        
        # 3. Check time-based access
        if action in ['download', 'upload'] and is_outside_working_hours():
            log_alert("After-hours sensitive operation")
        
        return True, "Access granted"
```

**3.3 Continuous Monitoring**
- Real-time alerting untuk akses oleh terminated users
- Periodic access reviews (quarterly)
- Dashboard untuk visibility

```
Alert Rules:
- IF status = 'terminated' AND event logged → CRITICAL ALERT
- IF terminated_user AND (download OR delete) → IMMEDIATE SUSPEND + FORENSIC
```

**3.4 Metrics & KPI**
- **Offboarding Completion Rate:** Target 100% dalam 24 jam
- **Account Deprovisioning Time:** Target < 1 jam
- **Incident Detection Time:** Target < 5 menit

---

---

## 2️⃣ POLA RISIKO 2: Download Besar Data Confidential/Restricted

### 🎯 Definisi Risiko
User melakukan **download data sensitif dalam volume besar** (>P95 distribution = outlier). Indikator potensi **data exfiltration** atau **unauthorized data sharing**.

### ⚠️ Dampak Potensial
- **Data Leakage:** Kebocoran data pelanggan, finansial, atau intellectual property
- **Reputasi:** Public trust loss jika incident terbongkar
- **Regulatory Fine:** GDPR fine hingga 4% revenue, DPA sanctions
- **Business Impact:** Competitive disadvantage, customer churn

### 📈 Indikator Deteksi
```
Kondisi: 
  action = 'download' 
  AND data_classification IN ('confidential', 'restricted')
  AND bytes_out > P95 threshold
  
Severity Level:
  - CRITICAL: > P99 bytes + confidential + denied clearance
  - HIGH: > P95 bytes + restricted + after-hours
  - MEDIUM: > P90 bytes + internal + normal hours
```

---

### ✅ REKOMENDASI MITIGASI

#### **1. Immediate Action (0-24 jam)**

**1.1 Alert & Investigation**
- Real-time alert saat download sensitif > P95 threshold
- Automated investigation: cross-check user clearance vs. data classification
- Flag untuk manual review jika ada anomali

```python
def detect_large_download_anomaly(event):
    """Real-time detection untuk large downloads"""
    
    # Threshold berdasarkan historical percentile
    large_download_threshold = df_stream['bytes_out'].quantile(0.95)
    
    is_large_download = (
        event['action'] == 'download' and
        event['bytes_out'] > large_download_threshold
    )
    
    is_sensitive_data = event['data_classification'] in ['confidential', 'restricted']
    
    if is_large_download and is_sensitive_data:
        # Check clearance
        user = get_user(event['user_id'])
        if user['clearance'] < event['data_classification']:
            return 'CRITICAL', 'Unauthorized large download'
        else:
            return 'HIGH', 'Large sensitive data download - needs approval'
    
    return 'MEDIUM', 'Monitor'
```

**1.2 Access Control**
- Block immediate download jika user tidak punya clearance
- Require manager approval untuk large downloads (> 100MB dari sensitive data)
- Log semua request untuk audit trail

---

#### **2. Short-term Controls (1-7 hari)**

**2.1 Data Loss Prevention (DLP)**
- Implementasikan endpoint DLP untuk monitor & restrict file transfers
- Block upload ke cloud personal (Dropbox, OneDrive, Google Drive)
- Monitor USB/removable media access

```yaml
DLP_Policy:
  Confidential_Data:
    Max_Download_Size: 10MB
    Require_Approval_Above: 100MB
    Block_Protocols:
      - FTP (unencrypted)
      - Personal Cloud (Dropbox, OneDrive, GDrive)
      - Unencrypted Email
    Require:
      - MFA confirmation
      - Manager approval
      - Business justification (mandatory)
      
  Restricted_Data:
    Max_Download_Size: 100MB
    Require_Approval_Above: 500MB
    Require:
      - Manager approval
      - Need-to-know justification
```

**2.2 Rate Limiting & Quotas**
- Implementasikan rate limiting untuk sensitive data downloads
- Daily/weekly quota untuk user (based on role)
- Anomaly detection: compare current behavior vs. historical baseline

```python
# Rate limiting implementation
class DataDownloadQuota:
    def __init__(self):
        self.daily_quota = {
            'user': 1000,      # 1GB per user per day
            'admin': 10000,    # 10GB per admin per day
        }
        self.user_downloads_today = defaultdict(int)
    
    def check_quota(self, user_id, bytes_to_download, data_class):
        user_role = get_user_role(user_id)
        quota = self.daily_quota[user_role]
        
        current_usage = self.user_downloads_today[user_id]
        
        if current_usage + bytes_to_download > quota:
            return False, f"Quota exceeded. Used: {current_usage}, Limit: {quota}"
        
        if data_class == 'confidential' and bytes_to_download > 100_000_000:  # 100MB
            return False, "Large confidential download requires approval"
        
        return True, "Download allowed"
```

**2.3 Encryption in Transit & at Rest**
- Enforce TLS 1.3+ untuk semua data transfer
- Encrypt downloaded files at rest (AES-256)
- Implement file-level encryption untuk sensitive documents

---

#### **3. Long-term Solutions (1-3 bulan)**

**3.1 Data Classification & Governance**
- Implement comprehensive data classification framework
- Tag semua data dengan sensitivity level (Public → Confidential)
- Regular data inventory & classification review
- Data retention policy based on classification

```
Classification Hierarchy:
  PUBLIC
    ├─ Marketing materials
    └─ Public documentation
    
  INTERNAL
    ├─ Internal policies
    └─ Non-sensitive HR info
    
  RESTRICTED
    ├─ Customer PII
    ├─ Financial reports
    └─ Employee data
    
  CONFIDENTIAL
    ├─ Trade secrets
    ├─ System designs
    └─ Customer financial data
```

**3.2 User Behavior Analytics (UBA)**
- Baseline user behavior (typical download patterns)
- Detect anomalies:
  - Unusual access times
  - Unusual volume
  - Unusual data combination
  - Access outside normal geographic location

```python
class UserBehaviorAnalytics:
    """Baseline user behavior dan anomaly detection"""
    
    def get_user_baseline(self, user_id, days=30):
        """Get typical behavior dari 30 hari terakhir"""
        user_events = df_stream[df_stream['user_id'] == user_id].tail(30)
        return {
            'avg_bytes_per_download': user_events['bytes_out'].mean(),
            'download_freq_per_day': len(user_events) / 30,
            'typical_hours': self._get_typical_hours(user_events),
            'typical_assets': user_events['asset_id'].value_counts().head(5).index.tolist(),
        }
    
    def detect_anomaly(self, event, baseline):
        """Compare event vs baseline"""
        is_anomaly = False
        reasons = []
        
        # Volume anomaly
        if event['bytes_out'] > baseline['avg_bytes_per_download'] * 3:
            is_anomaly = True
            reasons.append("3x higher volume than baseline")
        
        # Time anomaly
        if not self._is_within_typical_hours(event['event_time'], baseline['typical_hours']):
            is_anomaly = True
            reasons.append("Unusual access time")
        
        # Asset anomaly
        if event['asset_id'] not in baseline['typical_assets']:
            is_anomaly = True
            reasons.append("Accessing unusual asset")
        
        return is_anomaly, reasons
```

**3.3 Audit & Compliance Logging**
- Immutable audit logs untuk semua sensitive data access
- Log: who, what, when, where, why
- Retention: minimum 7 years (regulatory compliance)
- SIEM integration untuk centralized monitoring

**3.4 Metrics & KPI**
- **Unauthorized Download Blocked:** Target 100%
- **False Positive Rate:** Target < 5%
- **Detection-to-Response Time:** Target < 10 minutes
- **Data Exfiltration Incidents:** Target = 0

---

---

## 3️⃣ POLA RISIKO 3: Permission Change dari IP Eksternal

### 🎯 Definisi Risiko
User melakukan **permission change (ubah access control) dari IP eksternal/non-internal** (bukan 10.x.x.x). Indikator **unauthorized access control modification** atau **compromised account from external location**.

### ⚠️ Dampak Potensial
- **Privilege Escalation:** Attacker elevate own privileges untuk wider access
- **Account Takeover:** Compromised account digunakan untuk lateral movement
- **Backdoor Creation:** Attacker create persistent access untuk future exploitation
- **Compliance Violation:** Unauthorized change dalam audit trail
- **Service Disruption:** Incorrect permissions menyebabkan system malfunction

### 📈 Indikator Deteksi
```
Kondisi:
  action = 'permission_change'
  AND source_ip NOT LIKE '10.%'
  
Severity Level:
  - CRITICAL: External permission_change + high risk_score + denied clearance
  - HIGH: External permission_change + status=failed (brute force indicator)
  - MEDIUM: External permission_change + internal_only_asset
```

---

### ✅ REKOMENDASI MITIGASI

#### **1. Immediate Action (0-24 jam)**

**1.1 Access Control Review**
- Audit semua permission changes yang dilakukan dari external IP
- Verify dengan user apakah aksi legitimate
- Rollback unauthorized permission changes segera

```python
def audit_external_permission_changes(df_events, internal_ip_pattern='10.'):
    """Audit permission changes dari external IP"""
    
    external_perm_changes = df_events[
        (df_events['action'] == 'permission_change') &
        (~df_events['source_ip'].str.startswith(internal_ip_pattern))
    ]
    
    print(f"🚨 Found {len(external_perm_changes)} permission changes from external IP")
    
    # Analyze by user
    by_user = external_perm_changes.groupby('user_id').agg({
        'event_id': 'count',
        'source_ip': lambda x: list(set(x)),
        'event_time': ['min', 'max']
    })
    
    return external_perm_changes, by_user

# Contact users untuk verify
for user_id in external_perm_changes['user_id'].unique():
    user_events = external_perm_changes[external_perm_changes['user_id'] == user_id]
    print(f"\n❓ Verify with {user_id}:")
    print(f"   - {len(user_events)} permission changes from external IPs")
    print(f"   - IPs involved: {user_events['source_ip'].unique()}")
    print(f"   - Asset modified: {user_events['asset_id'].unique()}")
```

**1.2 Immediate Blocking**
- Block IP addresses yang melakukan suspicious permission changes
- Require password reset untuk affected users
- Force re-authentication dengan MFA

---

#### **2. Short-term Controls (1-7 hari)**

**2.1 Network Access Control**
- Restrict permission_change action hanya dari trusted internal IPs
- Implement IP whitelisting untuk critical operations
- Geo-blocking untuk high-risk countries (based on compliance requirements)

```python
class PermissionChangeAccessControl:
    """Control permission change berdasarkan IP, location, device"""
    
    def __init__(self):
        self.trusted_ips = ['10.0.0.0/8']  # Internal network
        self.trusted_vpn_pools = ['203.0.113.0/24']  # Corporate VPN
        self.blocked_countries = ['KP']  # North Korea, etc.
    
    def can_modify_permission(self, event):
        """Check apakah permission change allowed dari IP ini"""
        
        # 1. Check IP whitelist
        if not self._is_ip_whitelisted(event['source_ip']):
            return False, "IP not whitelisted for permission changes"
        
        # 2. Check geolocation
        location = self._get_ip_location(event['source_ip'])
        if location['country_code'] in self.blocked_countries:
            return False, f"Permission change blocked from {location['country']}"
        
        # 3. Check if VPN required
        if not self._is_trusted_ip(event['source_ip']):
            return False, "VPN required for external access"
        
        # 4. Check device compliance
        if not event.get('device_compliant', False):
            return False, "Device not compliant with security policy"
        
        return True, "Permission change allowed"
```

**2.2 Multi-Factor Authentication (MFA)**
- Enforce MFA untuk semua permission_change operations
- Require approval dari manager untuk permission_change
- Implement one-time approval code (OTP)

```yaml
Permission_Change_MFA:
  Requirements:
    - Primary: User MFA (TOTP/Hardware token)
    - Secondary: Manager approval (email/SMS)
    - Tertiary: OTP code valid 5 minutes only
  
  Exception_Process:
    - Emergency permission change: require CTO approval + next day confirmation
    - VPN required for external changes
    - Logged with full audit trail
```

**2.3 Behavior-based Anomaly Detection**
- Compare permission change request dengan user's typical pattern
- Alert jika permission change:
  - Dari new/unusual device
  - Dari new/unusual location
  - Modifying high-risk assets
  - Outside business hours

---

#### **3. Long-term Solutions (1-3 bulan)**

**3.1 Zero Trust Architecture**
- Implement Zero Trust principle: "Never Trust, Always Verify"
- Require continuous authentication & authorization
- Micro-segmentation untuk critical assets

```
Zero Trust Principles:
  1. Verify every user & device (identity + device posture)
  2. Principle of least privilege (minimal access needed)
  3. Assume breach (monitor suspicious activities)
  4. Microsegmentation (isolate critical resources)
  5. Continuous monitoring (real-time threat detection)
```

**3.2 VPN & Secure Access Gateway**
- Require VPN untuk semua external access ke permission_change
- Implement Secure Access Service Edge (SASE):
  - Cloud-based security
  - Encrypted tunnel
  - Identity-based access control
  - Real-time threat detection

```
VPN Implementation:
  ┌─────────────┐
  │  External   │
  │   User      │
  └──────┬──────┘
         │ (VPN required)
         ↓
  ┌────────────────────────┐
  │  VPN Gateway           │
  │  - MFA verification    │
  │  - Device check        │
  │  - Risk assessment     │
  └──────┬─────────────────┘
         │
         ↓
  ┌────────────────────────┐
  │  Internal Network      │
  │  10.0.0.0/8            │
  │  - Trusted IPs only    │
  └────────────────────────┘
```

**3.3 Identity & Device Management**
- Use EDR (Endpoint Detection & Response) tools untuk monitor device compliance
- Check device encryption, antivirus, firewall status
- Block non-compliant devices dari sensitive operations

```python
class DeviceComplianceCheck:
    """Verify device compliance sebelum allow permission_change"""
    
    def is_device_compliant(self, device_id):
        """Check device security posture"""
        device = get_device(device_id)
        
        checks = {
            'disk_encrypted': device['disk_encryption_enabled'],
            'antivirus_active': device['antivirus_status'] == 'active',
            'firewall_enabled': device['firewall_enabled'],
            'os_patched': self._is_os_current(device['os_version']),
            'password_policy': device['password_last_changed'] < 90 days,
        }
        
        if all(checks.values()):
            return True, "Device compliant"
        else:
            failed = [k for k, v in checks.items() if not v]
            return False, f"Device non-compliant: {failed}"
```

**3.4 Audit & Compliance Logging**
- Immutable audit logs untuk semua permission changes
- Log: who, what, when, where, why, IP, device, approval
- SIEM integration untuk real-time alerting

**3.5 Metrics & KPI**
- **Unauthorized Permission Changes Blocked:** Target 100%
- **Detection-to-Block Time:** Target < 5 minutes
- **VPN Adoption Rate:** Target 100% untuk sensitive operations
- **Incident Response Time:** Target < 30 minutes

---

---

## 🛡️ IMPLEMENTASI ROADMAP

### **Phase 1: Emergency Response (Week 1-2)**
```
Priority: IMMEDIATE
├─ Suspend terminated users
├─ Investigate existing breaches
├─ Setup real-time alerts untuk 3 risk patterns
├─ Block non-internal IP permission changes
└─ Require MFA untuk sensitive operations
```

### **Phase 2: Short-term Controls (Week 3-8)**
```
Priority: HIGH
├─ Deploy DLP solution
├─ Implement rate limiting & quotas
├─ Setup UBA (User Behavior Analytics)
├─ Automated offboarding process
├─ IP whitelisting for critical ops
└─ Device compliance checking
```

### **Phase 3: Long-term Solutions (Month 2-3)**
```
Priority: MEDIUM
├─ Zero Trust Architecture
├─ PAM (Privileged Access Management)
├─ Comprehensive IAM system
├─ SIEM integration
├─ Data classification framework
└─ Continuous monitoring & improvement
```

---

## 📈 SUCCESS METRICS

| Metrik | Target | Review |
|--------|--------|--------|
| **Incident Detection Time** | < 5 min | Weekly |
| **Incident Response Time** | < 30 min | Weekly |
| **Unauthorized Access Blocked** | 100% | Daily |
| **False Positive Rate** | < 5% | Monthly |
| **System Availability** | > 99.9% | Monthly |
| **User Satisfaction** | > 90% | Quarterly |

---

## 📚 REFERENSI & BEST PRACTICES

1. **NIST Cybersecurity Framework** - Risk Management
2. **ISO 27001** - Information Security Management
3. **GDPR** - Data Protection Regulations
4. **CIS Critical Security Controls** - Top 20 Controls
5. **OWASP Top 10** - Web Application Security
6. **Zero Trust Architecture** - NIST SP 800-207

---

## 📞 KONTAK & APPROVAL

**Prepared by:** Security Data Science Team  
**Reviewed by:** [CISO/Security Officer]  
**Approved by:** [CTO/Director IT]  
**Date:** 2026-06-12  
**Next Review:** 2026-09-12

---

**Status:** 🟡 PENDING IMPLEMENTATION

