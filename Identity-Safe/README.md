# Biometric Identity Verification System

A secure, decentralized smart contract platform for multi-modal biometric authentication with comprehensive fraud prevention, device trust management, and comprehensive audit trails.

## Overview

This smart contract implements a sophisticated biometric identity verification system that enables secure authentication using multiple biometric modalities. The system provides enterprise-grade security features including rate limiting, device trust management, account lockout mechanisms, and comprehensive audit logging.

## Features

### Core Capabilities
- **Multi-Modal Biometric Authentication** - Support for various biometric types (fingerprint, facial recognition, iris scan, etc.)
- **Device Trust Management** - Registration and validation of trusted authentication devices
- **Rate Limiting** - Protection against brute force attacks with configurable request limits
- **Account Lockout Protection** - Automatic account suspension after failed authentication attempts
- **Audit Trail** - Comprehensive logging of all authentication activities
- **Template Expiration** - Automatic invalidation of outdated biometric templates
- **Confidence Scoring** - Configurable confidence thresholds for authentication acceptance

### Security Features
- **Encrypted Biometric Storage** - All biometric data stored as encrypted hashes
- **IP Address Tracking** - Authentication attempts logged with origin IP hashes
- **Administrative Controls** - Granular system configuration management
- **Data Validity Periods** - Automatic expiration of biometric templates
- **Multi-Level Access Control** - User and administrator permission systems

## System Configuration

### Default Configuration Constants
```clarity
Minimum Confidence Threshold: 50%
Maximum Confidence Threshold: 100%
Default Authentication Threshold: 85%
Default Lockout Period: 3600 blocks (~1 hour)
Max Authentication Failures: 5 attempts
Biometric Data Validity: 7,776,000 blocks (~90 days)
Rate Limiting Window: 60 blocks (~1 minute)
Max Requests Per Window: 10 requests
```

## Contract Architecture

### Core Data Maps
1. **User Identity Profiles** - User account status and authentication history
2. **Biometric Identity Templates** - Encrypted biometric data and metadata
3. **Authorized Device Registry** - Trusted device registration and tracking
4. **Authentication Activity Records** - Comprehensive audit logging
5. **User Request Rate Tracking** - Rate limiting enforcement

## Getting Started

### 1. Deploy the Contract
Deploy the smart contract to your Stacks blockchain network. The deploying address becomes the contract administrator.

### 2. Initialize User Profile
```clarity
(initialize-user-identity-profile)
```

### 3. Register Biometric Template
```clarity
(register-new-biometric-template 
  "fingerprint-001" 
  0x1234567890abcdef... 
  "fingerprint" 
  u92)
```

### 4. Register Trusted Device
```clarity
(register-trusted-authentication-device 
  "device-001" 
  0xabcdef1234567890...)
```

### 5. Perform Authentication
```clarity
(verify-biometric-authentication 
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM
  "fingerprint-001"
  "device-001"
  0x1234567890abcdef...
  u95
  0x987654321fedcba0...)
```

## Core Functions

### User Management
- `initialize-user-identity-profile()` - Create new user profile
- `suspend-user-identity-profile(principal)` - Deactivate user account

### Biometric Template Management
- `register-new-biometric-template(id, hash, type, confidence)` - Register biometric data
- `disable-biometric-template(user, template-id)` - Deactivate biometric template

### Device Management
- `register-trusted-authentication-device(device-id, fingerprint)` - Add trusted device
- Device trust validation during authentication

### Authentication
- `verify-biometric-authentication(user, template-id, device-id, hash, confidence, ip)` - Primary authentication function

### Data Retrieval
- `retrieve-user-identity-profile(user)` - Get user profile information
- `retrieve-biometric-template-metadata(user, template-id)` - Get template details
- `retrieve-trusted-device-information(user, device-id)` - Get device information
- `retrieve-authentication-activity-log(log-id)` - Get authentication history
- `get-system-configuration-settings()` - Get current system settings

## Security Features

### Rate Limiting
The system implements sliding window rate limiting to prevent abuse:
- **Window Duration**: 60 blocks
- **Max Requests**: 10 per window
- **Automatic Reset**: New window starts after duration expires

### Account Lockout
Protection against brute force attacks:
- **Failure Threshold**: 5 consecutive failed attempts (configurable)
- **Lockout Duration**: 3600 blocks (configurable)
- **Automatic Reset**: Counter resets on successful authentication

### Biometric Template Security
- **Encrypted Storage**: All biometric data stored as 32-byte hashes
- **Expiration**: Templates automatically expire after validity period
- **Confidence Scoring**: Minimum confidence requirements for authentication
- **Usage Tracking**: Comprehensive statistics on template usage

### Device Trust Management
- **Device Fingerprinting**: Unique device identification
- **Registration Required**: Only registered devices can authenticate
- **Activity Tracking**: Last activity timestamps for all devices
- **Trust Status**: Devices can be enabled/disabled

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 100 | ERR-UNAUTHORIZED-ACCESS | Unauthorized access attempt |
| 101 | ERR-INSUFFICIENT-PERMISSIONS | Insufficient permissions for operation |
| 102 | ERR-USER-PROFILE-NOT-FOUND | User profile does not exist |
| 103 | ERR-BIOMETRIC-TEMPLATE-EXISTS | Biometric template already exists |
| 104 | ERR-BIOMETRIC-TEMPLATE-NOT-FOUND | Biometric template not found |
| 105 | ERR-INVALID-BIOMETRIC-DATA | Invalid biometric data provided |
| 106 | ERR-AUTHENTICATION-VERIFICATION-FAILED | Authentication verification failed |
| 107 | ERR-DEVICE-NOT-TRUSTED | Device not in trusted registry |
| 108 | ERR-REQUEST-RATE-LIMIT-EXCEEDED | Too many requests in time window |
| 109 | ERR-BIOMETRIC-DATA-EXPIRED | Biometric template has expired |
| 110 | ERR-CONFIDENCE-THRESHOLD-INVALID | Invalid confidence threshold value |
| 111 | ERR-MAXIMUM-FAILED-ATTEMPTS-REACHED | Account locked due to failed attempts |

## Usage Examples

### Complete User Onboarding Flow
```clarity
;; 1. Initialize user profile
(initialize-user-identity-profile)

;; 2. Register fingerprint template
(register-new-biometric-template 
  "fp-primary" 
  0x1a2b3c4d5e6f7890a1b2c3d4e5f67890a1b2c3d4 
  "fingerprint" 
  u88)

;; 3. Register backup facial recognition
(register-new-biometric-template 
  "face-backup" 
  0x9876543210fedcba0987654321fedcba09876543 
  "facial" 
  u91)

;; 4. Register mobile device
(register-trusted-authentication-device 
  "mobile-001" 
  0xaabbccddeeff00112233445566778899aabbccdd)
```

### Authentication Flow
```clarity
;; Perform biometric authentication
(verify-biometric-authentication 
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM
  "fp-primary"
  "mobile-001"
  0x1a2b3c4d5e6f7890a1b2c3d4e5f67890a1b2c3d4
  u89
  0x192837465019283746501928374650192837465)
```

## Administrative Functions

### System Configuration
- `configure-system-operational-status(bool)` - Enable/disable system
- `update-authentication-confidence-threshold(uint)` - Set confidence requirements
- `configure-maximum-authentication-failures(uint)` - Set lockout threshold
- `set-account-lockout-duration(uint)` - Configure lockout duration

### Monitoring
- `check-user-account-lockout(principal)` - Check if user is locked out
- `retrieve-user-rate-limiting-status(principal)` - Get rate limiting status
- `get-system-configuration-settings()` - Get all system settings

## Data Structures

### User Identity Profile
```clarity
{
  account-active-status: bool,
  profile-creation-block: uint,
  most-recent-authentication: uint,
  consecutive-authentication-failures: uint,
  account-locked-until-timestamp: uint,
  registered-biometric-templates-count: uint
}
```

### Biometric Template
```clarity
{
  encrypted-biometric-hash: (buff 32),
  biometric-modality-type: (string-ascii 20),
  template-confidence-level: uint,
  template-creation-timestamp: uint,
  most-recent-usage-timestamp: uint,
  total-authentication-attempts: uint,
  template-activation-status: bool
}
```

### Trusted Device
```clarity
{
  device-fingerprint-hash: (buff 32),
  device-registration-timestamp: uint,
  device-last-activity-timestamp: uint,
  device-trust-status: bool
}
```

### Authentication Activity Record
```clarity
{
  authenticated-user-principal: principal,
  used-biometric-template-id: (string-ascii 64),
  authentication-device-id: (string-ascii 64),
  authentication-attempt-timestamp: uint,
  authentication-result-success: bool,
  measured-confidence-score: uint,
  request-origin-ip-hash: (buff 32)
}
```

## Security Considerations

### Best Practices
1. **Biometric Data Handling**: Never store raw biometric data - only encrypted hashes
2. **Device Registration**: Implement secure device registration flows
3. **Network Security**: Use HTTPS for all biometric data transmission
4. **Key Management**: Secure management of encryption keys for biometric hashes
5. **Regular Updates**: Encourage users to update biometric templates periodically

### Privacy Protection
- All biometric data is stored as irreversible cryptographic hashes
- IP addresses are stored as hashes for privacy protection
- No personally identifiable information is stored in plaintext
- Users maintain control over their biometric templates

### Compliance Considerations
- Designed to support GDPR compliance requirements
- Audit trails for regulatory reporting
- User consent and data portability support
- Right to deletion through template deactivation