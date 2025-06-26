;; Biometric Identity Verification System Smart Contract
;; A secure, decentralized platform for multi-modal biometric authentication
;; with comprehensive fraud prevention, device trust management, and audit trails

;; System Configuration Constants
(define-constant contract-administrator tx-sender)
(define-constant minimum-confidence-threshold u50)
(define-constant maximum-confidence-threshold u100)
(define-constant default-authentication-threshold u85)
(define-constant default-lockout-period u3600)
(define-constant default-max-authentication-failures u5)
(define-constant biometric-data-validity-period u7776000)
(define-constant rate-limiting-window-duration u60)
(define-constant max-requests-per-window u10)
(define-constant max-string-length u64)
(define-constant max-biometric-type-length u20)
(define-constant max-uint-value u340282366920938463463374607431768211455)

;; Error Response Codes
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-INSUFFICIENT-PERMISSIONS (err u101))
(define-constant ERR-USER-PROFILE-NOT-FOUND (err u102))
(define-constant ERR-BIOMETRIC-TEMPLATE-EXISTS (err u103))
(define-constant ERR-BIOMETRIC-TEMPLATE-NOT-FOUND (err u104))
(define-constant ERR-INVALID-BIOMETRIC-DATA (err u105))
(define-constant ERR-AUTHENTICATION-VERIFICATION-FAILED (err u106))
(define-constant ERR-DEVICE-NOT-TRUSTED (err u107))
(define-constant ERR-REQUEST-RATE-LIMIT-EXCEEDED (err u108))
(define-constant ERR-BIOMETRIC-DATA-EXPIRED (err u109))
(define-constant ERR-CONFIDENCE-THRESHOLD-INVALID (err u110))
(define-constant ERR-MAXIMUM-FAILED-ATTEMPTS-REACHED (err u111))
(define-constant ERR-INVALID-INPUT-LENGTH (err u112))
(define-constant ERR-INVALID-INPUT-VALUE (err u113))

;; System State Variables
(define-data-var system-operational-status bool true)
(define-data-var required-authentication-confidence uint default-authentication-threshold)
(define-data-var maximum-allowed-failed-attempts uint default-max-authentication-failures)
(define-data-var account-lockout-duration-seconds uint default-lockout-period)
(define-data-var biometric-template-expiration-period uint biometric-data-validity-period)
(define-data-var authentication-log-counter uint u1)

;; User Identity Management Storage
(define-map user-identity-profiles
  { user-principal: principal }
  {
    account-active-status: bool,
    profile-creation-block: uint,
    most-recent-authentication: uint,
    consecutive-authentication-failures: uint,
    account-locked-until-timestamp: uint,
    registered-biometric-templates-count: uint
  }
)

;; Biometric Template Repository
(define-map biometric-identity-templates
  { user-principal: principal, biometric-template-identifier: (string-ascii 64) }
  {
    encrypted-biometric-hash: (buff 32),
    biometric-modality-type: (string-ascii 20),
    template-confidence-level: uint,
    template-creation-timestamp: uint,
    most-recent-usage-timestamp: uint,
    total-authentication-attempts: uint,
    template-activation-status: bool
  }
)

;; Trusted Device Registry
(define-map authorized-device-registry
  { user-principal: principal, device-unique-identifier: (string-ascii 64) }
  {
    device-fingerprint-hash: (buff 32),
    device-registration-timestamp: uint,
    device-last-activity-timestamp: uint,
    device-trust-status: bool
  }
)

;; Authentication Activity Logs
(define-map authentication-activity-records
  { activity-log-identifier: uint }
  {
    authenticated-user-principal: principal,
    used-biometric-template-id: (string-ascii 64),
    authentication-device-id: (string-ascii 64),
    authentication-attempt-timestamp: uint,
    authentication-result-success: bool,
    measured-confidence-score: uint,
    request-origin-ip-hash: (buff 32)
  }
)

;; Rate Limiting Control
(define-map user-request-rate-tracking
  { user-principal: principal }
  {
    most-recent-request-timestamp: uint,
    current-window-request-count: uint,
    rate-limiting-window-start: uint
  }
)

;; INTERNAL UTILITY FUNCTIONS

(define-private (verify-contract-administrator-privileges)
  (is-eq tx-sender contract-administrator)
)

(define-private (validate-user-account-active-status (target-user-principal principal))
  (match (map-get? user-identity-profiles { user-principal: target-user-principal })
    user-profile-data (get account-active-status user-profile-data)
    false
  )
)

(define-private (check-user-account-lockout-status (target-user-principal principal))
  (match (map-get? user-identity-profiles { user-principal: target-user-principal })
    user-profile-data 
    (let ((account-lockout-expiry (get account-locked-until-timestamp user-profile-data)))
      (> account-lockout-expiry burn-block-height)
    )
    false
  )
)

(define-private (validate-string-length (input-string (string-ascii 64)) (max-length uint))
  (<= (len input-string) max-length)
)

(define-private (validate-biometric-type-length (input-string (string-ascii 20)) (max-length uint))
  (<= (len input-string) max-length)
)

(define-private (validate-uint-value (input-value uint))
  (<= input-value max-uint-value)
)

(define-private (validate-buffer-length (input-buffer (buff 32)) (expected-length uint))
  (is-eq (len input-buffer) expected-length)
)

(define-private (process-authentication-failure (failed-user-principal principal))
  (let (
    (current-user-profile (unwrap-panic (map-get? user-identity-profiles { user-principal: failed-user-principal })))
    (updated-failure-count (+ (get consecutive-authentication-failures current-user-profile) u1))
    (lockout-required (>= updated-failure-count (var-get maximum-allowed-failed-attempts)))
    (calculated-lockout-timestamp (if lockout-required 
                                   (+ burn-block-height (var-get account-lockout-duration-seconds))
                                   u0))
  )
    (map-set user-identity-profiles 
      { user-principal: failed-user-principal }
      (merge current-user-profile {
        consecutive-authentication-failures: updated-failure-count,
        account-locked-until-timestamp: calculated-lockout-timestamp
      })
    )
  )
)

(define-private (reset-authentication-failure-counter (successful-user-principal principal))
  (let ((current-user-profile (unwrap-panic (map-get? user-identity-profiles { user-principal: successful-user-principal }))))
    (map-set user-identity-profiles 
      { user-principal: successful-user-principal }
      (merge current-user-profile {
        consecutive-authentication-failures: u0,
        account-locked-until-timestamp: u0
      })
    )
  )
)

(define-private (enforce-request-rate-limiting (requesting-user-principal principal))
  (let (
    (current-block-timestamp burn-block-height)
    (existing-rate-limit-data (default-to 
      { most-recent-request-timestamp: u0, current-window-request-count: u0, rate-limiting-window-start: current-block-timestamp }
      (map-get? user-request-rate-tracking { user-principal: requesting-user-principal })
    ))
  )
    (if (> (- current-block-timestamp (get rate-limiting-window-start existing-rate-limit-data)) rate-limiting-window-duration)
      ;; Initialize new rate limiting window
      (begin
        (map-set user-request-rate-tracking 
          { user-principal: requesting-user-principal }
          { most-recent-request-timestamp: current-block-timestamp, current-window-request-count: u1, rate-limiting-window-start: current-block-timestamp }
        )
        (ok true)
      )
      ;; Validate current window request limits
      (if (>= (get current-window-request-count existing-rate-limit-data) max-requests-per-window)
        ERR-REQUEST-RATE-LIMIT-EXCEEDED
        (begin
          (map-set user-request-rate-tracking 
            { user-principal: requesting-user-principal }
            (merge existing-rate-limit-data {
              most-recent-request-timestamp: current-block-timestamp,
              current-window-request-count: (+ (get current-window-request-count existing-rate-limit-data) u1)
            })
          )
          (ok true)
        )
      )
    )
  )
)

(define-private (create-authentication-activity-log 
  (authenticated-user principal) 
  (template-identifier (string-ascii 64))
  (device-identifier (string-ascii 64))
  (authentication-successful bool)
  (confidence-measurement uint)
  (origin-ip-hash (buff 32))
)
  (let ((log-entry-id (var-get authentication-log-counter)))
    ;; Validate inputs before using them
    (asserts! (validate-string-length template-identifier max-string-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-string-length device-identifier max-string-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-buffer-length origin-ip-hash u32) ERR-INVALID-INPUT-LENGTH)
    
    (map-set authentication-activity-records
      { activity-log-identifier: log-entry-id }
      {
        authenticated-user-principal: authenticated-user,
        used-biometric-template-id: template-identifier,
        authentication-device-id: device-identifier,
        authentication-attempt-timestamp: burn-block-height,
        authentication-result-success: authentication-successful,
        measured-confidence-score: confidence-measurement,
        request-origin-ip-hash: origin-ip-hash
      }
    )
    (var-set authentication-log-counter (+ log-entry-id u1))
    (ok log-entry-id)
  )
)

(define-private (validate-biometric-template-freshness (template-metadata { encrypted-biometric-hash: (buff 32), biometric-modality-type: (string-ascii 20), template-confidence-level: uint, template-creation-timestamp: uint, most-recent-usage-timestamp: uint, total-authentication-attempts: uint, template-activation-status: bool }))
  (let (
    (current-block-timestamp burn-block-height)
    (template-expiration-timestamp (+ (get template-creation-timestamp template-metadata) (var-get biometric-template-expiration-period)))
  )
    (> current-block-timestamp template-expiration-timestamp)
  )
)

;; ADMINISTRATIVE SYSTEM MANAGEMENT

(define-public (configure-system-operational-status (operational-state bool))
  (begin
    (asserts! (verify-contract-administrator-privileges) ERR-UNAUTHORIZED-ACCESS)
    (var-set system-operational-status operational-state)
    (ok true)
  )
)

(define-public (update-authentication-confidence-threshold (new-threshold-value uint))
  (begin
    (asserts! (verify-contract-administrator-privileges) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (and (>= new-threshold-value minimum-confidence-threshold) 
                   (<= new-threshold-value maximum-confidence-threshold)) ERR-CONFIDENCE-THRESHOLD-INVALID)
    (var-set required-authentication-confidence new-threshold-value)
    (ok true)
  )
)

(define-public (configure-maximum-authentication-failures (max-failure-attempts uint))
  (begin
    (asserts! (verify-contract-administrator-privileges) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-uint-value max-failure-attempts) ERR-INVALID-INPUT-VALUE)
    (asserts! (> max-failure-attempts u0) ERR-INVALID-INPUT-VALUE)
    (var-set maximum-allowed-failed-attempts max-failure-attempts)
    (ok true)
  )
)

(define-public (set-account-lockout-duration (lockout-duration-seconds uint))
  (begin
    (asserts! (verify-contract-administrator-privileges) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-uint-value lockout-duration-seconds) ERR-INVALID-INPUT-VALUE)
    (asserts! (> lockout-duration-seconds u0) ERR-INVALID-INPUT-VALUE)
    (var-set account-lockout-duration-seconds lockout-duration-seconds)
    (ok true)
  )
)

;; USER IDENTITY PROFILE MANAGEMENT

(define-public (initialize-user-identity-profile)
  (let ((registering-user-principal tx-sender))
    (asserts! (var-get system-operational-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-none (map-get? user-identity-profiles { user-principal: registering-user-principal })) ERR-BIOMETRIC-TEMPLATE-EXISTS)
    (map-set user-identity-profiles
      { user-principal: registering-user-principal }
      {
        account-active-status: true,
        profile-creation-block: block-height,
        most-recent-authentication: u0,
        consecutive-authentication-failures: u0,
        account-locked-until-timestamp: u0,
        registered-biometric-templates-count: u0
      }
    )
    (ok true)
  )
)

(define-public (suspend-user-identity-profile (target-user-principal principal))
  (begin
    (asserts! (var-get system-operational-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (or (verify-contract-administrator-privileges) (is-eq tx-sender target-user-principal)) ERR-INSUFFICIENT-PERMISSIONS)
    (asserts! (is-some (map-get? user-identity-profiles { user-principal: target-user-principal })) ERR-USER-PROFILE-NOT-FOUND)
    (let ((existing-user-profile (unwrap-panic (map-get? user-identity-profiles { user-principal: target-user-principal }))))
      (map-set user-identity-profiles 
        { user-principal: target-user-principal }
        (merge existing-user-profile { account-active-status: false })
      )
    )
    (ok true)
  )
)

;; BIOMETRIC TEMPLATE REGISTRATION & MANAGEMENT

(define-public (register-new-biometric-template 
  (unique-template-identifier (string-ascii 64))
  (encrypted-template-hash (buff 32))
  (biometric-type-classification (string-ascii 20))
  (template-confidence-score uint)
)
  (let ((registering-user-principal tx-sender))
    (asserts! (var-get system-operational-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-user-account-active-status registering-user-principal) ERR-USER-PROFILE-NOT-FOUND)
    
    ;; Validate input parameters
    (asserts! (validate-string-length unique-template-identifier max-string-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-biometric-type-length biometric-type-classification max-biometric-type-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-buffer-length encrypted-template-hash u32) ERR-INVALID-INPUT-LENGTH)
    
    (asserts! (is-none (map-get? biometric-identity-templates 
                        { user-principal: registering-user-principal, biometric-template-identifier: unique-template-identifier })) 
              ERR-BIOMETRIC-TEMPLATE-EXISTS)
    (asserts! (and (>= template-confidence-score minimum-confidence-threshold) 
                   (<= template-confidence-score maximum-confidence-threshold)) ERR-INVALID-BIOMETRIC-DATA)
    (asserts! (> (len encrypted-template-hash) u0) ERR-INVALID-BIOMETRIC-DATA)
    
    (let (
      (current-block-timestamp burn-block-height)
      (existing-user-profile (unwrap-panic (map-get? user-identity-profiles { user-principal: registering-user-principal })))
    )
      (map-set biometric-identity-templates
        { user-principal: registering-user-principal, biometric-template-identifier: unique-template-identifier }
        {
          encrypted-biometric-hash: encrypted-template-hash,
          biometric-modality-type: biometric-type-classification,
          template-confidence-level: template-confidence-score,
          template-creation-timestamp: current-block-timestamp,
          most-recent-usage-timestamp: u0,
          total-authentication-attempts: u0,
          template-activation-status: true
        }
      )
      (map-set user-identity-profiles 
        { user-principal: registering-user-principal }
        (merge existing-user-profile {
          registered-biometric-templates-count: (+ (get registered-biometric-templates-count existing-user-profile) u1)
        })
      )
    )
    (ok true)
  )
)

(define-public (disable-biometric-template 
  (target-user-principal principal)
  (template-identifier-to-disable (string-ascii 64))
)
  (begin
    (asserts! (var-get system-operational-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (or (verify-contract-administrator-privileges) (is-eq tx-sender target-user-principal)) ERR-INSUFFICIENT-PERMISSIONS)
    
    ;; Validate input parameter
    (asserts! (validate-string-length template-identifier-to-disable max-string-length) ERR-INVALID-INPUT-LENGTH)
    
    (asserts! (is-some (map-get? biometric-identity-templates 
                        { user-principal: target-user-principal, biometric-template-identifier: template-identifier-to-disable })) 
              ERR-BIOMETRIC-TEMPLATE-NOT-FOUND)
    
    (let ((existing-template-data (unwrap-panic (map-get? biometric-identity-templates 
                                                  { user-principal: target-user-principal, biometric-template-identifier: template-identifier-to-disable }))))
      (map-set biometric-identity-templates 
        { user-principal: target-user-principal, biometric-template-identifier: template-identifier-to-disable }
        (merge existing-template-data { template-activation-status: false })
      )
    )
    (ok true)
  )
)

;; TRUSTED DEVICE MANAGEMENT

(define-public (register-trusted-authentication-device 
  (unique-device-identifier (string-ascii 64))
  (device-fingerprint-hash (buff 32))
)
  (let ((device-owner-principal tx-sender))
    (asserts! (var-get system-operational-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-user-account-active-status device-owner-principal) ERR-USER-PROFILE-NOT-FOUND)
    
    ;; Validate input parameters
    (asserts! (validate-string-length unique-device-identifier max-string-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-buffer-length device-fingerprint-hash u32) ERR-INVALID-INPUT-LENGTH)
    
    (asserts! (is-none (map-get? authorized-device-registry 
                        { user-principal: device-owner-principal, device-unique-identifier: unique-device-identifier })) 
              ERR-BIOMETRIC-TEMPLATE-EXISTS)
    
    (let ((current-block-timestamp burn-block-height))
      (map-set authorized-device-registry
        { user-principal: device-owner-principal, device-unique-identifier: unique-device-identifier }
        {
          device-fingerprint-hash: device-fingerprint-hash,
          device-registration-timestamp: current-block-timestamp,
          device-last-activity-timestamp: u0,
          device-trust-status: true
        }
      )
    )
    (ok true)
  )
)

;; BIOMETRIC AUTHENTICATION VERIFICATION

(define-public (verify-biometric-authentication 
  (authenticating-user-principal principal)
  (biometric-template-id (string-ascii 64))
  (authentication-device-id (string-ascii 64))
  (submitted-biometric-hash (buff 32))
  (measured-confidence-score uint)
  (request-origin-ip-hash (buff 32))
)
  (let (
    (current-block-timestamp burn-block-height)
  )
    (asserts! (var-get system-operational-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-user-account-active-status authenticating-user-principal) ERR-USER-PROFILE-NOT-FOUND)
    (asserts! (not (check-user-account-lockout-status authenticating-user-principal)) ERR-MAXIMUM-FAILED-ATTEMPTS-REACHED)
    
    ;; Validate input parameters
    (asserts! (validate-string-length biometric-template-id max-string-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-string-length authentication-device-id max-string-length) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-buffer-length submitted-biometric-hash u32) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-buffer-length request-origin-ip-hash u32) ERR-INVALID-INPUT-LENGTH)
    (asserts! (validate-uint-value measured-confidence-score) ERR-INVALID-INPUT-VALUE)
    
    ;; Enforce rate limiting controls
    (try! (enforce-request-rate-limiting authenticating-user-principal))
    
    ;; Retrieve and validate biometric template
    (match (map-get? biometric-identity-templates 
             { user-principal: authenticating-user-principal, biometric-template-identifier: biometric-template-id })
      biometric-template-data
      (begin
        (asserts! (get template-activation-status biometric-template-data) ERR-BIOMETRIC-TEMPLATE-NOT-FOUND)
        (asserts! (not (validate-biometric-template-freshness biometric-template-data)) ERR-BIOMETRIC-DATA-EXPIRED)
        
        ;; Validate trusted device registration
        (match (map-get? authorized-device-registry 
                 { user-principal: authenticating-user-principal, device-unique-identifier: authentication-device-id })
          trusted-device-data
          (begin
            (asserts! (get device-trust-status trusted-device-data) ERR-DEVICE-NOT-TRUSTED)
            
            ;; Execute biometric authentication verification
            (let (
              (biometric-hash-matches (is-eq (get encrypted-biometric-hash biometric-template-data) submitted-biometric-hash))
              (confidence-score-acceptable (>= measured-confidence-score (var-get required-authentication-confidence)))
              (authentication-verification-successful (and biometric-hash-matches confidence-score-acceptable))
            )
              
              ;; Record authentication attempt in activity logs
              (unwrap-panic (create-authentication-activity-log 
                            authenticating-user-principal biometric-template-id authentication-device-id 
                            authentication-verification-successful measured-confidence-score request-origin-ip-hash))
              
              (if authentication-verification-successful
                (begin
                  ;; Process successful authentication
                  (reset-authentication-failure-counter authenticating-user-principal)
                  (let ((current-user-profile (unwrap-panic (map-get? user-identity-profiles { user-principal: authenticating-user-principal }))))
                    (map-set user-identity-profiles 
                      { user-principal: authenticating-user-principal }
                      (merge current-user-profile { most-recent-authentication: current-block-timestamp })
                    )
                  )
                  
                  ;; Update biometric template usage statistics
                  (map-set biometric-identity-templates 
                    { user-principal: authenticating-user-principal, biometric-template-identifier: biometric-template-id }
                    (merge biometric-template-data {
                      most-recent-usage-timestamp: current-block-timestamp,
                      total-authentication-attempts: (+ (get total-authentication-attempts biometric-template-data) u1)
                    })
                  )
                  
                  ;; Update trusted device activity timestamp
                  (map-set authorized-device-registry 
                    { user-principal: authenticating-user-principal, device-unique-identifier: authentication-device-id }
                    (merge trusted-device-data { device-last-activity-timestamp: current-block-timestamp })
                  )
                  
                  (ok true)
                )
                (begin
                  ;; Process failed authentication attempt
                  (process-authentication-failure authenticating-user-principal)
                  ERR-AUTHENTICATION-VERIFICATION-FAILED
                )
              )
            )
          )
          ERR-DEVICE-NOT-TRUSTED
        )
      )
      ERR-BIOMETRIC-TEMPLATE-NOT-FOUND
    )
  )
)

;; PUBLIC DATA RETRIEVAL FUNCTIONS

(define-read-only (retrieve-user-identity-profile (target-user-principal principal))
  (map-get? user-identity-profiles { user-principal: target-user-principal })
)

(define-read-only (retrieve-biometric-template-metadata (target-user-principal principal) (template-identifier (string-ascii 64)))
  (map-get? biometric-identity-templates { user-principal: target-user-principal, biometric-template-identifier: template-identifier })
)

(define-read-only (retrieve-trusted-device-information (target-user-principal principal) (device-identifier (string-ascii 64)))
  (map-get? authorized-device-registry { user-principal: target-user-principal, device-unique-identifier: device-identifier })
)

(define-read-only (retrieve-authentication-activity-log (log-identifier uint))
  (map-get? authentication-activity-records { activity-log-identifier: log-identifier })
)

(define-read-only (get-system-configuration-settings)
  {
    system-operational: (var-get system-operational-status),
    authentication-threshold: (var-get required-authentication-confidence),
    max-failure-attempts: (var-get maximum-allowed-failed-attempts),
    lockout-duration: (var-get account-lockout-duration-seconds),
    template-expiry-period: (var-get biometric-template-expiration-period)
  }
)

(define-read-only (check-user-account-lockout (target-user-principal principal))
  (check-user-account-lockout-status target-user-principal)
)

(define-read-only (retrieve-user-rate-limiting-status (target-user-principal principal))
  (map-get? user-request-rate-tracking { user-principal: target-user-principal })
)