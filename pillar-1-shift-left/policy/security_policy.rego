package main

# Policy 1: Container must not run as root
deny[msg] {
    input.kind == "Dockerfile"
    not input.user
    msg := "POLICY-VIOLATION-001: Dockerfile must define a non-root USER directive"
}

# Policy 2: Security Mode check for deployment
deny[msg] {
    input.securityMode == "VULNERABLE"
    input.targetEnvironment == "production"
    msg := "POLICY-VIOLATION-002: Cannot deploy to production with securityMode set to VULNERABLE"
}

# Policy 3: Image Signing Verification
deny[msg] {
    input.kind == "ImageMetadata"
    input.cosignSigned != true
    msg := "POLICY-VIOLATION-003: Container image is not cryptographically signed with Cosign"
}
