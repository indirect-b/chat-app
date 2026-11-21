# PRODUCT.md — Chat App (پیام‌رسان)

## 1. Product Truth
- **Name:** پیام‌رسان (Chat App)
- **Nature:** High-security real-time web messenger with post-quantum end-to-end encryption (PQ-MPRBA: ML-KEM-768 + ML-DSA-65 hybrid ratchet).
- **Primary Audience:** Persian-speaking individuals and teams seeking private, untampered, and quantum-resistant real-time communication.
- **Platform:** Web application (React 19 + TypeScript + Socket.IO + Vite), RTL-first, responsive from mobile viewports (360px+) to wide desktop monitors.

## 2. Core Mechanism & Key Flows
- **Authentication:** Single sign-in via Google OAuth (GIS with redirect fallback) and emergency offline one-time recovery codes.
- **Conversations:** Direct 1:1 chats and multi-party groups. Real-time message streaming, typing indicators, read receipts, message replies, edits, pinned messages, reactions, voice notes, and file attachments.
- **E2EE Trust Signals:**
  - Post-quantum security badge (PQ-MPRBA indicator on 1:1 and group chats when epoch keys are verified).
  - Safety numbers (60-digit verification codes + QR codes with camera scanner, comparing v2 ML-DSA-65 + ML-KEM-768 keys). Verification states: VERIFIED, CHANGED, UNVERIFIED.
  - Password protection for keystore / private key encryption.
  - Ephemeral / disappearing messages timer.
- **Account & Data Rights:** Terms of service, offline account data export (JSON), and permanent account deletion secured by recovery codes.

## 3. Durable Constraints
- **Design Persona & Direction:** Dark-first, moody, minimalist, cosmic nebula/cyan accent. Zero purple-blue gradients, zero generic template cliches.
- **Language & Directionality:** Persian RTL (`dir="rtl"`) first. English/code blocks inside (`dir="ltr"`) must never break layout.
- **Performance Budget:** 60fps on low-end hardware (e.g. Intel Core i7-5500U / GeForce 940M / HDD). Composite-only CSS animations (transform, opacity). No CPU/GPU-heavy 3D/shader bloat.
- **Security Invariant:** Never modify cryptographic algorithms, keystore storage, or verification logic. Keep trust signals prominent and uncompromised.
