import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  SAFETY_STRINGS_FA,
  SafetyNumberData,
  ContactVerificationRecord,
  computeSafetyNumberForContact,
  generateQrCodeMatrix,
  parseAndCompareQrPayload,
  compareSafetyNumberDigits,
  markContactVerified,
  resetContactVerificationToUnverified,
} from '../utils/safetyNumber';

interface SafetyNumberModalProps {
  open: boolean;
  myUsername: string;
  contactUsername: string;
  contactAvatar?: string | null;
  peerPublicKey: string | null | undefined;
  verificationRecord: ContactVerificationRecord;
  initialShowLearnMore?: boolean;
  onClose: () => void;
  onVerificationUpdated: (updated: ContactVerificationRecord) => void;
  showToast: (text: string) => void;
}

type ModalMode =
  | 'MAIN'
  | 'SCANNING'
  | 'SCAN_MATCH_CONFIRM'
  | 'SCAN_MISMATCH'
  | 'SCAN_TECH_ERROR';

export const SafetyNumberModal: React.FC<SafetyNumberModalProps> = ({
  open,
  myUsername,
  contactUsername,
  contactAvatar,
  peerPublicKey,
  verificationRecord,
  initialShowLearnMore = false,
  onClose,
  onVerificationUpdated,
  showToast,
}) => {
  const [mode, setMode] = useState<ModalMode>('MAIN');
  const [checkedGroups, setCheckedGroups] = useState<boolean[]>(Array(12).fill(false));
  const [showLearnMore, setShowLearnMore] = useState<boolean>(initialShowLearnMore);
  const [pasteCompareInput, setPasteCompareInput] = useState<string>('');
  const [qrInputManual, setQrInputManual] = useState<string>('');
  const [techErrorDetail, setTechErrorDetail] = useState<string>('');
  const [mismatchOtherGroups, setMismatchOtherGroups] = useState<string[]>([]);
  const [mismatchOtherHex, setMismatchOtherHex] = useState<string>('');

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const scanTimerRef = useRef<number | null>(null);
  const qrFileInputRef = useRef<HTMLInputElement | null>(null);

  const safetyData: SafetyNumberData | null = useMemo(() => {
    if (!open || !myUsername || !contactUsername) return null;
    return computeSafetyNumberForContact(myUsername, peerPublicKey, contactUsername);
  }, [open, myUsername, contactUsername, peerPublicKey]);

  const qrMatrix = useMemo(() => {
    if (!safetyData?.qrPayload) return null;
    try {
      return generateQrCodeMatrix(safetyData.qrPayload);
    } catch {
      return null;
    }
  }, [safetyData]);

  const stopCamera = () => {
    if (scanTimerRef.current) {
      window.clearInterval(scanTimerRef.current);
      scanTimerRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  };

  useEffect(() => {
    if (open) {
      setMode('MAIN');
      setCheckedGroups(Array(12).fill(false));
      setShowLearnMore(initialShowLearnMore || verificationRecord.state === 'CHANGED');
      setPasteCompareInput('');
      setQrInputManual('');
      setTechErrorDetail('');
      setMismatchOtherGroups([]);
      setMismatchOtherHex('');
    } else {
      stopCamera();
    }
    return () => {
      stopCamera();
    };
  }, [open, contactUsername, initialShowLearnMore, verificationRecord.state]);

  if (!open) return null;

  const handleToggleGroupCheck = (index: number) => {
    // صرفاً کمک‌حافظه (Memory Aid)؛ هرگز به‌صورت خودکار وضعیت را VERIFIED نمی‌کند
    setCheckedGroups(prev => {
      const next = [...prev];
      next[index] = !next[index];
      return next;
    });
  };

  const handleCopySafetyNumber = async () => {
    if (!safetyData) return;
    try {
      await navigator.clipboard.writeText(safetyData.formattedDisplay);
      showToast(`📋 ${SAFETY_STRINGS_FA.copiedToast}`);
    } catch {
      showToast('کپی انجام نشد');
    }
  };

  const handleNumbersMatchAction = () => {
    if (!safetyData) return;
    const updated = markContactVerified(myUsername, contactUsername, peerPublicKey);
    if (updated) {
      onVerificationUpdated(updated);
      showToast(`🛡️ ${SAFETY_STRINGS_FA.verified}: @${contactUsername}`);
    }
  };

  const handleResetVerification = () => {
    const updated = resetContactVerificationToUnverified(myUsername, contactUsername);
    onVerificationUpdated(updated);
    setCheckedGroups(Array(12).fill(false));
    showToast(`وضعیت @${contactUsername} به «${SAFETY_STRINGS_FA.notVerified}» تغییر یافت`);
  };

  const evaluateScannedQrString = (rawScanned: string) => {
    stopCamera();
    if (!safetyData) {
      setTechErrorDetail('کلید هویت پساکوانتومی (ML-DSA-65) مخاطب هنوز در دسترس نیست.');
      setMode('SCAN_TECH_ERROR');
      return;
    }

    const res = parseAndCompareQrPayload(rawScanned, safetyData.sha256Hex);
    if (res.status === 'PARSE_ERROR') {
      setTechErrorDetail(res.errorReason || 'ساختار کد QR نامعتبر است.');
      setMode('SCAN_TECH_ERROR');
      return;
    }

    if (res.status === 'MATCH') {
      setMode('SCAN_MATCH_CONFIRM');
      return;
    }

    // MISMATCH
    setMismatchOtherGroups(res.scannedGroups12 || []);
    setMismatchOtherHex(res.scannedHex || '');
    setMode('SCAN_MISMATCH');
  };

  const startCameraScanner = async () => {
    setTechErrorDetail('');
    setMode('SCANNING');

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setTechErrorDetail('مرورگر یا محیط فعلی از دسترسی مستقیم به دوربین پشتیبانی نمی‌کند.');
      setMode('SCAN_TECH_ERROR');
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play().catch(() => {});
      }

      const BarcodeDetectorCtor = (window as unknown as { BarcodeDetector?: any }).BarcodeDetector;
      if (BarcodeDetectorCtor) {
        const detector = new BarcodeDetectorCtor({ formats: ['qr_code'] });
        scanTimerRef.current = window.setInterval(async () => {
          if (!videoRef.current || videoRef.current.readyState < 2) return;
          try {
            const barcodes = await detector.detect(videoRef.current);
            if (Array.isArray(barcodes) && barcodes.length > 0 && barcodes[0]?.rawValue) {
              evaluateScannedQrString(String(barcodes[0].rawValue));
            }
          } catch {
            // ادامه اسکن در فریم بعدی
          }
        }, 350);
      }
    } catch {
      stopCamera();
      setTechErrorDetail('دسترسی به دوربین رد شد یا دوربینی در این دستگاه یافت نشد.');
      setMode('SCAN_TECH_ERROR');
    }
  };

  const handleQrImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    const BarcodeDetectorCtor = (window as unknown as { BarcodeDetector?: any }).BarcodeDetector;
    if (!BarcodeDetectorCtor) {
      setTechErrorDetail(
        'مرورگر فعلی فاقد موتور داخلی تشخیص تصویر QR (BarcodeDetector) است. لطفاً کد QR را وارد کنید یا از مقایسه خوانشی استفاده نمایید.'
      );
      setMode('SCAN_TECH_ERROR');
      return;
    }

    try {
      const bitmap = await createImageBitmap(file);
      const detector = new BarcodeDetectorCtor({ formats: ['qr_code'] });
      const codes = await detector.detect(bitmap);
      if (Array.isArray(codes) && codes.length > 0 && codes[0]?.rawValue) {
        evaluateScannedQrString(String(codes[0].rawValue));
      } else {
        setTechErrorDetail('هیچ کد QR معتبری در تصویر انتخابی تشخیص داده نشد.');
        setMode('SCAN_TECH_ERROR');
      }
    } catch {
      setTechErrorDetail('خطا در پردازش فایل تصویر کد QR.');
      setMode('SCAN_TECH_ERROR');
    }
  };

  const handleComparePastedDigits = () => {
    if (!safetyData || !pasteCompareInput.trim()) return;
    const trimmed = pasteCompareInput.trim();

    // اگر کاربر رشته کامل کد QR را پیست کرده باشد
    if (trimmed.startsWith('PQ-MPRBA-SAFETY-v1:')) {
      evaluateScannedQrString(trimmed);
      return;
    }

    const cmp = compareSafetyNumberDigits(safetyData.digits60, trimmed);
    if (!cmp.validFormat) {
      setTechErrorDetail(
        'شماره واردشده باید دقیقاً شامل ۶۰ رقم لاتین (با یا بدون فاصله) باشد.'
      );
      setMode('SCAN_TECH_ERROR');
      return;
    }

    if (cmp.matches) {
      setMode('SCAN_MATCH_CONFIRM');
    } else {
      setMismatchOtherGroups(cmp.otherGroups12);
      setMismatchOtherHex('');
      setMode('SCAN_MISMATCH');
    }
  };

  const formatAuditDate = (ts: number) => {
    try {
      return new Intl.DateTimeFormat('fa-IR', {
        dateStyle: 'medium',
        timeStyle: 'short',
        timeZone: 'Asia/Tehran',
      }).format(new Date(ts));
    } catch {
      return new Date(ts).toISOString();
    }
  };

  const stateBadgeStyle = (): React.CSSProperties => {
    if (verificationRecord.state === 'VERIFIED') {
      return {
        background: 'rgba(34, 197, 94, 0.16)',
        border: '1px solid rgba(34, 197, 94, 0.45)',
        color: '#4ade80',
      };
    }
    if (verificationRecord.state === 'CHANGED') {
      return {
        background: 'rgba(239, 68, 68, 0.2)',
        border: '1px solid rgba(239, 68, 68, 0.5)',
        color: '#f87171',
      };
    }
    return {
      background: 'rgba(255, 255, 255, 0.07)',
      border: '1px solid rgba(255, 255, 255, 0.15)',
      color: '#d1d5db',
    };
  };

  const stateLabel = () => {
    if (verificationRecord.state === 'VERIFIED') {
      return `🛡️ ${SAFETY_STRINGS_FA.verified}`;
    }
    if (verificationRecord.state === 'CHANGED') {
      return `⚠️ ${SAFETY_STRINGS_FA.safetyNumberChanged}`;
    }
    return `○ ${SAFETY_STRINGS_FA.notVerified}`;
  };

  return (
    <div className="modal" id="safetyNumberModal" style={{ zIndex: 700 }}>
      <div
        className="modal-box"
        style={{
          width: '94%',
          maxWidth: '500px',
          maxHeight: '90vh',
          overflowY: 'auto',
          textAlign: 'right',
          direction: 'rtl',
          padding: '22px',
        }}
      >
        {/* HEADER */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '12px',
            borderBottom: '1px solid var(--border)',
            paddingBottom: '10px',
          }}
        >
          <h3 style={{ margin: 0, fontSize: '16px', color: '#f3f4f6' }}>
            🔐 {SAFETY_STRINGS_FA.safetyNumber} — {SAFETY_STRINGS_FA.verifyContact}
          </h3>
          <button
            type="button"
            onClick={() => {
              stopCamera();
              onClose();
            }}
            style={{
              background: 'none',
              border: 'none',
              color: '#9ca3af',
              fontSize: '18px',
              cursor: 'pointer',
              padding: '2px 6px',
            }}
            title="بستن"
          >
            ✕
          </button>
        </div>

        {/* CONTACT IDENTITY SUMMARY */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '10px',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: '12px',
            padding: '10px 12px',
            marginBottom: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '50%',
                background: 'linear-gradient(135deg,#7c3aed,#06b6d4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '18px',
                fontWeight: 700,
                color: '#fff',
                overflow: 'hidden',
                flexShrink: 0,
              }}
            >
              {contactAvatar ? (
                <img
                  src={contactAvatar}
                  alt=""
                  style={{ width: '44px', height: '44px', objectFit: 'cover' }}
                />
              ) : (
                contactUsername[0]?.toUpperCase()
              )}
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '14.5px', color: '#f9fafb' }}>
                @{contactUsername}
              </div>
              <div style={{ fontSize: '11px', color: '#9ca3af' }}>
                کلید هویت پساکوانتومی FIPS 204 (ML-DSA-65)
              </div>
            </div>
          </div>

          <div
            style={{
              ...stateBadgeStyle(),
              padding: '5px 10px',
              borderRadius: '14px',
              fontSize: '11.5px',
              fontWeight: 700,
              whiteSpace: 'nowrap',
            }}
          >
            {stateLabel()}
          </div>
        </div>

        {/* CHANGED WARNING + AUDIT LOG */}
        {verificationRecord.state === 'CHANGED' && (
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.14)',
              border: '1px solid rgba(239, 68, 68, 0.45)',
              borderRadius: '12px',
              padding: '11px 13px',
              marginBottom: '12px',
              fontSize: '12px',
              lineHeight: '1.7',
              color: '#fecaca',
            }}
          >
            <div style={{ fontWeight: 700, color: '#f87171', marginBottom: '4px' }}>
              ⚠️ {SAFETY_STRINGS_FA.inChatChangedNoticeTitle}
            </div>
            <div>{SAFETY_STRINGS_FA.inChatChangedNoticeBody}</div>
            <div style={{ marginTop: '6px' }}>
              <button
                type="button"
                onClick={() => setShowLearnMore(prev => !prev)}
                style={{
                  background: 'rgba(255,255,255,0.1)',
                  border: '1px solid rgba(255,255,255,0.2)',
                  color: '#fff',
                  borderRadius: '7px',
                  padding: '3px 9px',
                  fontSize: '11px',
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                }}
              >
                {SAFETY_STRINGS_FA.learnMore} {showLearnMore ? '▲' : '▼'}
              </button>
            </div>
            {showLearnMore && (
              <div
                style={{
                  marginTop: '8px',
                  paddingTop: '8px',
                  borderTop: '1px solid rgba(239,68,68,0.3)',
                  whiteSpace: 'pre-line',
                  color: '#fee2e2',
                  fontSize: '11.5px',
                }}
              >
                {SAFETY_STRINGS_FA.learnMoreBenignAndRisk}
                {verificationRecord.auditHistory.length > 0 && (
                  <div
                    style={{
                      marginTop: '8px',
                      background: 'rgba(0,0,0,0.25)',
                      padding: '8px',
                      borderRadius: '8px',
                    }}
                  >
                    <div style={{ fontWeight: 700, marginBottom: '4px', color: '#fca5a5' }}>
                      📋 سابقه ممیزی محلی کلیدهای قبلی (فقط در این دستگاه):
                    </div>
                    {verificationRecord.auditHistory.slice(0, 3).map((entry, idx) => (
                      <div
                        key={idx}
                        style={{
                          fontSize: '10.5px',
                          marginBottom: '4px',
                          borderBottom:
                            idx < Math.min(2, verificationRecord.auditHistory.length - 1)
                              ? '1px dashed rgba(255,255,255,0.1)'
                              : 'none',
                          paddingBottom: '3px',
                        }}
                      >
                        <div>زمان تشخیص تغییر: {formatAuditDate(entry.detectedAt)}</div>
                        <div
                          dir="ltr"
                          style={{
                            fontFamily:
                              'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                            color: '#fcd34d',
                            wordBreak: 'break-all',
                          }}
                        >
                          SHA-256 قبلی: {entry.previousKeyFingerprint.slice(0, 32)}…
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* MISSING KEY FALLBACK */}
        {!safetyData ? (
          <div
            style={{
              background: 'rgba(234, 179, 8, 0.14)',
              border: '1px solid rgba(234, 179, 8, 0.4)',
              borderRadius: '12px',
              padding: '16px',
              textAlign: 'center',
              color: '#fef08a',
              fontSize: '13px',
              lineHeight: '1.7',
              marginBottom: '14px',
            }}
          >
            ⚠️ کلید عمومی امضای هویت پساکوانتومی (ML-DSA-65) برای کاربر{' '}
            <b>@{contactUsername}</b> یا حساب شما هنوز منتشر نشده است. به محض دریافت باندل کلید
            عمومی مخاطب، شماره ایمنی ۶۰ رقمی و کد QR قابل محاسبه خواهد بود.
          </div>
        ) : mode === 'SCAN_MATCH_CONFIRM' ? (
          /* QR / COMPARISON MATCH EXPLICIT CONFIRMATION */
          <div
            style={{
              background: 'rgba(34, 197, 94, 0.14)',
              border: '1px solid rgba(34, 197, 94, 0.45)',
              borderRadius: '14px',
              padding: '16px',
              marginBottom: '14px',
            }}
          >
            <div
              style={{
                fontSize: '15px',
                fontWeight: 700,
                color: '#4ade80',
                marginBottom: '8px',
              }}
            >
              ✅ {SAFETY_STRINGS_FA.qrMatchTitle}
            </div>
            <p
              style={{
                fontSize: '12.5px',
                lineHeight: '1.75',
                color: '#e5e7eb',
                marginBottom: '12px',
              }}
            >
              {SAFETY_STRINGS_FA.qrMatchBody}
            </p>
            <div
              dir="ltr"
              style={{
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                background: 'rgba(0,0,0,0.3)',
                padding: '10px',
                borderRadius: '10px',
                fontSize: '13px',
                textAlign: 'center',
                color: '#86efac',
                letterSpacing: '0.5px',
                marginBottom: '14px',
              }}
            >
              {safetyData.formattedDisplay}
            </div>
            <div className="modal-btns">
              <button
                type="button"
                onClick={() => {
                  handleNumbersMatchAction();
                  setMode('MAIN');
                }}
              >
                {SAFETY_STRINGS_FA.confirmVerifyOnDevice}
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setMode('MAIN')}
              >
                {SAFETY_STRINGS_FA.cancel}
              </button>
            </div>
          </div>
        ) : mode === 'SCAN_MISMATCH' ? (
          /* HARD WARNING ON MISMATCH — NO "VERIFY ANYWAY" ALLOWED */
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.18)',
              border: '2px solid rgba(239, 68, 68, 0.65)',
              borderRadius: '14px',
              padding: '16px',
              marginBottom: '14px',
            }}
          >
            <div
              style={{
                fontSize: '15px',
                fontWeight: 700,
                color: '#f87171',
                marginBottom: '8px',
              }}
            >
              ⛔ {SAFETY_STRINGS_FA.qrMismatchTitle}
            </div>
            <p
              style={{
                fontSize: '12.5px',
                lineHeight: '1.75',
                color: '#fecaca',
                marginBottom: '12px',
              }}
            >
              {SAFETY_STRINGS_FA.qrMismatchBody}
            </p>

            {/* BOTH NUMBERS DISPLAYED FOR DIRECT INSPECTION */}
            <div style={{ marginBottom: '10px' }}>
              <div style={{ fontSize: '11.5px', color: '#9ca3af', marginBottom: '4px' }}>
                ۱. شماره ایمنی محاسبه‌شده در این دستگاه برای @{contactUsername}:
              </div>
              <div
                dir="ltr"
                style={{
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  background: 'rgba(0,0,0,0.35)',
                  border: '1px solid rgba(255,255,255,0.12)',
                  borderRadius: '8px',
                  padding: '8px 10px',
                  fontSize: '12.5px',
                  color: '#e5e7eb',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, 1fr)',
                  gap: '6px',
                  textAlign: 'center',
                }}
              >
                {safetyData.groups12.map((g, idx) => (
                  <span key={idx}>{g}</span>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <div style={{ fontSize: '11.5px', color: '#fca5a5', marginBottom: '4px' }}>
                ۲. شماره ایمنی استخراج‌شده از کد اسکن‌شده / مقایسه‌شده (نامنطبق):
              </div>
              <div
                dir="ltr"
                style={{
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  background: 'rgba(127, 29, 29, 0.45)',
                  border: '1px solid rgba(248, 113, 113, 0.5)',
                  borderRadius: '8px',
                  padding: '8px 10px',
                  fontSize: '12.5px',
                  color: '#fecaca',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, 1fr)',
                  gap: '6px',
                  textAlign: 'center',
                }}
              >
                {mismatchOtherGroups.map((g, idx) => (
                  <span
                    key={idx}
                    style={{
                      color: g !== safetyData.groups12[idx] ? '#f87171' : '#d1d5db',
                      fontWeight: g !== safetyData.groups12[idx] ? 700 : 400,
                      textDecoration: g !== safetyData.groups12[idx] ? 'underline' : 'none',
                    }}
                  >
                    {g}
                  </span>
                ))}
              </div>
              {mismatchOtherHex && (
                <div
                  dir="ltr"
                  style={{
                    fontFamily:
                      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                    fontSize: '10px',
                    color: '#fca5a5',
                    marginTop: '4px',
                    wordBreak: 'break-all',
                  }}
                >
                  Scanned Digest: {mismatchOtherHex}
                </div>
              )}
            </div>

            {/* ONLY TRY AGAIN OR CANCEL — NEVER VERIFY ANYWAY */}
            <div className="modal-btns">
              <button type="button" onClick={startCameraScanner}>
                {SAFETY_STRINGS_FA.tryAgain}
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setMode('MAIN')}
              >
                {SAFETY_STRINGS_FA.cancel}
              </button>
            </div>
          </div>
        ) : mode === 'SCAN_TECH_ERROR' ? (
          /* TECHNICAL CAMERA / PARSE FAILURE — DISTINCT FROM MISMATCH */
          <div
            style={{
              background: 'rgba(245, 158, 11, 0.14)',
              border: '1px solid rgba(245, 158, 11, 0.45)',
              borderRadius: '14px',
              padding: '16px',
              marginBottom: '14px',
            }}
          >
            <div
              style={{
                fontSize: '14.5px',
                fontWeight: 700,
                color: '#fbbf24',
                marginBottom: '6px',
              }}
            >
              📷 {SAFETY_STRINGS_FA.qrTechFailureTitle}
            </div>
            <p
              style={{
                fontSize: '12px',
                lineHeight: '1.75',
                color: '#fde68a',
                marginBottom: '8px',
              }}
            >
              {SAFETY_STRINGS_FA.qrTechFailureBody}
            </p>
            {techErrorDetail && (
              <div
                style={{
                  background: 'rgba(0,0,0,0.25)',
                  padding: '8px 10px',
                  borderRadius: '8px',
                  fontSize: '11.5px',
                  color: '#fef3c7',
                  marginBottom: '12px',
                }}
              >
                جزئیات فنی: {techErrorDetail}
              </div>
            )}
            <div className="modal-btns">
              <button type="button" onClick={startCameraScanner}>
                {SAFETY_STRINGS_FA.tryAgain}
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setMode('MAIN')}
              >
                {SAFETY_STRINGS_FA.readOutComparison}
              </button>
            </div>
          </div>
        ) : mode === 'SCANNING' ? (
          /* IN-APP CAMERA QR SCANNER VIEW */
          <div
            style={{
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '14px',
              padding: '14px',
              marginBottom: '14px',
            }}
          >
            <div
              style={{
                fontSize: '13.5px',
                fontWeight: 700,
                color: '#c4b5fd',
                marginBottom: '8px',
                textAlign: 'center',
              }}
            >
              📷 اسکن حضوری کد QR مخاطب (@{contactUsername})
            </div>
            <div
              style={{
                position: 'relative',
                width: '100%',
                maxWidth: '280px',
                height: '220px',
                margin: '0 auto 10px',
                background: '#000',
                borderRadius: '12px',
                overflow: 'hidden',
                border: '2px solid rgba(124, 58, 237, 0.5)',
              }}
            >
              <video
                ref={videoRef}
                playsInline
                muted
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
              />
            </div>

            <div
              style={{
                display: 'flex',
                gap: '8px',
                marginBottom: '10px',
                justifyContent: 'center',
              }}
            >
              <input
                ref={qrFileInputRef}
                type="file"
                accept="image/*"
                style={{ display: 'none' }}
                onChange={handleQrImageUpload}
              />
              <button
                type="button"
                onClick={() => qrFileInputRef.current?.click()}
                style={{
                  background: 'rgba(255,255,255,0.08)',
                  border: '1px solid rgba(255,255,255,0.16)',
                  color: '#e5e7eb',
                  borderRadius: '8px',
                  padding: '6px 12px',
                  fontSize: '11.5px',
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                }}
              >
                🖼️ انتخاب تصویر کد QR
              </button>
            </div>

            <div
              style={{
                borderTop: '1px solid rgba(255,255,255,0.08)',
                paddingTop: '10px',
                marginTop: '6px',
              }}
            >
              <label
                style={{
                  display: 'block',
                  fontSize: '11px',
                  color: '#9ca3af',
                  marginBottom: '4px',
                }}
              >
                یا رشته کد QR اسکن‌شده (<code>PQ-MPRBA-SAFETY-v1:...</code>) را جهت بررسی وارد کنید:
              </label>
              <div style={{ display: 'flex', gap: '6px' }}>
                <input
                  type="text"
                  dir="ltr"
                  placeholder="PQ-MPRBA-SAFETY-v1:..."
                  value={qrInputManual}
                  onChange={e => setQrInputManual(e.target.value)}
                  style={{
                    flex: 1,
                    marginBottom: 0,
                    fontSize: '11.5px',
                    padding: '8px 10px',
                    fontFamily:
                      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  }}
                />
                <button
                  type="button"
                  onClick={() => evaluateScannedQrString(qrInputManual)}
                  style={{
                    background: 'var(--accent)',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#fff',
                    padding: '0 12px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                    fontWeight: 600,
                  }}
                >
                  بررسی
                </button>
              </div>
            </div>

            <div className="modal-btns" style={{ marginTop: '12px' }}>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => {
                  stopCamera();
                  setMode('MAIN');
                }}
              >
                {SAFETY_STRINGS_FA.cancel}
              </button>
            </div>
          </div>
        ) : (
          /* MAIN VERIFICATION VIEW: 60-DIGIT READ-OUT + QR CODE */
          <>
            {/* PLAIN-LANGUAGE EXPLANATION & OUT-OF-BAND WARNING */}
            <div
              style={{
                background: 'rgba(124, 58, 237, 0.1)',
                border: '1px solid rgba(124, 58, 237, 0.3)',
                borderRadius: '10px',
                padding: '10px 12px',
                fontSize: '11.5px',
                lineHeight: '1.7',
                color: '#e5e7eb',
                marginBottom: '10px',
              }}
            >
              <div>{SAFETY_STRINGS_FA.explanationText}</div>
              <div
                style={{
                  marginTop: '6px',
                  paddingTop: '6px',
                  borderTop: '1px solid rgba(124, 58, 237, 0.25)',
                  color: '#fde047',
                  fontWeight: 600,
                }}
              >
                ⚠️ {SAFETY_STRINGS_FA.outOfBandWarning}
              </div>
            </div>

            {/* 60-DIGIT NUMBER IN 12 GROUPS OF 5 (LTR, MONOSPACED, TAPPABLE MEMORY AID) */}
            <div
              style={{
                background: 'rgba(0, 0, 0, 0.28)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '12px',
                padding: '12px',
                marginBottom: '12px',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '8px',
                }}
              >
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#c4b5fd' }}>
                  🔢 شماره ایمنی ۶۰ رقمی (۱۲ گروه ۵ رقمی):
                </span>
                <span style={{ fontSize: '11px', color: '#9ca3af' }}>
                  بررسی‌شده: {checkedGroups.filter(Boolean).length} / 12
                </span>
              </div>

              <div
                dir="ltr"
                id="safetyNumberDigitsGrid"
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, 1fr)',
                  gap: '7px',
                  fontFamily:
                    'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  direction: 'ltr',
                  textAlign: 'center',
                  marginBottom: '8px',
                }}
              >
                {safetyData.groups12.map((groupDigits, idx) => {
                  const isChecked = checkedGroups[idx];
                  return (
                    <button
                      key={idx}
                      type="button"
                      dir="ltr"
                      onClick={() => handleToggleGroupCheck(idx)}
                      title="برای علامت‌گذاری کمکی هنگام روخوانی کلیک کنید (به‌تنهایی باعث تأیید نمی‌شود)"
                      style={{
                        fontFamily:
                          'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                        fontSize: '14px',
                        fontWeight: 700,
                        letterSpacing: '1px',
                        padding: '8px 4px',
                        borderRadius: '8px',
                        cursor: 'pointer',
                        border: isChecked
                          ? '1px solid rgba(34, 197, 94, 0.65)'
                          : '1px solid rgba(255, 255, 255, 0.12)',
                        background: isChecked
                          ? 'rgba(34, 197, 94, 0.18)'
                          : 'rgba(255, 255, 255, 0.05)',
                        color: isChecked ? '#86efac' : '#f9fafb',
                        transition: '0.15s',
                      }}
                    >
                      {groupDigits}
                    </button>
                  );
                })}
              </div>

              <div
                style={{
                  fontSize: '10.5px',
                  color: '#9ca3af',
                  lineHeight: '1.55',
                  marginBottom: '8px',
                }}
              >
                💡 {SAFETY_STRINGS_FA.memoryAidHint}
              </div>

              {/* COPY & PASTE-COMPARE (IGNORING SPACES) */}
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={handleCopySafetyNumber}
                  style={{
                    background: 'rgba(255,255,255,0.08)',
                    border: '1px solid rgba(255,255,255,0.15)',
                    borderRadius: '8px',
                    padding: '6px 12px',
                    fontSize: '12px',
                    color: '#e5e7eb',
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                  }}
                >
                  📋 {SAFETY_STRINGS_FA.copySafetyNumber}
                </button>
                <div style={{ display: 'flex', gap: '4px', flex: 1, minWidth: '180px' }}>
                  <input
                    type="text"
                    dir="ltr"
                    placeholder="تست تطابق عدد کپی‌شده (فاصله‌ها نادیده گرفته می‌شوند)..."
                    value={pasteCompareInput}
                    onChange={e => setPasteCompareInput(e.target.value)}
                    style={{
                      flex: 1,
                      marginBottom: 0,
                      padding: '6px 9px',
                      fontSize: '11px',
                      borderRadius: '8px',
                      fontFamily:
                        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                    }}
                  />
                  {pasteCompareInput.trim() && (
                    <button
                      type="button"
                      onClick={handleComparePastedDigits}
                      style={{
                        background: 'rgba(124, 58, 237, 0.3)',
                        border: '1px solid rgba(124, 58, 237, 0.5)',
                        borderRadius: '8px',
                        padding: '0 10px',
                        fontSize: '11px',
                        color: '#ddd6fe',
                        cursor: 'pointer',
                        fontFamily: 'inherit',
                      }}
                    >
                      مقایسه
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* QR CODE DISPLAY */}
            <div
              style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.09)',
                borderRadius: '12px',
                padding: '12px',
                textAlign: 'center',
                marginBottom: '14px',
              }}
            >
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  color: '#d1d5db',
                  marginBottom: '8px',
                }}
              >
                کد QR شماره ایمنی (جهت اسکن حضوری توسط دستگاه مقابل)
              </div>
              {qrMatrix && (
                <div
                  style={{
                    background: '#ffffff',
                    padding: '10px',
                    borderRadius: '10px',
                    display: 'inline-block',
                    marginBottom: '6px',
                  }}
                >
                  <svg
                    width="168"
                    height="168"
                    viewBox={`0 0 ${qrMatrix.length + 4} ${qrMatrix.length + 4}`}
                    shapeRendering="crispEdges"
                    role="img"
                    aria-label={`QR Code ${safetyData.qrPayload}`}
                  >
                    <rect
                      width={qrMatrix.length + 4}
                      height={qrMatrix.length + 4}
                      fill="#ffffff"
                    />
                    {qrMatrix.map((row, rIdx) =>
                      row.map((cell, cIdx) =>
                        cell ? (
                          <rect
                            key={`${rIdx}-${cIdx}`}
                            x={cIdx + 2}
                            y={rIdx + 2}
                            width={1}
                            height={1}
                            fill="#000000"
                          />
                        ) : null
                      )
                    )}
                  </svg>
                </div>
              )}
              <div
                dir="ltr"
                style={{
                  fontFamily:
                    'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  fontSize: '10px',
                  color: '#9ca3af',
                  wordBreak: 'break-all',
                  padding: '0 6px',
                }}
              >
                {safetyData.qrPayload}
              </div>
            </div>

            {/* PRIMARY VERIFICATION ACTIONS */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div className="modal-btns">
                <button
                  type="button"
                  id="numbersMatchVerifyBtn"
                  onClick={handleNumbersMatchAction}
                  style={{
                    background: 'linear-gradient(135deg, #16a34a, #059669)',
                  }}
                >
                  ✓ {SAFETY_STRINGS_FA.numbersMatch} (
                  {verificationRecord.state === 'CHANGED'
                    ? SAFETY_STRINGS_FA.verifyAgain
                    : SAFETY_STRINGS_FA.verifyContact}
                  )
                </button>
                <button
                  type="button"
                  id="scanContactQrBtn"
                  onClick={startCameraScanner}
                >
                  📷 {SAFETY_STRINGS_FA.scanContactCode}
                </button>
              </div>

              {verificationRecord.state === 'VERIFIED' && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: 'rgba(34, 197, 94, 0.1)',
                    border: '1px solid rgba(34, 197, 94, 0.25)',
                    borderRadius: '8px',
                    padding: '6px 10px',
                    fontSize: '11px',
                    color: '#86efac',
                  }}
                >
                  <span>
                    تأیید شده در این دستگاه:{' '}
                    {verificationRecord.verifiedAt
                      ? formatAuditDate(verificationRecord.verifiedAt)
                      : 'هم‌اکنون'}
                  </span>
                  <button
                    type="button"
                    onClick={handleResetVerification}
                    style={{
                      background: 'rgba(255,255,255,0.08)',
                      border: '1px solid rgba(255,255,255,0.15)',
                      color: '#d1d5db',
                      borderRadius: '6px',
                      padding: '3px 8px',
                      fontSize: '10.5px',
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    {SAFETY_STRINGS_FA.resetToUnverified}
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
};
