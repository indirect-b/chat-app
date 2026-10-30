/**
 * ============================================================================
 * ماژول شماره‌های ایمنی پساکوانتومی — Safety Numbers (Spec v0.1 / PQ-MPRBA-SAFETY-v1)
 * ============================================================================
 *
 * [CRITICAL SECURITY NOTE & KEM-BINDING LIMITATION — VERIFIED FROM CLIENT CODE]
 *
 * این شماره ایمنی (Safety Number) صرفاً کلیدهای عمومی امضای دیجیتال هویت پساکوانتومی
 * ML-DSA-65 (FIPS 204) دو طرف مکالمه را اصالت‌سنجی (Authenticate) می‌کند و هیچ کلید
 * کپسوله‌سازی (ML-KEM-768)، کلید کلاسیک (ECDH P-256)، کلید نشست (Session Key) یا کلید پیام
 * را در محاسبه هش وارد نمی‌کند.
 *
 * وضعیت فعلی پیوند امضای ML-DSA-65 با کلید کپسوله‌سازی ML-KEM-768 در کد کلاینت (`src/utils/crypto.ts`):
 * ۱. در مسیر تولید باندل (`ensureUserHybridKeyPair` خطوط ۲۷۳ تا ۳۹۲) و اعتبارسنجی باندل
 *    (`parsePeerKeyBundle` خطوط ۴۱۲ تا ۴۹۳)، کلاینت رشتهٔ
 *    `MLDSA-BUNDLE-v2:<username>:<crv>:<x>:<y>:<mlkemPubB64>` را با کلید خصوصی ML-DSA-65 امضا
 *    و با `ml_dsa65.verify` بررسی می‌کند و در مسیر ارسال پیام جدید (`encryptMessageText` خط ۱۳۵۴)
 *    صحت `peerBundle.isFullyPostQuantum` را پیش از کپسوله‌سازی با کلید `mlkemPub` بررسی می‌نماید.
 * ۲. محدودیت شناخته‌شده (Known Limitation در کد موجود بدون تغییر پروتکل):
 *    - در مسیر دریافت/رمزگشایی (`decryptMessageText` خطوط ۱۵۳۰ تا ۱۵۹۶ و `ensurePQRatchetSession`
 *      خطوط ۷۵۰ تا ۹۱۹)، شرط خط ۷۶۷ (`if (!bundle.isFullyPostQuantum && !existing && !incomingKemCipherB64)`)
 *      هنگام وجود `incomingKemCipherB64` یا وجود نشست قبلی (`existing`) در حافظه محلی دور زده می‌شود.
 *      در نتیجه، در دریافت پیام‌های `e2ee:pq:v2:` یا در مسیر Fallback بازتولید کپسول (خط ۷۹۳ و خط ۸۶۸)،
 *      کلاینت پیش از پذیرش کپسول یا استفاده از `mlkemPub`، معتبر بودن امضای ML-DSA-65 باندل
 *      (`isFullyPostQuantum`) یا امضای پیام (`mldsaVerified`) را به‌صورت مسدودکننده (Hard Requirement)
 *      الزام نمی‌کند.
 *    - همچنین در `parsePeerKeyBundle` (خطوط ۴۶۳ تا ۴۷۰)، اگر فیلد `username` در باندل JSON خالی باشد،
 *      اعتبارسنجی با رشتهٔ نام کاربری تهی (`""`) انجام می‌شود.
 *
 * بنابراین، شماره ایمنی به‌تنهایی فقط کلید هویت ML-DSA-65 را تأیید می‌کند و تا زمانی که محدودیت‌های
 * فوق در لایهٔ پروتکل برطرف نشوند، تأیید شماره ایمنی در تمامی مسیرهای رمزگشایی/بازتولید نشست،
 * تضمین‌کنندهٔ کامل اصالت کلید کپسوله‌سازی ML-KEM-768 نیست.
 * ============================================================================
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  base64ToBuf,
  bufToBase64,
  getMyMLDSAPublicKey,
  parsePeerKeyBundle,
} from './crypto';

export const SAFETY_PROTOCOL_ID = 'PQ-MPRBA-SAFETY-v1';
export const SAFETY_QR_PREFIX = 'PQ-MPRBA-SAFETY-v1:';

const VERIFICATION_STORAGE_PREFIX = 'chat_safety_verifications_v1_';

export type VerificationState = 'UNVERIFIED' | 'VERIFIED' | 'CHANGED';

/**
 * رشته‌های فارسی رابط کاربری برای قابلیت شماره ایمنی (Spec v0.1)
 */
export const SAFETY_STRINGS_FA = {
  safetyNumber: 'شماره ایمنی',
  verifyContact: 'تأیید هویت مخاطب',
  notVerified: 'تأیید نشده',
  verified: 'تأیید شده',
  safetyNumberChanged: 'شماره ایمنی تغییر کرده است',
  verifyAgain: 'تأیید مجدد',
  learnMore: 'بیشتر بدانید',
  numbersMatch: 'اعداد مطابقت دارند',
  scanContactCode: 'اسکن کد مخاطب',
  verifyFirst: 'ابتدا تأیید هویت کنید',
  sendAnyway: 'ارسال به هر حال',
  cancel: 'انصراف',
  tryAgain: 'تلاش مجدد',
  readOutComparison: 'مقایسه خوانشی اعداد',
  copySafetyNumber: 'کپی شماره ایمنی',
  copiedToast: 'شماره ایمنی در حافظه کپی شد',
  confirmVerifyOnDevice: 'تأیید نهایی هویت در این دستگاه',
  resetToUnverified: 'لغو وضعیت تأیید (بازگشت به تأیید نشده)',

  // خلاصه وضعیت گروه‌ها
  groupAllVerified: 'همه اعضای گروه تأیید شده‌اند',
  groupMemberChanged: 'کلید یکی از اعضا تغییر کرده است',
  groupSomeUnverified: 'برخی از اعضا تأیید نشده‌اند',

  // توضیحات و هشدارها
  explanationText:
    'شماره ایمنی فقط از کلیدهای عمومی امضای هویت پساکوانتومی (ML-DSA-65) شما و این مخاطب محاسبه می‌شود. وضعیت تأیید صرفاً روی همین دستگاه ذخیره شده و هرگز به سرور ارسال یا در نسخه‌های پشتیبان ذخیره نمی‌شود.',
  outOfBandWarning:
    'هشدار مهم: ارسال یا دریافت شماره ایمنی از طریق همین پیام‌رسان یا هر کانال تحت کنترل سرور هیچ اعتباری ندارد. مقایسه اعداد باید حتماً به‌صورت حضوری یا از طریق یک کانال ارتباطی مستقل و مورد اطمینان (مانند تماس تلفنی/تصویری مستقیم با شناخت صدای مخاطب) انجام شود.',
  memoryAidHint:
    'تیک زدن هر گروه ۵ رقمی صرفاً یک ابزار کمکی برای خاطرجمع شدن هنگام روخوانی اعداد است و به‌تنهایی باعث تأیید هویت نمی‌شود. پس از اطمینان از برابری هر ۱۲ گروه، دکمه «اعداد مطابقت دارند» را بزنید.',
  inChatChangedNoticeTitle: 'هشدار امنیتی: شماره ایمنی این مخاطب تغییر کرده است',
  inChatChangedNoticeBody:
    'کلید هویت پساکوانتومی (ML-DSA-65) این مخاطب تغییر کرده است. تا زمان بررسی و تأیید مجدد، وضعیت تأیید قبلی لغو شده است.',
  learnMoreBenignAndRisk:
    'علت‌های احتمالی تغییر کلید هویت:\n۱. دلایل عادی (غیرخصمانه): ممکن است مخاطب برنامه را دوباره نصب کرده باشد، دستگاه جدیدی به کار گرفته باشد یا کلیدهای حساب خود را بازتولید کرده باشد.\n۲. خطر جعل هویت (Impersonation / MITM): ممکن است شخص ثالث یا سرور میانی در حال تلاش برای جایگزینی کلید هویت و شنود یا جعل هویت مخاطب باشد.\nسامانه نمی‌تواند حدس بزند کدام حالت رخ داده است؛ بنابراین لازم است پیش از ادامه تبادل اطلاعات حساس، شماره ایمنی جدید را به‌صورت حضوری یا از طریق یک کانال امن و مستقل با مخاطب مقایسه و تأیید مجدد کنید.',
  outgoingChangedDialogTitle: 'هشدار تغییر شماره ایمنی پیش از ارسال پیام',
  outgoingChangedDialogBody:
    'شماره ایمنی هویت پساکوانتومی (ML-DSA-65) این مخاطب تغییر کرده و هنوز تأیید مجدد نشده است. آیا می‌خواهید ابتدا هویت مخاطب را بررسی و تأیید کنید یا فقط همین پیام را ارسال می‌کنید؟ توجه: انتخاب «ارسال به هر حال» صرفاً همین یک پیام را ارسال می‌کند، وضعیت را «شماره ایمنی تغییر کرده است» باقی می‌گذارد و به هیچ عنوان به معنای تأیید هویت نیست.',
  qrMatchTitle: 'تطابق کامل کد QR با شماره ایمنی',
  qrMatchBody:
    'کد QR اسکن‌شده دقیقاً با شماره ایمنی محاسبه‌شده برای این مخاطب مطابقت دارد. آیا مایلید وضعیت این مخاطب را فقط روی همین دستگاه به «تأیید شده» تغییر دهید؟ توجه: طرف مقابل نیز باید کد QR شما را با دستگاه خودش اسکن کند تا هویت شما در دستگاه او نیز تأیید شود.',
  qrMismatchTitle: 'عدم تطابق شماره ایمنی! (هشدار امنیتی جدی)',
  qrMismatchBody:
    'کد اسکن‌شده یا شماره مقایسه‌شده با شماره ایمنی محاسبه‌شده برای این مخاطب مطابقت ندارد! این وضعیت می‌تواند نشانه خطر جعل هویت یا حمله مرد میانی (MITM) باشد. هرگز به این کلید اعتماد نکنید؛ وضعیت مخاطب تأیید نخواهد شد.',
  qrTechFailureTitle: 'خطای فنی در اسکن یا خواندن کد QR',
  qrTechFailureBody:
    'دسترسی به دوربین امکان‌پذیر نبود یا ساختار کد اسکن‌شده در قالب معتبر PQ-MPRBA-SAFETY-v1 قابل خواندن نیست. این یک خطای فنی است و به معنای عدم تطابق کلیدها نیست. می‌توانید دوباره تلاش کنید یا از روش مقایسه خوانشی ۱۲ گروه ۵ رقمی استفاده نمایید.',
  rekeyDistinctNote:
    'توجه: بازنشانی یا تغییر کلید نشست رمزنگاری (Session Key) فقط کلیدهای رمزنگاری پیام‌ها را نوسازی می‌کند و هیچ تغییری در شماره ایمنی یا وضعیت تأیید هویت مخاطب ایجاد نمی‌کند.',
} as const;

export interface ContactKeyAuditEntry {
  previousKeyFingerprint: string;
  previousKeyB64: string;
  detectedAt: number;
}

export interface ContactVerificationRecord {
  contactUsername: string;
  state: VerificationState;
  knownMldsaPubB64: string | null;
  verifiedMldsaPubB64: string | null;
  verifiedAt: number | null;
  changedAt: number | null;
  auditHistory: ContactKeyAuditEntry[];
}

export interface SafetyNumberData {
  digits60: string;
  groups12: string[];
  formattedDisplay: string;
  sha256Hex: string;
  qrPayload: string;
  myKeyFingerprint: string;
  peerKeyFingerprint: string;
  myMldsaPubB64: string;
  peerMldsaPubB64: string;
}

export interface QrComparisonResult {
  status: 'MATCH' | 'MISMATCH' | 'PARSE_ERROR';
  scannedHex?: string;
  scannedDigits60?: string;
  scannedGroups12?: string[];
  scannedFormatted?: string;
  errorReason?: string;
}

export interface GroupVerificationSummary {
  status: 'ALL_VERIFIED' | 'MEMBER_CHANGED' | 'SOME_UNVERIFIED';
  summaryText: string;
  changedMembers: string[];
  memberRecords: Record<string, ContactVerificationRecord>;
}

/**
 * تبدیل آرایه بایت به رشته هگزادسیمال با حروف کوچک لاتین
 */
export function bytesToLowerHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * محاسبه اثر انگشت کوتاه و کامل (SHA-256 Hex) از کلید عمومی ML-DSA-65
 */
export function computeKeyFingerprintHex(rawKeyBytes: Uint8Array): string {
  return bytesToLowerHex(sha256(rawKeyBytes));
}

/**
 * استخراج بایت‌های خام کلید عمومی ML-DSA-65 کاربر فعلی
 * کدگذاری متعارف (Canonical Encoding): کلید عمومی در کلاینت به‌صورت رشته Base64 استاندارد
 * از آرایه بایت خام ۱۹۵۲ بایتی FIPS 204 ML-DSA-65 ذخیره می‌شود و پیش از هش به بایت‌های خام تبدیل می‌گردد.
 */
export function extractMyMldsaPublicKeyBytes(
  myUsername: string
): { rawBytes: Uint8Array; base64: string } | null {
  const b64 = getMyMLDSAPublicKey(myUsername);
  if (!b64) return null;
  try {
    const rawBytes = base64ToBuf(b64);
    if (!rawBytes || rawBytes.byteLength === 0) return null;
    return { rawBytes, base64: b64 };
  } catch {
    return null;
  }
}

/**
 * استخراج بایت‌های خام کلید عمومی ML-DSA-65 مخاطب از باندل کلید عمومی ذخیره/دریافت‌شده
 */
export function extractPeerMldsaPublicKeyBytes(
  peerPublicKeyStr: string | null | undefined,
  expectedPeerUsername?: string
): { rawBytes: Uint8Array; base64: string } | null {
  if (!peerPublicKeyStr) return null;
  const parsed = parsePeerKeyBundle(peerPublicKeyStr, expectedPeerUsername);
  if (!parsed.hasMLDSA || !parsed.mldsaPub || parsed.mldsaPub.byteLength === 0) {
    return null;
  }
  return {
    rawBytes: parsed.mldsaPub,
    base64: bufToBase64(parsed.mldsaPub),
  };
}

/**
 * مقایسه لغت‌نامه‌ای (Lexicographical) دو آرایه بایت خام بدون علامت
 */
export function compareRawBytesLexicographically(a: Uint8Array, b: Uint8Array): number {
  const minLen = Math.min(a.byteLength, b.byteLength);
  for (let i = 0; i < minLen; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  if (a.byteLength === b.byteLength) return 0;
  return a.byteLength < b.byteLength ? -1 : 1;
}

/**
 * نوشتن طول کلید به‌صورت ۴ بایت Big-Endian
 */
function encodeUint32BE(length: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (length >>> 24) & 0xff;
  buf[1] = (length >>> 16) & 0xff;
  buf[2] = (length >>> 8) & 0xff;
  buf[3] = length & 0xff;
  return buf;
}

/**
 * تبدیل هش ۶۴ کاراکتری هگزادسیمال SHA-256 به عدد ۶۰ رقمی لاتین (mod 10^60) در ۱۲ گروه ۵ رقمی
 */
export function hexDigestTo60Digits(sha256Hex: string): {
  digits60: string;
  groups12: string[];
  formattedDisplay: string;
} {
  const cleanHex = sha256Hex.trim().toLowerCase();
  const hashInt = BigInt('0x' + cleanHex);
  const mod10Pow60 = 10n ** 60n;
  const safetyInt = hashInt % mod10Pow60;
  const digits60 = safetyInt.toString(10).padStart(60, '0');
  const groups12: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    groups12.push(digits60.slice(i, i + 5));
  }
  return {
    digits60,
    groups12,
    formattedDisplay: groups12.join(' '),
  };
}

/**
 * محاسبه قطعی شماره ایمنی از بایت‌های خام کلیدهای عمومی ML-DSA-65 دو طرف:
 * SHA-256( "PQ-MPRBA-SAFETY-v1" || 0x00 || lenBE32(key1) || key1 || lenBE32(key2) || key2 )
 * که در آن [key1, key2] بر اساس بایت‌های خام به‌صورت Lexicographical مرتب شده‌اند.
 */
export function computeSafetyNumberFromRawKeys(
  myRawKey: Uint8Array,
  peerRawKey: Uint8Array
): Omit<SafetyNumberData, 'myMldsaPubB64' | 'peerMldsaPubB64'> {
  const domainBytes = new TextEncoder().encode(SAFETY_PROTOCOL_ID);
  const cmp = compareRawBytesLexicographically(myRawKey, peerRawKey);
  const firstKey = cmp <= 0 ? myRawKey : peerRawKey;
  const secondKey = cmp <= 0 ? peerRawKey : myRawKey;

  const firstLenBE = encodeUint32BE(firstKey.byteLength);
  const secondLenBE = encodeUint32BE(secondKey.byteLength);

  // "PQ-MPRBA-SAFETY-v1" + 0x00 + len(firstKey) + firstKey + len(secondKey) + secondKey
  const totalLen =
    domainBytes.byteLength +
    1 +
    4 +
    firstKey.byteLength +
    4 +
    secondKey.byteLength;

  const preimage = new Uint8Array(totalLen);
  let offset = 0;
  preimage.set(domainBytes, offset);
  offset += domainBytes.byteLength;
  preimage[offset] = 0x00;
  offset += 1;
  preimage.set(firstLenBE, offset);
  offset += 4;
  preimage.set(firstKey, offset);
  offset += firstKey.byteLength;
  preimage.set(secondLenBE, offset);
  offset += 4;
  preimage.set(secondKey, offset);

  const digest = sha256(preimage);
  const sha256Hex = bytesToLowerHex(digest);
  const { digits60, groups12, formattedDisplay } = hexDigestTo60Digits(sha256Hex);

  return {
    digits60,
    groups12,
    formattedDisplay,
    sha256Hex,
    qrPayload: `${SAFETY_QR_PREFIX}${sha256Hex}`,
    myKeyFingerprint: computeKeyFingerprintHex(myRawKey),
    peerKeyFingerprint: computeKeyFingerprintHex(peerRawKey),
  };
}

/**
 * محاسبه شماره ایمنی برای یک مخاطب مشخص بر اساس کلیدهای ML-DSA-65 موجود
 */
export function computeSafetyNumberForContact(
  myUsername: string,
  peerPublicKeyStr: string | null | undefined,
  peerUsername?: string
): SafetyNumberData | null {
  const myKey = extractMyMldsaPublicKeyBytes(myUsername);
  const peerKey = extractPeerMldsaPublicKeyBytes(peerPublicKeyStr, peerUsername);
  if (!myKey || !peerKey) return null;

  const core = computeSafetyNumberFromRawKeys(myKey.rawBytes, peerKey.rawBytes);
  return {
    ...core,
    myMldsaPubB64: myKey.base64,
    peerMldsaPubB64: peerKey.base64,
  };
}

/**
 * نرمال‌سازی رشته شماره ایمنی هنگام مقایسه کپی/پیست (حذف تمام فاصله‌ها و کاراکترهای جداساز سفید)
 */
export function normalizeSafetyDigits(input: string): string {
  // تبدیل ارقام فارسی/عربی احتمالی در ورودی کاربر به ارقام لاتین و حذف تمام فاصله‌ها
  const persianDigits = '۰۱۲۳۴۵۶۷۸۹';
  const arabicDigits = '٠١٢٣٤٥٦٧٨٩';
  let out = '';
  for (const ch of input) {
    const pIdx = persianDigits.indexOf(ch);
    if (pIdx !== -1) {
      out += String(pIdx);
      continue;
    }
    const aIdx = arabicDigits.indexOf(ch);
    if (aIdx !== -1) {
      out += String(aIdx);
      continue;
    }
    if (!/\s/.test(ch)) {
      out += ch;
    }
  }
  return out;
}

/**
 * مقایسه شماره ایمنی ۶۰ رقمی (با نادیده گرفتن فاصله‌ها طبق اسپک)
 */
export function compareSafetyNumberDigits(
  localDigits60: string,
  otherDigitsInput: string
): {
  validFormat: boolean;
  matches: boolean;
  normalizedOther: string;
  otherGroups12: string[];
} {
  const normalizedOther = normalizeSafetyDigits(otherDigitsInput);
  if (!/^[0-9]{60}$/.test(normalizedOther)) {
    return {
      validFormat: false,
      matches: false,
      normalizedOther,
      otherGroups12: [],
    };
  }
  const otherGroups12: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    otherGroups12.push(normalizedOther.slice(i, i + 5));
  }
  return {
    validFormat: true,
    matches: normalizedOther === localDigits60,
    normalizedOther,
    otherGroups12,
  };
}

/**
 * بررسی و مقایسه محتوای کد QR اسکن‌شده با هش محلی
 * قالب مجاز: PQ-MPRBA-SAFETY-v1:<64 lowercase hex chars>
 */
export function parseAndCompareQrPayload(
  scannedRaw: string,
  expectedSha256Hex: string
): QrComparisonResult {
  const trimmed = (scannedRaw || '').trim();
  if (!trimmed) {
    return {
      status: 'PARSE_ERROR',
      errorReason: 'کد QR خالی یا غیرقابل خواندن است.',
    };
  }

  if (!trimmed.startsWith(SAFETY_QR_PREFIX)) {
    return {
      status: 'PARSE_ERROR',
      errorReason: 'پیشوند کد اسکن‌شده با استاندارد PQ-MPRBA-SAFETY-v1 مطابقت ندارد.',
    };
  }

  const hexPart = trimmed.slice(SAFETY_QR_PREFIX.length);
  if (!/^[0-9a-f]{64}$/.test(hexPart)) {
    return {
      status: 'PARSE_ERROR',
      errorReason: 'ساختار هش ۶۴ کاراکتری (SHA-256 lowercase hex) در کد QR نامعتبر است.',
    };
  }

  const { digits60, groups12, formattedDisplay } = hexDigestTo60Digits(hexPart);
  const expectedClean = expectedSha256Hex.trim().toLowerCase();

  if (hexPart === expectedClean) {
    return {
      status: 'MATCH',
      scannedHex: hexPart,
      scannedDigits60: digits60,
      scannedGroups12: groups12,
      scannedFormatted: formattedDisplay,
    };
  }

  return {
    status: 'MISMATCH',
    scannedHex: hexPart,
    scannedDigits60: digits60,
    scannedGroups12: groups12,
    scannedFormatted: formattedDisplay,
  };
}

// ============================================================================
// مدیریت وضعیت تأیید هویت مخاطبین (صرفاً محلی در این دستگاه — LocalStorage Only)
// ============================================================================

function loadAllVerificationRecords(
  myUsername: string
): Record<string, ContactVerificationRecord> {
  if (!myUsername) return {};
  try {
    const raw = localStorage.getItem(`${VERIFICATION_STORAGE_PREFIX}${myUsername}`);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function saveAllVerificationRecords(
  myUsername: string,
  records: Record<string, ContactVerificationRecord>
): void {
  if (!myUsername) return;
  try {
    localStorage.setItem(
      `${VERIFICATION_STORAGE_PREFIX}${myUsername}`,
      JSON.stringify(records)
    );
  } catch {
    // ignore storage quota errors
  }
}

/**
 * دریافت وضعیت فعلی تأیید هویت یک مخاطب در این دستگاه
 */
export function getContactVerificationRecord(
  myUsername: string,
  contactUsername: string
): ContactVerificationRecord {
  const normContact = String(contactUsername || '').trim();
  const all = loadAllVerificationRecords(myUsername);
  const existing = all[normContact];
  if (existing) {
    return {
      contactUsername: normContact,
      state: existing.state || 'UNVERIFIED',
      knownMldsaPubB64: existing.knownMldsaPubB64 || null,
      verifiedMldsaPubB64: existing.verifiedMldsaPubB64 || null,
      verifiedAt: existing.verifiedAt || null,
      changedAt: existing.changedAt || null,
      auditHistory: Array.isArray(existing.auditHistory) ? existing.auditHistory : [],
    };
  }
  return {
    contactUsername: normContact,
    state: 'UNVERIFIED',
    knownMldsaPubB64: null,
    verifiedMldsaPubB64: null,
    verifiedAt: null,
    changedAt: null,
    auditHistory: [],
  };
}

/**
 * مشاهده و پایش کلید عمومی ML-DSA-65 مخاطب جهت تشخیص فوری تغییر کلید هویت (Change Detection).
 * قوانین اسپک:
 * - اگر مخاطب قبلاً کلید ML-DSA-65 شناخته‌شده‌ای داشته و کلید جدید با آن متفاوت باشد:
 *   بلافاصله وضعیت به `CHANGED` تغییر می‌کند، وضعیت `VERIFIED` پاک می‌شود (و هرگز به‌صورت خودکار
 *   حتی در صورت بازگشت به کلید قبلی بازیابی نمی‌شود)، و اثر انگشت و تاریخ کلید قبلی برای ممیزی محلی ذخیره می‌گردد.
 */
export function observeContactPublicKey(
  myUsername: string,
  contactUsername: string,
  peerPublicKeyStr: string | null | undefined
): ContactVerificationRecord {
  const normContact = String(contactUsername || '').trim();
  const currentRecord = getContactVerificationRecord(myUsername, normContact);
  if (!normContact || !myUsername) return currentRecord;

  const extracted = extractPeerMldsaPublicKeyBytes(peerPublicKeyStr, normContact);
  if (!extracted) {
    return currentRecord;
  }

  const all = loadAllVerificationRecords(myUsername);
  const newKeyB64 = extracted.base64;

  // اولین بار که کلید ML-DSA-65 این مخاطب در این دستگاه دیده می‌شود
  if (!currentRecord.knownMldsaPubB64) {
    const initialized: ContactVerificationRecord = {
      ...currentRecord,
      knownMldsaPubB64: newKeyB64,
      state: currentRecord.state === 'CHANGED' ? 'CHANGED' : 'UNVERIFIED',
    };
    all[normContact] = initialized;
    saveAllVerificationRecords(myUsername, all);
    return initialized;
  }

  // اگر کلید هویت ML-DSA-65 مخاطب نسبت به آخرین کلید ذخیره‌شده تغییر کرده باشد
  if (currentRecord.knownMldsaPubB64 !== newKeyB64) {
    let prevFingerprint = 'unknown';
    try {
      const prevBytes = base64ToBuf(currentRecord.knownMldsaPubB64);
      prevFingerprint = computeKeyFingerprintHex(prevBytes);
    } catch {
      prevFingerprint = 'unknown';
    }

    const now = Date.now();
    const auditEntry: ContactKeyAuditEntry = {
      previousKeyFingerprint: prevFingerprint,
      previousKeyB64: currentRecord.knownMldsaPubB64,
      detectedAt: now,
    };

    const updated: ContactVerificationRecord = {
      contactUsername: normContact,
      state: 'CHANGED',
      knownMldsaPubB64: newKeyB64,
      verifiedMldsaPubB64: null, // پاک کردن کامل VERIFIED؛ هرگز به‌طور خودکار بازیابی نمی‌شود
      verifiedAt: null,
      changedAt: now,
      auditHistory: [auditEntry, ...(currentRecord.auditHistory || [])].slice(0, 25),
    };

    all[normContact] = updated;
    saveAllVerificationRecords(myUsername, all);
    return updated;
  }

  return currentRecord;
}

/**
 * ثبت صریح وضعیت `VERIFIED` برای کلید فعلی ML-DSA-65 مخاطب (صرفاً پس از تأیید صریح کاربر در این دستگاه)
 */
export function markContactVerified(
  myUsername: string,
  contactUsername: string,
  peerPublicKeyStr: string | null | undefined
): ContactVerificationRecord | null {
  const normContact = String(contactUsername || '').trim();
  if (!myUsername || !normContact) return null;

  const extracted = extractPeerMldsaPublicKeyBytes(peerPublicKeyStr, normContact);
  if (!extracted) return null;

  const currentRecord = getContactVerificationRecord(myUsername, normContact);
  const now = Date.now();
  const updated: ContactVerificationRecord = {
    ...currentRecord,
    contactUsername: normContact,
    state: 'VERIFIED',
    knownMldsaPubB64: extracted.base64,
    verifiedMldsaPubB64: extracted.base64,
    verifiedAt: now,
  };

  const all = loadAllVerificationRecords(myUsername);
  all[normContact] = updated;
  saveAllVerificationRecords(myUsername, all);
  return updated;
}

/**
 * بازگرداندن دستی وضعیت مخاطب به `UNVERIFIED`
 */
export function resetContactVerificationToUnverified(
  myUsername: string,
  contactUsername: string
): ContactVerificationRecord {
  const normContact = String(contactUsername || '').trim();
  const currentRecord = getContactVerificationRecord(myUsername, normContact);
  const updated: ContactVerificationRecord = {
    ...currentRecord,
    state: 'UNVERIFIED',
    verifiedMldsaPubB64: null,
    verifiedAt: null,
  };
  const all = loadAllVerificationRecords(myUsername);
  all[normContact] = updated;
  saveAllVerificationRecords(myUsername, all);
  return updated;
}

/**
 * محاسبه خلاصه وضعیت تأیید اعضای گروه (بدون هیچ‌گونه شماره ایمنی گروهی یا تأیید کلی گروه)
 * قوانین اسپک:
 * - "All members verified" (`همه اعضای گروه تأیید شده‌اند`) فقط اگر تمام اعضای فعلی (غیر از خود کاربر) در وضعیت `VERIFIED` باشند.
 * - "A member's key has changed" (`کلید یکی از اعضا تغییر کرده است`) اگر هر یک از اعضا در وضعیت `CHANGED` باشد (به همراه لیست آن‌ها).
 * - در غیر این صورت: "Some members not verified" (`برخی از اعضا تأیید نشده‌اند`).
 */
export function getGroupVerificationSummary(
  myUsername: string,
  members: string[]
): GroupVerificationSummary {
  const otherMembers = Array.from(
    new Set((members || []).map(m => String(m || '').trim()).filter(Boolean))
  ).filter(m => m !== myUsername);

  const memberRecords: Record<string, ContactVerificationRecord> = {};
  const changedMembers: string[] = [];

  for (const member of otherMembers) {
    const rec = getContactVerificationRecord(myUsername, member);
    memberRecords[member] = rec;
    if (rec.state === 'CHANGED') {
      changedMembers.push(member);
    }
  }

  if (changedMembers.length > 0) {
    return {
      status: 'MEMBER_CHANGED',
      summaryText: SAFETY_STRINGS_FA.groupMemberChanged,
      changedMembers,
      memberRecords,
    };
  }

  if (
    otherMembers.length > 0 &&
    otherMembers.every(m => memberRecords[m]?.state === 'VERIFIED')
  ) {
    return {
      status: 'ALL_VERIFIED',
      summaryText: SAFETY_STRINGS_FA.groupAllVerified,
      changedMembers: [],
      memberRecords,
    };
  }

  return {
    status: 'SOME_UNVERIFIED',
    summaryText: SAFETY_STRINGS_FA.groupSomeUnverified,
    changedMembers: [],
    memberRecords,
  };
}

/**
 * چرخش/بازنشانی صرفاً کلید نشست متقارن (Session Key / Ratchet State) بدون هیچ‌گونه تغییر
 * در کلیدهای هویت (ML-DSA-65)، شماره ایمنی یا وضعیت تأیید هویت مخاطب (طبق بند ۶ اسپک).
 */
export function rotateSessionRatchetOnly(myUsername: string, roomId: string): void {
  if (!myUsername || !roomId) return;
  try {
    localStorage.removeItem(`chat_pq_ratchet_${myUsername}_${roomId}`);
  } catch {
    // ignore
  }
}


// ============================================================================
// تولیدکننده استاندارد کد QR (ISO/IEC 18004 — Version 5, Error Correction Level L)
// برای رشته ۸۳ بایتی `PQ-MPRBA-SAFETY-v1:<64 lowercase hex chars>` بدون وابستگی خارجی
// ============================================================================

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= 0x11d;
    }
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const factor = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], factor);
    }
    poly = next;
  }
  return poly;
}

function rsComputeRemainder(data: Uint8Array, ecCount: number): Uint8Array {
  const gen = rsGeneratorPoly(ecCount);
  const rem = new Uint8Array(ecCount);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecCount - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < ecCount; j++) {
        rem[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }
  return rem;
}

function computeBchFormatBits(ecLevelBits: number, maskPattern: number): number {
  const data = ((ecLevelBits & 0x03) << 3) | (maskPattern & 0x07);
  let rem = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((rem >>> i) & 1) {
      rem ^= 0x537 << (i - 10);
    }
  }
  return ((data << 10) | rem) ^ 0x5412;
}

/**
 * تولید ماتریس بولین کد QR استاندارد (ISO/IEC 18004) برای رشته ورودی (حداکثر ۱۰۶ بایت، نسخه ۵-L)
 */
export function generateQrCodeMatrix(payloadText: string): boolean[][] {
  const utf8 = new TextEncoder().encode(payloadText);
  // Version 5-L: size = 37x37, 108 data codewords, 26 EC codewords (single block)
  const version = 5;
  const size = 17 + version * 4; // 37
  const totalDataBytes = 108;
  const ecBytesCount = 26;

  // ۱. ساخت بیت‌استریم داده (Byte Mode = 0100)
  const bitList: number[] = [];
  const pushBits = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) {
      bitList.push((val >>> i) & 1);
    }
  };

  pushBits(0b0100, 4); // Byte mode
  pushBits(utf8.length, 8); // Character count (8 bits for v1..9)
  for (let i = 0; i < utf8.length; i++) {
    pushBits(utf8[i], 8);
  }
  // Terminator (up to 4 zero bits)
  const maxDataBits = totalDataBytes * 8;
  const termCount = Math.min(4, maxDataBits - bitList.length);
  pushBits(0, termCount);
  while (bitList.length % 8 !== 0) {
    bitList.push(0);
  }

  const dataBytes = new Uint8Array(totalDataBytes);
  for (let i = 0; i < bitList.length / 8; i++) {
    let b = 0;
    for (let bit = 0; bit < 8; bit++) {
      b = (b << 1) | bitList[i * 8 + bit];
    }
    dataBytes[i] = b;
  }

  let padToggle = true;
  for (let i = bitList.length / 8; i < totalDataBytes; i++) {
    dataBytes[i] = padToggle ? 0xec : 0x11;
    padToggle = !padToggle;
  }

  // ۲. محاسبه بایت‌های تصحیح خطای Reed-Solomon
  const ecBytes = rsComputeRemainder(dataBytes, ecBytesCount);
  const allCodewords = new Uint8Array(totalDataBytes + ecBytesCount);
  allCodewords.set(dataBytes, 0);
  allCodewords.set(ecBytes, totalDataBytes);

  // ۳. آماده‌سازی ماتریس و الگوهای عملکردی (Function Patterns)
  const modules: boolean[][] = Array.from({ length: size }, () =>
    Array(size).fill(false)
  );
  const isFunction: boolean[][] = Array.from({ length: size }, () =>
    Array(size).fill(false)
  );

  const setFunctionModule = (r: number, c: number, dark: boolean) => {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      modules[r][c] = dark;
      isFunction[r][c] = true;
    }
  };

  // Finder patterns + separators
  const drawFinder = (topR: number, leftC: number) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = topR + dr;
        const c = leftC + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const onBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const inInner = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunctionModule(r, c, inOuter && (onBorder || inInner));
      }
    }
  };

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Alignment pattern for Version 5 at center (30, 30)
  const alignCenter = 30;
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
      setFunctionModule(alignCenter + dr, alignCenter + dc, dark);
    }
  }

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    const dark = i % 2 === 0;
    if (!isFunction[6][i]) setFunctionModule(6, i, dark);
    if (!isFunction[i][6]) setFunctionModule(i, 6, dark);
  }

  // Dark module and reserved format areas
  setFunctionModule(4 * version + 9, 8, true);
  for (let i = 0; i <= 8; i++) {
    if (!isFunction[8][i]) setFunctionModule(8, i, false);
    if (!isFunction[i][8]) setFunctionModule(i, 8, false);
  }
  for (let i = 0; i < 8; i++) {
    if (!isFunction[8][size - 1 - i]) setFunctionModule(8, size - 1 - i, false);
    if (!isFunction[size - 1 - i][8]) setFunctionModule(size - 1 - i, 8, false);
  }

  // ۴. چیدمان بیت‌های داده و تصحیح خطا به شکل زیگزاگ دو ستونی از راست به چپ
  const totalBits = allCodewords.length * 8;
  let bitIdx = 0;
  let upward = true;

  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) rightCol = 5; // عبور از ستون Timing
    for (let step = 0; step < size; step++) {
      const r = upward ? size - 1 - step : step;
      for (let dc = 0; dc < 2; dc++) {
        const c = rightCol - dc;
        if (!isFunction[r][c]) {
          let dark = false;
          if (bitIdx < totalBits) {
            const byteVal = allCodewords[bitIdx >>> 3];
            dark = ((byteVal >>> (7 - (bitIdx & 7))) & 1) === 1;
            bitIdx++;
          }
          modules[r][c] = dark;
        }
      }
    }
    upward = !upward;
  }

  // ۵. اعمال ماسک و انتخاب بهترین ماسک (Mask 0: (r + c) % 2 === 0) به همراه نوشتن Format Bits
  const maskPattern = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunction[r][c]) {
        if ((r + c) % 2 === 0) {
          modules[r][c] = !modules[r][c];
        }
      }
    }
  }

  // Format bits for EC Level L (01) and mask 0
  const formatBits = computeBchFormatBits(0b01, maskPattern);
  const getFormatBit = (idx: number) => ((formatBits >>> idx) & 1) === 1;

  // Top-left format bits
  for (let i = 0; i <= 5; i++) modules[8][i] = getFormatBit(i);
  modules[8][7] = getFormatBit(6);
  modules[8][8] = getFormatBit(7);
  modules[7][8] = getFormatBit(8);
  for (let i = 9; i < 15; i++) modules[14 - i][8] = getFormatBit(i);

  // Top-right and bottom-left format bits
  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = getFormatBit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = getFormatBit(i);
  modules[size - 8][8] = true; // Always dark module

  return modules;
}

// Sync checkpoint touch: comment only, no functional change.