import axios from 'axios';
import { config } from './config';

const BASE = `${config.BALE_API}${config.BALE_BOT_TOKEN}`;
const BALE_TIMEOUT_MS = 8000;

export interface BaleUpdate {
  update_id: number;
  message?: {
    chat: { id: number | string };
    from: { id: number | string; username?: string };
    text?: string;
  };
}

export interface BaleHealthStatus {
  configured: boolean;
  reachable: boolean;
  consecutiveFailures: number;
  lastCheckedAt: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastErrorMessage: string | null;
}

const baleHealth: BaleHealthStatus = {
  configured: Boolean(config.BALE_BOT_TOKEN),
  reachable: false,
  consecutiveFailures: 0,
  lastCheckedAt: null,
  lastSuccessAt: null,
  lastErrorAt: null,
  lastErrorMessage: null,
};

function recordBaleSuccess(): void {
  const now = new Date().toISOString();
  baleHealth.configured = Boolean(config.BALE_BOT_TOKEN);
  baleHealth.reachable = true;
  baleHealth.consecutiveFailures = 0;
  baleHealth.lastCheckedAt = now;
  baleHealth.lastSuccessAt = now;
  baleHealth.lastErrorMessage = null;
}

function recordBaleFailure(context: string, err: unknown): void {
  const now = new Date().toISOString();
  const message = err instanceof Error ? err.message : String(err || 'Unknown Bale API error');
  baleHealth.configured = Boolean(config.BALE_BOT_TOKEN);
  baleHealth.reachable = false;
  baleHealth.consecutiveFailures += 1;
  baleHealth.lastCheckedAt = now;
  baleHealth.lastErrorAt = now;
  baleHealth.lastErrorMessage = message;
  console.error(
    `[Bale Health] ${now} API failure in ${context} (consecutive=${baleHealth.consecutiveFailures}): ${message}`
  );
}

export function getBaleHealthStatus(): BaleHealthStatus {
  return { ...baleHealth, configured: Boolean(config.BALE_BOT_TOKEN) };
}

/**
 * Active Bale Bot API health probe (GET /getMe).
 * Logs Bale API failures cleanly and updates in-memory health telemetry.
 */
export async function checkBaleHealth(): Promise<BaleHealthStatus> {
  if (!config.BALE_BOT_TOKEN) {
    baleHealth.configured = false;
    baleHealth.reachable = false;
    baleHealth.lastCheckedAt = new Date().toISOString();
    return getBaleHealthStatus();
  }
  try {
    const res = await axios.get(`${BASE}/getMe`, { timeout: 5000 });
    if (res.data && res.data.ok) {
      recordBaleSuccess();
    } else {
      recordBaleFailure('getMe', new Error('Unexpected response from Bale getMe'));
    }
  } catch (e: unknown) {
    recordBaleFailure('getMe', e);
  }
  return getBaleHealthStatus();
}

export async function sendMessage(chatId: string | number, text: string): Promise<boolean> {
  if (!config.BALE_BOT_TOKEN) return false;
  try {
    await axios.post(`${BASE}/sendMessage`, { chat_id: chatId, text }, { timeout: BALE_TIMEOUT_MS });
    recordBaleSuccess();
    return true;
  } catch (e: unknown) {
    recordBaleFailure('sendMessage', e);
    return false;
  }
}

export async function sendPhoto(
  chatId: string | number,
  photoUrl: string,
  caption?: string
): Promise<boolean> {
  if (!config.BALE_BOT_TOKEN) return false;
  try {
    await axios.post(
      `${BASE}/sendPhoto`,
      { chat_id: chatId, photo: photoUrl, caption: caption || '' },
      { timeout: BALE_TIMEOUT_MS }
    );
    recordBaleSuccess();
    return true;
  } catch (e: unknown) {
    recordBaleFailure('sendPhoto', e);
    return false;
  }
}

export async function getUpdates(offset: number): Promise<BaleUpdate[]> {
  if (!config.BALE_BOT_TOKEN) return [];
  try {
    const res = await axios.get(`${BASE}/getUpdates`, {
      params: { offset, timeout: 30 },
      timeout: 35000,
    });
    recordBaleSuccess();
    return res.data.result || [];
  } catch (e: unknown) {
    recordBaleFailure('getUpdates', e);
    return [];
  }
}
