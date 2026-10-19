import axios from 'axios';
import { config } from './config';

const BASE = `${config.BALE_API}${config.BALE_BOT_TOKEN}`;

export interface BaleUpdate {
  update_id: number;
  message?: {
    chat: { id: number | string };
    from: { id: number | string; username?: string };
    text?: string;
  };
}

export async function sendMessage(chatId: string | number, text: string): Promise<void> {
  try {
    await axios.post(`${BASE}/sendMessage`, { chat_id: chatId, text });
  } catch (e: any) {
    console.error('Bale sendMessage error:', e.message);
  }
}

export async function sendPhoto(chatId: string | number, photoUrl: string, caption?: string): Promise<void> {
  try {
    await axios.post(`${BASE}/sendPhoto`, { chat_id: chatId, photo: photoUrl, caption: caption || '' });
  } catch (e: any) {
    console.error('Bale sendPhoto error:', e.message);
  }
}

export async function getUpdates(offset: number): Promise<BaleUpdate[]> {
  try {
    const res = await axios.get(`${BASE}/getUpdates`, { params: { offset, timeout: 30 } });
    return res.data.result || [];
  } catch {
    return [];
  }
}
