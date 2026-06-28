const axios = require('axios');
const config = require('./config');

const BASE = `${config.BALE_API}${config.BALE_BOT_TOKEN}`;

async function sendMessage(chatId, text) {
  try {
    await axios.post(`${BASE}/sendMessage`, { chat_id: chatId, text });
  } catch (e) {
    console.error('Bale sendMessage error:', e.message);
  }
}

async function sendPhoto(chatId, photoUrl, caption) {
  try {
    await axios.post(`${BASE}/sendPhoto`, { chat_id: chatId, photo: photoUrl, caption: caption || '' });
  } catch (e) {
    console.error('Bale sendPhoto error:', e.message);
  }
}

async function getUpdates(offset) {
  try {
    const res = await axios.get(`${BASE}/getUpdates`, { params: { offset, timeout: 30 } });
    return res.data.result || [];
  } catch (e) {
    return [];
  }
}

module.exports = { sendMessage, sendPhoto, getUpdates };
