export interface ServerConfig {
  BALE_BOT_TOKEN: string;
  PORT: number;
  ADMIN_PASSWORD: string;
  ADMIN_PATH: string;
  OTP_EXPIRE: number;
  BALE_API: string;
  MAX_FILE_SIZE: number;
}

const rawToken = process.env.BALE_BOT_TOKEN || '';

export const config: ServerConfig = {
  BALE_BOT_TOKEN: rawToken && rawToken !== 'your_bale_bot_token_here' ? rawToken : '',
  PORT: process.env.DEFAULT_APP_PORT
    ? parseInt(process.env.DEFAULT_APP_PORT, 10)
    : parseInt(process.env.PORT || '3000', 10) || 3000,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'Tk_tokyo',
  ADMIN_PATH: process.env.ADMIN_PATH || '/panel-Tk_tokyo',
  OTP_EXPIRE: parseInt(process.env.OTP_EXPIRE || '120', 10) || 120,
  BALE_API: process.env.BALE_API || 'https://tapi.bale.ai/bot',
  MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE || String(50 * 1024 * 1024), 10),
};
