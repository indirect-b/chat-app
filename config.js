module.exports = {
  BALE_BOT_TOKEN: (process.env.BALE_BOT_TOKEN && process.env.BALE_BOT_TOKEN !== 'your_bale_bot_token_here') ? process.env.BALE_BOT_TOKEN : '',
  PORT: process.env.DEFAULT_APP_PORT ? parseInt(process.env.DEFAULT_APP_PORT) : (parseInt(process.env.PORT) || 3000),
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'Tk_tokyo',
  ADMIN_PATH: process.env.ADMIN_PATH || '/panel-Tk_tokyo',
  OTP_EXPIRE: parseInt(process.env.OTP_EXPIRE) || 120,
  BALE_API: process.env.BALE_API || 'https://tapi.bale.ai/bot',
  // حداکثر سایز فایل آپلود (بایت) - 50MB
  MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE) || 50 * 1024 * 1024,
};
