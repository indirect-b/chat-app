import React from 'react';
import { createRoot } from 'react-dom/client';
import '../public/css/base.css';
import '../public/css/auth.css';
import '../public/css/chat.css';
import '../public/css/modals.css';
import { App } from './App';

const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}
