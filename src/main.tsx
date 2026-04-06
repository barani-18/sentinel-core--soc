import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css' // If you have a global CSS file

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
