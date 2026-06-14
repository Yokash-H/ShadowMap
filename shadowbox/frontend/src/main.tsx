import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './index.css';
import App from './App';
import UploadPage from './pages/UploadPage';
import AnalysisPage from './pages/AnalysisPage';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<App />}>
          <Route index element={<UploadPage />} />
          <Route path="/analysis/:id" element={<AnalysisPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
