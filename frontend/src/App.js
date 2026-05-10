
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Header from './components/Header';
import Hero from './components/Hero';
import DashboardPage from './pages/DashboardPage';
import './App.css';

export default function App() {
  return (
    <BrowserRouter>
      <div
        className="fixed inset-0 -z-10"
        style={{
          background:
            'linear-gradient(45deg, #C3DDED 0%, #E1EEF6 50%, #FFFFFF 100%)'
        }}
      >
        <div className="relative z-10 min-h-screen flex flex-col"></div>
        <Header />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<Hero />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}