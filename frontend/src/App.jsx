import React from 'react'
import { Routes, Route } from 'react-router-dom'
import { motion } from 'framer-motion'
import Navbar from './components/Navbar'
import HomePage from './pages/HomePage'
import AnalyzePage from './pages/AnalyzePage'
import ComparePage from './pages/ComparePage'
import HistoryPage from './pages/HistoryPage'
import ResultPage from './pages/ResultPage'

function App() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <Navbar />
      
      <motion.main
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5 }}
        className="container mx-auto px-4 py-8"
      >
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/compare" element={<ComparePage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/result" element={<ResultPage />} />
        </Routes>
      </motion.main>
      
      {/* Background Effects */}
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute -top-40 -right-32 w-80 h-80 bg-primary-500/10 rounded-full blur-3xl"></div>
        <div className="absolute -bottom-40 -left-32 w-80 h-80 bg-cyber-500/10 rounded-full blur-3xl"></div>
      </div>
    </div>
  )
}

export default App
