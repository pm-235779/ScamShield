import React from 'react'
import { motion } from 'framer-motion'

const RiskGauge = ({ score }) => {
  const normalizedScore = Math.min(Math.max(score, 0), 10)
  const percentage = (normalizedScore / 10) * 100
  const rotation = (percentage / 100) * 180 - 90 // -90 to 90 degrees
  
  const getColor = (score) => {
    if (score < 3) return '#22c55e' // green
    if (score < 7) return '#eab308' // yellow
    return '#ef4444' // red
  }

  const color = getColor(normalizedScore)

  return (
    <div className="flex flex-col items-center justify-center w-full max-w-xs mx-auto">
      {/* Gauge Container */}
      <div className="relative w-48 h-28 mb-4 p-4 bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-2xl backdrop-blur-sm border border-gray-700/50">
        {/* Background Arc */}
        <svg className="w-full h-full" viewBox="0 0 200 100" preserveAspectRatio="xMidYMid meet">
          <path
            d="M 30 75 A 50 50 0 0 1 170 75"
            fill="none"
            stroke="#374151"
            strokeWidth="6"
            strokeLinecap="round"
          />
          
          {/* Progress Arc */}
          <motion.path
            d="M 30 75 A 50 50 0 0 1 170 75"
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray="157.08"
            initial={{ strokeDashoffset: 157.08 }}
            animate={{ strokeDashoffset: 157.08 - (percentage * 1.5708) }}
            transition={{ duration: 1.5, ease: "easeOut" }}
          />
        </svg>
        
        {/* Needle */}
        <motion.div
          className="absolute w-0.5 h-12 bg-white rounded-full"
          style={{ 
            transformOrigin: 'bottom center',
            bottom: '18px',
            left: '50%',
            transform: 'translateX(-50%)'
          }}
          initial={{ rotate: -90 }}
          animate={{ rotate: rotation }}
          transition={{ duration: 1.5, ease: "easeOut" }}
        />
        
        {/* Center Dot */}
        <div className="absolute w-3 h-3 bg-white rounded-full shadow-lg" 
             style={{ 
               bottom: '18px', 
               left: '50%', 
               transform: 'translateX(-50%)' 
             }} />
        
        {/* Scale Labels */}
        <div className="absolute text-xs text-gray-400 font-medium" 
             style={{ bottom: '8px', left: '20px' }}>0</div>
        <div className="absolute text-xs text-gray-400 font-medium" 
             style={{ bottom: '12px', left: '50%', transform: 'translateX(-50%)' }}>5</div>
        <div className="absolute text-xs text-gray-400 font-medium" 
             style={{ bottom: '8px', right: '20px' }}>10</div>
      </div>
      
      {/* Risk Level Indicator */}
      <div className="text-center space-y-2">
        <div className={`text-2xl font-bold mb-1`} style={{ color }}>
          {normalizedScore.toFixed(1)}
        </div>
        <div className={`text-sm font-medium px-3 py-1 rounded-full border`} style={{ 
          color, 
          borderColor: color + '40',
          backgroundColor: color + '10'
        }}>
          {normalizedScore < 3 ? 'Low Risk' : normalizedScore < 7 ? 'Medium Risk' : 'High Risk'}
        </div>
      </div>
    </div>
  )
}

export default RiskGauge
