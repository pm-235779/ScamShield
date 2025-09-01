import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, Info, ChevronDown, ChevronRight } from 'lucide-react'

const PermissionsList = ({ permissions }) => {
  const [expanded, setExpanded] = useState(false)
  
  const dangerousPermissions = [
    'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE', 'WRITE_EXTERNAL_STORAGE',
    'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_PHONE_STATE', 'CALL_PHONE',
    'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'WRITE_SETTINGS',
    'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'BIND_DEVICE_ADMIN'
  ]

  const getPermissionRisk = (permission) => {
    if (dangerousPermissions.some(dp => permission.includes(dp))) {
      return 'high'
    }
    if (permission.includes('INTERNET') || permission.includes('NETWORK') || 
        permission.includes('ACCESS_') || permission.includes('READ_')) {
      return 'medium'
    }
    return 'low'
  }

  const getPermissionIcon = (risk) => {
    switch (risk) {
      case 'high':
        return <AlertTriangle className="w-4 h-4 text-danger-400" />
      case 'medium':
        return <Shield className="w-4 h-4 text-yellow-400" />
      default:
        return <Info className="w-4 h-4 text-cyber-400" />
    }
  }

  const getPermissionColor = (risk) => {
    switch (risk) {
      case 'high':
        return 'border-danger-500/30 bg-danger-500/5'
      case 'medium':
        return 'border-yellow-500/30 bg-yellow-500/5'
      default:
        return 'border-cyber-500/30 bg-cyber-500/5'
    }
  }

  const categorizedPermissions = permissions.reduce((acc, permission) => {
    const risk = getPermissionRisk(permission)
    if (!acc[risk]) acc[risk] = []
    acc[risk].push(permission)
    return acc
  }, {})

  const displayPermissions = expanded ? permissions : permissions.slice(0, 8)

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-semibold text-white flex items-center space-x-2">
          <Shield className="w-5 h-5" />
          <span>Permissions Analysis</span>
        </h3>
        <div className="text-sm text-gray-400">
          {permissions.length} total
        </div>
      </div>

      {/* Risk Summary */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {['high', 'medium', 'low'].map(risk => (
          <div key={risk} className="text-center">
            <div className={`text-2xl font-bold ${
              risk === 'high' ? 'text-danger-400' :
              risk === 'medium' ? 'text-yellow-400' : 'text-cyber-400'
            }`}>
              {categorizedPermissions[risk]?.length || 0}
            </div>
            <div className="text-xs text-gray-400 capitalize">
              {risk} Risk
            </div>
          </div>
        ))}
      </div>

      {/* Permissions List */}
      <div className="space-y-2">
        {displayPermissions.map((permission, index) => {
          const risk = getPermissionRisk(permission)
          const cleanName = permission.replace('android.permission.', '')
          
          return (
            <motion.div
              key={permission}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
              className={`p-3 rounded-lg border ${getPermissionColor(risk)} flex items-center space-x-3`}
            >
              {getPermissionIcon(risk)}
              <div className="flex-1">
                <div className="font-medium text-white text-sm">
                  {cleanName}
                </div>
                <div className="text-xs text-gray-400">
                  {getPermissionDescription(cleanName)}
                </div>
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Show More/Less Button */}
      {permissions.length > 8 && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full mt-4 p-2 text-primary-400 hover:text-primary-300 transition-colors flex items-center justify-center space-x-2"
        >
          {expanded ? (
            <>
              <ChevronDown className="w-4 h-4" />
              <span>Show Less</span>
            </>
          ) : (
            <>
              <ChevronRight className="w-4 h-4" />
              <span>Show {permissions.length - 8} More</span>
            </>
          )}
        </button>
      )}
    </div>
  )
}

const getPermissionDescription = (permission) => {
  const descriptions = {
    'INTERNET': 'Access to network connections',
    'ACCESS_NETWORK_STATE': 'View network connection status',
    'ACCESS_FINE_LOCATION': 'Access precise location (GPS)',
    'ACCESS_COARSE_LOCATION': 'Access approximate location',
    'CAMERA': 'Take pictures and record video',
    'RECORD_AUDIO': 'Record audio from microphone',
    'READ_PHONE_STATE': 'Read phone status and identity',
    'READ_SMS': 'Read text messages (SMS)',
    'SEND_SMS': 'Send text messages',
    'CALL_PHONE': 'Directly call phone numbers',
    'READ_CONTACTS': 'Read contact information',
    'WRITE_EXTERNAL_STORAGE': 'Modify/delete SD card contents',
    'READ_EXTERNAL_STORAGE': 'Read SD card contents',
    'SYSTEM_ALERT_WINDOW': 'Display over other apps',
    'BIND_ACCESSIBILITY_SERVICE': 'Bind to accessibility service',
    'WRITE_SETTINGS': 'Modify system settings',
    'INSTALL_PACKAGES': 'Install applications',
    'DELETE_PACKAGES': 'Delete applications'
  }
  
  return descriptions[permission] || 'System permission'
}

export default PermissionsList
