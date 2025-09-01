import React, { Suspense } from 'react'
import { useLocation, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { 
  Shield, 
  AlertTriangle, 
  XCircle, 
  CheckCircle, 
  FileText, 
  Key, 
  Globe, 
  ArrowLeft,
  Download,
  Share2
} from 'lucide-react'
import RiskGauge from '../components/RiskGauge'
import FeatureExplanation from '../components/FeatureExplanation'
import SlimeModel from '../components/SlimeModel'
import ParticleBackground from '../components/ParticleBackground'

const ResultPage = () => {
  const location = useLocation()
  const { analysis, filename } = location.state || {}

  const handleExportReport = () => {
    // Create a comprehensive report
    const report = {
      filename: filename,
      timestamp: new Date().toISOString(),
      analysis: analysis,
      summary: {
        verdict: analysis.verdict,
        risk_score: analysis.risk_score,
        app_name: analysis.app_name,
        package_name: analysis.package_name
      }
    }

    // Convert to JSON and download
    const dataStr = JSON.stringify(report, null, 2)
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr)
    
    const exportFileDefaultName = `apkshield_report_${analysis.package_name}_${new Date().toISOString().split('T')[0]}.json`
    
    const linkElement = document.createElement('a')
    linkElement.setAttribute('href', dataUri)
    linkElement.setAttribute('download', exportFileDefaultName)
    linkElement.click()
  }

  const handleShare = async () => {
    const shareData = {
      title: `APKShield Analysis: ${analysis.app_name}`,
      text: `Security analysis results for ${analysis.app_name}: ${analysis.verdict} (Risk Score: ${analysis.risk_score}/10)`,
      url: window.location.href
    }

    try {
      if (navigator.share && navigator.canShare(shareData)) {
        await navigator.share(shareData)
      } else {
        // Fallback: copy to clipboard
        await navigator.clipboard.writeText(`${shareData.title}\n${shareData.text}\n${shareData.url}`)
        alert('Analysis summary copied to clipboard!')
      }
    } catch (error) {
      console.error('Error sharing:', error)
      // Final fallback: copy URL
      try {
        await navigator.clipboard.writeText(window.location.href)
        alert('Report URL copied to clipboard!')
      } catch (clipboardError) {
        alert('Unable to share. Please copy the URL manually.')
      }
    }
  }

  if (!analysis) {
    return (
      <div className="text-center space-y-4">
        <p className="text-gray-400">No analysis data found</p>
        <Link to="/analyze" className="btn-primary">
          Go Back to Analysis
        </Link>
      </div>
    )
  }

  const getVerdictIcon = (verdict) => {
    switch (verdict) {
      case 'Safe':
        return <CheckCircle className="w-8 h-8 text-cyber-500" />
      case 'Suspicious':
        return <AlertTriangle className="w-8 h-8 text-yellow-500" />
      case 'High Risk':
        return <XCircle className="w-8 h-8 text-danger-500" />
      default:
        return <Shield className="w-8 h-8 text-gray-500" />
    }
  }

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'Safe':
        return 'text-cyber-500'
      case 'Suspicious':
        return 'text-yellow-500'
      case 'High Risk':
        return 'text-danger-500'
      default:
        return 'text-gray-500'
    }
  }

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div className="flex items-center space-x-4">
          <Link
            to="/analyze"
            className="p-2 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white">Analysis Results</h1>
            <p className="text-gray-400">{filename}</p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button 
            onClick={handleExportReport}
            className="btn-secondary flex items-center space-x-2"
          >
            <Download className="w-4 h-4" />
            <span>Export Report</span>
          </button>
          <button 
            onClick={handleShare}
            className="btn-secondary flex items-center space-x-2"
          >
            <Share2 className="w-4 h-4" />
            <span>Share</span>
          </button>
        </div>
      </motion.div>

      {/* Main Results */}
      <div className="grid lg:grid-cols-3 gap-8">
        {/* Risk Assessment */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-1"
        >
          <div className="card text-center space-y-6">
            <div className="flex items-center justify-center space-x-3">
              {getVerdictIcon(analysis.verdict)}
              <h2 className={`text-2xl font-bold ${getVerdictColor(analysis.verdict)}`}>
                {analysis.verdict}
              </h2>
            </div>

            <div className="flex flex-col items-center justify-center space-y-4">
              <RiskGauge score={analysis.risk_score} />
              
              <div className="text-center space-y-2">
                <p className="text-3xl font-bold text-white">
                  {analysis.risk_score}/10
                </p>
                <p className="text-gray-400">Risk Score</p>
              </div>
            </div>

            <div className="pt-4 border-t border-gray-700 space-y-2">
              <p className="text-sm text-gray-400">Confidence Level</p>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className="bg-primary-500 h-2 rounded-full"
                  style={{ width: `${Math.min((analysis.confidence || 0.5) * 100, 100)}%` }}
                />
              </div>
              <p className="text-sm text-gray-300">
                {((analysis.confidence || 0.5) * 100).toFixed(1)}%
              </p>
            </div>
          </div>
        </motion.div>

        {/* App Information */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-2 space-y-6"
        >
          {/* App Details */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
              <FileText className="w-5 h-5" />
              <span>Application Details</span>
            </h3>
            
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div>
                  <p className="text-gray-400 text-sm">App Name</p>
                  <p className="text-white font-medium">{analysis.app_name}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Package Name</p>
                  <p className="text-white font-mono text-sm">{analysis.package_name}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Version</p>
                  <p className="text-white font-medium">{analysis.version_name}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">File Size</p>
                  <p className="text-white font-medium">{analysis.file_size_human || 'Unknown'}</p>
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-gray-400 text-sm">Target SDK</p>
                  <p className="text-white font-medium">API {analysis.target_sdk || 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Min SDK</p>
                  <p className="text-white font-medium">API {analysis.min_sdk || 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Permissions</p>
                  <p className="text-white font-medium">
                    {analysis.permissions.length} total
                    {analysis.dangerous_permissions && analysis.dangerous_permissions.length > 0 && (
                      <span className="text-yellow-400 ml-2">
                        ({analysis.dangerous_permissions.length} dangerous)
                      </span>
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Components</p>
                  <p className="text-white font-medium">
                    {analysis.component_summary ? 
                      `${analysis.component_summary.activities} activities, ${analysis.component_summary.services} services` :
                      `${analysis.activities?.length || 0} activities, ${analysis.services?.length || 0} services`
                    }
                  </p>
                </div>
              </div>
            </div>
            
            {/* Additional Details Row */}
            <div className="mt-4 pt-4 border-t border-gray-700">
              <div className="grid md:grid-cols-3 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">Install Location</p>
                  <p className="text-white font-medium capitalize">{analysis.install_location || 'Auto'}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Backup Allowed</p>
                  <p className={`font-medium ${analysis.allows_backup !== false ? 'text-yellow-400' : 'text-cyber-400'}`}>
                    {analysis.allows_backup !== false ? 'Yes' : 'No'}
                  </p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Debuggable</p>
                  <p className={`font-medium ${analysis.is_debuggable ? 'text-danger-400' : 'text-cyber-400'}`}>
                    {analysis.is_debuggable ? 'Yes' : 'No'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Certificate Info */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
              <Key className="w-5 h-5" />
              <span>Certificate Information</span>
            </h3>
            
            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${
                  analysis.certificate_info.is_valid ? 'bg-cyber-500' : 'bg-danger-500'
                }`}></div>
                <span className="text-gray-300">
                  {analysis.certificate_info.is_valid ? 'Valid Certificate' : 'Invalid Certificate'}
                </span>
              </div>
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${
                  analysis.certificate_info.is_self_signed ? 'bg-yellow-500' : 'bg-cyber-500'
                }`}></div>
                <span className="text-gray-300">
                  {analysis.certificate_info.is_self_signed ? 'Self-signed' : 'CA Signed'}
                </span>
              </div>
            </div>
            
            {/* Additional Certificate Details */}
            <div className="grid md:grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-400">Signature Algorithm</p>
                <p className="text-white font-mono">{analysis.certificate_info.signature_algorithm || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-gray-400">Issuer</p>
                <p className="text-white font-mono text-xs break-all">
                  {analysis.certificate_info.issuer || 'Unknown'}
                </p>
              </div>
              {analysis.certificate_info.valid_from && (
                <div>
                  <p className="text-gray-400">Valid From</p>
                  <p className="text-white">{new Date(analysis.certificate_info.valid_from).toLocaleDateString()}</p>
                </div>
              )}
              {analysis.certificate_info.valid_to && (
                <div>
                  <p className="text-gray-400">Valid To</p>
                  <p className="text-white">{new Date(analysis.certificate_info.valid_to).toLocaleDateString()}</p>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </div>

      {/* Detailed Analysis */}
      <div className="grid lg:grid-cols-1 gap-8">
        {/* Feature Explanations */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <FeatureExplanation features={analysis.top_features} verdict={analysis.verdict} />
        </motion.div>
      </div>

      {/* Suspicious Strings */}
      {analysis.suspicious_strings && analysis.suspicious_strings.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="card"
        >
          <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
            <Globe className="w-5 h-5" />
            <span>Suspicious Content Detected</span>
          </h3>
          
          <div className="grid md:grid-cols-2 gap-4">
            {analysis.suspicious_strings.map((str, index) => (
              <div key={index} className="p-3 bg-gray-700 rounded-lg">
                <code className="text-sm text-yellow-400 break-all">{str}</code>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Recommendations */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="card"
      >
        <h3 className="text-xl font-semibold text-white mb-4">
          Recommendations
        </h3>
        
        <div className="space-y-3">
          {analysis.verdict === 'High Risk' && (
            <div className="p-4 bg-danger-500/10 border border-danger-500/30 rounded-lg">
              <p className="text-danger-400 font-medium">⚠️ High Risk Detected</p>
              <p className="text-gray-300 mt-1">
                This APK shows multiple indicators of malicious behavior. Do not install or distribute this application.
              </p>
            </div>
          )}
          
          {analysis.verdict === 'Suspicious' && (
            <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
              <p className="text-yellow-400 font-medium">⚠️ Suspicious Activity</p>
              <p className="text-gray-300 mt-1">
                This APK has some concerning characteristics. Proceed with caution and verify the source.
              </p>
            </div>
          )}
          
          {analysis.verdict === 'Safe' && (
            <div className="p-4 bg-cyber-500/10 border border-cyber-500/30 rounded-lg">
              <p className="text-cyber-400 font-medium">✅ Appears Safe</p>
              <p className="text-gray-300 mt-1">
                This APK shows no obvious signs of malicious behavior, but always verify the source.
              </p>
            </div>
          )}
        </div>
      </motion.div>

      {/* Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="flex justify-center space-x-4"
      >
        <Link to="/analyze" className="btn-primary">
          Analyze Another APK
        </Link>
        <Link to="/compare" className="btn-secondary">
          Compare with Another APK
        </Link>
      </motion.div>
    </div>
  )
}

export default ResultPage
