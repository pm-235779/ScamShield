import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useDropzone } from 'react-dropzone'
import { Upload, FileText, Loader2, AlertCircle } from 'lucide-react'
import axios from 'axios'

const AnalyzePage = () => {
  const [file, setFile] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const onDrop = (acceptedFiles) => {
    const selectedFile = acceptedFiles[0]
    if (selectedFile && selectedFile.name.endsWith('.apk')) {
      setFile(selectedFile)
      setError('')
    } else {
      setError('Please select a valid APK file')
    }
  }

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.android.package-archive': ['.apk']
    },
    multiple: false
  })

  const handleAnalyze = async () => {
    if (!file) return

    setAnalyzing(true)
    setError('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await axios.post('/api/analyze_apk', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      // Navigate to results page with analysis data
      navigate('/result', { state: { analysis: response.data, filename: file.name } })
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed. Please try again.')
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <h1 className="text-4xl font-bold text-white">APK Analysis</h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          Upload an APK file to analyze its security posture and detect potential threats
        </p>
      </motion.div>

      {/* Upload Area */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card"
      >
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all duration-300 ${
            isDragActive
              ? 'border-neon-500 bg-neon-500/10 shadow-neon'
              : 'border-gray-600 hover:border-neon-500/50 hover:bg-neon-500/5'
          }`}
        >
          <input {...getInputProps()} />
          
          <div className="space-y-4">
            <div className="mx-auto w-16 h-16 bg-gradient-to-br from-neon-500/20 to-electric-500/20 rounded-full flex items-center justify-center border border-neon-500/30">
              <Upload className="w-8 h-8 text-neon-400" />
            </div>
            
            {isDragActive ? (
              <p className="text-primary-400 text-lg">Drop the APK file here...</p>
            ) : (
              <div className="space-y-2">
                <p className="text-gray-300 text-lg">
                  Drag and drop your APK file here, or click to browse
                </p>
                <p className="text-gray-500 text-sm">
                  Only .apk files are supported (max 100MB)
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Selected File */}
        {file && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mt-6 p-4 bg-gray-700 rounded-lg flex items-center justify-between"
          >
            <div className="flex items-center space-x-3">
              <FileText className="w-5 h-5 text-primary-400" />
              <div>
                <p className="text-white font-medium">{file.name}</p>
                <p className="text-gray-400 text-sm">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB
                </p>
              </div>
            </div>
            
            <button
              onClick={() => setFile(null)}
              className="text-gray-400 hover:text-white transition-colors"
            >
              ×
            </button>
          </motion.div>
        )}

        {/* Error Message */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 p-4 bg-danger-500/10 border border-danger-500/30 rounded-lg flex items-center space-x-3"
          >
            <AlertCircle className="w-5 h-5 text-danger-400" />
            <p className="text-danger-400">{error}</p>
          </motion.div>
        )}

        {/* Analyze Button */}
        <div className="mt-6 flex justify-center">
          <button
            onClick={handleAnalyze}
            disabled={!file || analyzing}
            className="btn-primary px-8 py-3 text-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
          >
            {analyzing ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <FileText className="w-5 h-5" />
                <span>Analyze APK</span>
              </>
            )}
          </button>
        </div>
      </motion.div>

      {/* Analysis Process */}
      {analyzing && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="card space-y-6"
        >
          <h3 className="text-xl font-semibold text-white text-center">
            Analysis in Progress
          </h3>
          
          <div className="space-y-4">
            {[
              'Extracting APK metadata...',
              'Analyzing permissions and certificates...',
              'Running ML threat detection...',
              'Generating risk assessment...'
            ].map((step, index) => (
              <motion.div
                key={step}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.5 }}
                className="flex items-center space-x-3"
              >
                <div className="w-2 h-2 bg-primary-500 rounded-full animate-pulse"></div>
                <span className="text-gray-300">{step}</span>
              </motion.div>
            ))}
          </div>
          
          <div className="w-full bg-gray-700 rounded-full h-2">
            <motion.div
              className="bg-gradient-to-r from-primary-500 to-cyber-500 h-2 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: '100%' }}
              transition={{ duration: 8, ease: "easeInOut" }}
            />
          </div>
        </motion.div>
      )}

      {/* Info Cards */}
      <div className="grid md:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card"
        >
          <h3 className="text-lg font-semibold text-white mb-3">
            What We Analyze
          </h3>
          <ul className="space-y-2 text-gray-400">
            <li>• App permissions and their risk levels</li>
            <li>• Certificate validity and signing information</li>
            <li>• Suspicious code patterns and strings</li>
            <li>• Network endpoints and URLs</li>
            <li>• Component exports and intents</li>
          </ul>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card"
        >
          <h3 className="text-lg font-semibold text-white mb-3">
            Risk Assessment
          </h3>
          <div className="space-y-3">
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-cyber-500 rounded-full"></div>
              <span className="text-gray-400">Safe (0-3): Low risk, likely benign</span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
              <span className="text-gray-400">Suspicious (3-7): Moderate risk</span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-danger-500 rounded-full"></div>
              <span className="text-gray-400">High Risk (7-10): Likely malicious</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default AnalyzePage
