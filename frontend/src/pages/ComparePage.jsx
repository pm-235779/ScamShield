import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { useDropzone } from 'react-dropzone'
import { Upload, FileText, Loader2, AlertCircle, GitCompare, ArrowRight } from 'lucide-react'
import axios from 'axios'
import ComparisonResult from '../components/ComparisonResult'

const ComparePage = () => {
  const [files, setFiles] = useState({ file1: null, file2: null })
  const [comparing, setComparing] = useState(false)
  const [error, setError] = useState('')
  const [comparisonResult, setComparisonResult] = useState(null)

  const createDropzone = (fileKey) => {
    const onDrop = (acceptedFiles, rejectedFiles) => {
      console.log('Files dropped:', { acceptedFiles, rejectedFiles })
      
      if (rejectedFiles && rejectedFiles.length > 0) {
        console.log('Rejected files:', rejectedFiles)
        setError(`File rejected: ${rejectedFiles[0].errors[0]?.message || 'Invalid file type'}`)
        return
      }
      
      const selectedFile = acceptedFiles[0]
      if (selectedFile) {
        console.log('Selected file:', selectedFile.name, selectedFile.type, selectedFile.size)
        // Accept any file for testing, validate extension
        if (selectedFile.name.toLowerCase().endsWith('.apk') || selectedFile.name.toLowerCase().includes('apk')) {
          setFiles(prev => ({ ...prev, [fileKey]: selectedFile }))
          setError('')
        } else {
          setError('Please select an APK file')
        }
      } else {
        setError('No file selected')
      }
    }

    return useDropzone({
      onDrop,
      multiple: false,
      maxSize: 100 * 1024 * 1024, // 100MB
      noClick: false,
      noKeyboard: false,
      disabled: false
    })
  }

  const dropzone1 = createDropzone('file1')
  const dropzone2 = createDropzone('file2')

  const handleCompare = async () => {
    if (!files.file1 || !files.file2) return

    setComparing(true)
    setError('')

    try {
      const formData = new FormData()
      formData.append('file1', files.file1)
      formData.append('file2', files.file2)

      const response = await axios.post('/api/compare', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setComparisonResult(response.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Comparison failed. Please try again.')
    } finally {
      setComparing(false)
    }
  }

  const FileUploadArea = ({ title, dropzone, file, fileKey }) => {
    const handleBrowseClick = (e) => {
      if (e) {
        e.preventDefault()
        e.stopPropagation()
      }
      console.log('Browse button clicked for:', fileKey)
      
      // Create and trigger file input
      const input = document.createElement('input')
      input.type = 'file'
      input.accept = '.apk,application/vnd.android.package-archive'
      input.style.display = 'none'
      
      input.onchange = (event) => {
        const selectedFile = event.target.files[0]
        if (selectedFile) {
          console.log('File selected:', selectedFile.name)
          setFiles(prev => ({ ...prev, [fileKey]: selectedFile }))
          setError('')
        }
        // Clean up
        document.body.removeChild(input)
      }
      
      // Add to DOM and click
      document.body.appendChild(input)
      input.click()
    }

    return (
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">{title}</h3>
        
        <div
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-300 ${
            dropzone.isDragActive
              ? 'border-primary-500 bg-primary-500/10'
              : 'border-gray-600 hover:border-gray-500'
          }`}
          onClick={handleBrowseClick}
          onDrop={dropzone.onDrop}
          onDragOver={(e) => e.preventDefault()}
          onDragEnter={(e) => e.preventDefault()}
          tabIndex={0}
          role="button"
          aria-label="Upload APK file"
        >
        
        <div className="space-y-3">
          <div className="mx-auto w-12 h-12 bg-gray-700 rounded-full flex items-center justify-center">
            <Upload className="w-6 h-6 text-gray-400" />
          </div>
          
          {dropzone.isDragActive ? (
            <p className="text-primary-400">Drop APK here...</p>
          ) : (
            <div className="space-y-1">
              <p className="text-gray-300">Drop APK or click anywhere to browse</p>
              <p className="text-gray-500 text-sm">Max 100MB • APK files only</p>
            </div>
          )}
        </div>
        </div>

        {file && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mt-4 p-3 bg-gray-700 rounded-lg flex items-center justify-between"
          >
            <div className="flex items-center space-x-3">
              <FileText className="w-4 h-4 text-primary-400" />
              <div>
                <p className="text-white font-medium text-sm">{file.name}</p>
                <p className="text-gray-400 text-xs">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB
                </p>
              </div>
            </div>
            
            <button
              onClick={() => setFiles(prev => ({ ...prev, [fileKey]: null }))}
              className="text-gray-400 hover:text-white transition-colors"
            >
              ×
            </button>
          </motion.div>
        )}
      </div>
    )
  }

  if (comparisonResult) {
    return <ComparisonResult result={comparisonResult} onReset={() => setComparisonResult(null)} />
  }

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <h1 className="text-4xl font-bold text-white">APK Comparison</h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          Compare two APK files side-by-side to identify differences in permissions, 
          certificates, and risk levels
        </p>
      </motion.div>

      {/* Upload Areas */}
      <div className="grid md:grid-cols-2 gap-8">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
        >
          <FileUploadArea
            dropzone={dropzone1}
            file={files.file1}
            title="Original APK"
            fileKey="file1"
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
        >
          <FileUploadArea
            dropzone={dropzone2}
            file={files.file2}
            title="Comparison APK"
            fileKey="file2"
          />
        </motion.div>
      </div>

      {/* Compare Button */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="flex justify-center"
      >
        <button
          onClick={handleCompare}
          disabled={!files.file1 || !files.file2 || comparing}
          className="btn-primary px-8 py-3 text-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
        >
          {comparing ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Comparing...</span>
            </>
          ) : (
            <>
              <GitCompare className="w-5 h-5" />
              <span>Compare APKs</span>
              <ArrowRight className="w-5 h-5" />
            </>
          )}
        </button>
      </motion.div>

      {/* Error Message */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl mx-auto p-4 bg-danger-500/10 border border-danger-500/30 rounded-lg flex items-center space-x-3"
        >
          <AlertCircle className="w-5 h-5 text-danger-400" />
          <p className="text-danger-400">{error}</p>
        </motion.div>
      )}

      {/* Comparison Process */}
      {comparing && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="card space-y-6"
        >
          <h3 className="text-xl font-semibold text-white text-center">
            Comparison in Progress
          </h3>
          
          <div className="space-y-4">
            {[
              'Analyzing first APK...',
              'Analyzing second APK...',
              'Comparing permissions and features...',
              'Calculating risk differences...'
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
              transition={{ duration: 6, ease: "easeInOut" }}
            />
          </div>
        </motion.div>
      )}

      {/* Info Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="card"
      >
        <h3 className="text-lg font-semibold text-white mb-4">
          What We Compare
        </h3>
        
        <div className="grid md:grid-cols-2 gap-6">
          <div className="space-y-3">
            <h4 className="font-medium text-primary-400">Security Features</h4>
            <ul className="space-y-1 text-gray-400 text-sm">
              <li>• Permission differences</li>
              <li>• Certificate validation</li>
              <li>• Risk score variations</li>
              <li>• Suspicious content detection</li>
            </ul>
          </div>
          
          <div className="space-y-3">
            <h4 className="font-medium text-primary-400">App Metadata</h4>
            <ul className="space-y-1 text-gray-400 text-sm">
              <li>• Package name and version</li>
              <li>• File size and structure</li>
              <li>• Component exports</li>
              <li>• Network endpoints</li>
            </ul>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

export default ComparePage
