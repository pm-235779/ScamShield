import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { History, Search, Filter, Calendar, FileText, Shield } from 'lucide-react'
import axios from 'axios'

const HistoryPage = () => {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [filterVerdict, setFilterVerdict] = useState('all')

  useEffect(() => {
    fetchHistory()
  }, [])

  const fetchHistory = async () => {
    try {
      const response = await axios.get('/api/history')
      setHistory(response.data)
    } catch (err) {
      setError('Failed to load analysis history')
    } finally {
      setLoading(false)
    }
  }

  const filteredHistory = history.filter(item => {
    const matchesSearch = item.package_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (item.app_name && item.app_name.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesFilter = filterVerdict === 'all' || item.verdict === filterVerdict
    return matchesSearch && matchesFilter
  })

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'Safe':
        return 'text-cyber-500 bg-cyber-500/10'
      case 'Suspicious':
        return 'text-yellow-500 bg-yellow-500/10'
      case 'High Risk':
        return 'text-danger-500 bg-danger-500/10'
      default:
        return 'text-gray-500 bg-gray-500/10'
    }
  }

  const getRiskScoreColor = (score) => {
    if (score < 3) return 'text-cyber-500'
    if (score < 7) return 'text-yellow-500'
    return 'text-danger-500'
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString()
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <h1 className="text-4xl font-bold text-white">Analysis History</h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          View and search through your previous APK analysis results
        </p>
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card"
      >
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search by app or package name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input pl-10 w-full"
            />
          </div>

          {/* Filter */}
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="input pl-10 pr-8 appearance-none cursor-pointer"
            >
              <option value="all">All Verdicts</option>
              <option value="Safe">Safe</option>
              <option value="Suspicious">Suspicious</option>
              <option value="High Risk">High Risk</option>
            </select>
          </div>
        </div>
      </motion.div>

      {/* Error Message */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 bg-danger-500/10 border border-danger-500/30 rounded-lg text-danger-400"
        >
          {error}
        </motion.div>
      )}

      {/* History List */}
      <div className="space-y-4">
        {filteredHistory.length === 0 ? (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="card text-center py-12"
          >
            <History className="w-16 h-16 text-gray-500 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">
              {history.length === 0 ? 'No Analysis History' : 'No Results Found'}
            </h3>
            <p className="text-gray-400">
              {history.length === 0 
                ? 'Start analyzing APKs to see your history here'
                : 'Try adjusting your search or filter criteria'
              }
            </p>
          </motion.div>
        ) : (
          filteredHistory.map((item, index) => (
            <motion.div
              key={item.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
              className="card hover:border-gray-600 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="p-3 bg-gray-700 rounded-lg">
                    <FileText className="w-6 h-6 text-primary-400" />
                  </div>
                  
                  <div className="space-y-1">
                    <h3 className="font-semibold text-white">
                      {item.app_name || 'Unknown App'}
                    </h3>
                    <p className="text-gray-400 text-sm font-mono">
                      {item.package_name}
                    </p>
                    <div className="flex items-center space-x-2 text-xs text-gray-500">
                      <Calendar className="w-3 h-3" />
                      <span>{formatDate(item.timestamp)}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  {/* Risk Score */}
                  <div className="text-center">
                    <div className={`text-2xl font-bold ${getRiskScoreColor(item.risk_score)}`}>
                      {item.risk_score}
                    </div>
                    <div className="text-xs text-gray-400">Risk Score</div>
                  </div>

                  {/* Verdict Badge */}
                  <div className={`px-3 py-1 rounded-full text-sm font-medium ${getVerdictColor(item.verdict)}`}>
                    {item.verdict}
                  </div>

                  {/* File Hash */}
                  <div className="text-right">
                    <div className="text-xs text-gray-500">Hash</div>
                    <div className="text-xs font-mono text-gray-400">
                      {item.file_hash}
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          ))
        )}
      </div>

      {/* Stats Summary */}
      {history.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card"
        >
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>Analysis Summary</span>
          </h3>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-white">{history.length}</div>
              <div className="text-sm text-gray-400">Total Analyzed</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-cyber-500">
                {history.filter(h => h.verdict === 'Safe').length}
              </div>
              <div className="text-sm text-gray-400">Safe</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-500">
                {history.filter(h => h.verdict === 'Suspicious').length}
              </div>
              <div className="text-sm text-gray-400">Suspicious</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-danger-500">
                {history.filter(h => h.verdict === 'High Risk').length}
              </div>
              <div className="text-sm text-gray-400">High Risk</div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}

export default HistoryPage
