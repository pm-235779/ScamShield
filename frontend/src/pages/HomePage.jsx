import React, { useState, useRef, Suspense } from 'react'
import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { 
  Upload, 
  Shield, 
  Zap, 
  Eye, 
  Lock,
  AlertTriangle,
  CheckCircle,
  FileText,
  Cpu,
  Globe,
  GitCompare,
  ArrowRight
} from 'lucide-react'
import SlimeModel from '../components/SlimeModel'
import ParticleBackground from '../components/ParticleBackground'

const HomePage = () => {
  const features = [
    {
      icon: Shield,
      title: 'AI-Powered Detection',
      description: 'Advanced machine learning models trained on thousands of APK samples to identify malicious behavior patterns.'
    },
    {
      icon: Zap,
      title: 'Real-time Analysis',
      description: 'Get instant risk assessment with detailed explanations and actionable insights in seconds.'
    },
    {
      icon: Eye,
      title: 'Deep Inspection',
      description: 'Comprehensive static analysis including permissions, certificates, and suspicious code patterns.'
    },
    {
      icon: GitCompare,
      title: 'Side-by-Side Comparison',
      description: 'Compare two APKs to identify differences and spot potential fake applications.'
    }
  ]

  const stats = [
    { label: 'APKs Analyzed', value: '10,000+', description: 'Successfully processed' },
    { label: 'Accuracy Rate', value: '96.8%', description: 'ML model precision' },
    { label: 'Detection Speed', value: '<5s', description: 'Average analysis time' },
    { label: 'False Positives', value: '<2%', description: 'Industry leading' }
  ]

  const steps = [
    {
      step: '1',
      title: 'Upload APK',
      description: 'Drag and drop your APK file or click to browse'
    },
    {
      step: '2',
      title: 'AI Analysis',
      description: 'Our ML models analyze permissions, certificates, and code patterns'
    },
    {
      step: '3',
      title: 'Get Results',
      description: 'Receive detailed risk assessment with explanations'
    }
  ]

  return (
    <div className="relative min-h-screen">
      {/* 3D Background */}
      <div className="fixed inset-0 -z-10">
        <Suspense fallback={null}>
          <ParticleBackground />
        </Suspense>
      </div>

      <div className="space-y-20">
        {/* Hero Section with 3D Elements */}
        <section className="relative text-center space-y-8 py-20 overflow-hidden">
          {/* Floating 3D Slimes */}
          <motion.div
            initial={{ opacity: 0, scale: 0, x: 100 }}
            animate={{ 
              opacity: 1, 
              scale: 1, 
              x: 0,
              y: [0, -20, 0],
              rotate: [0, 10, -10, 0]
            }}
            transition={{ 
              duration: 1.2, 
              delay: 0.5,
              y: { repeat: Infinity, duration: 4, ease: "easeInOut" },
              rotate: { repeat: Infinity, duration: 6, ease: "easeInOut" }
            }}
            className="absolute top-10 right-10 w-24 h-24 hidden lg:block"
          >
            <Suspense fallback={null}>
              <SlimeModel variant="neon" size="small" animated={false} />
            </Suspense>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0, x: -100 }}
            animate={{ 
              opacity: 1, 
              scale: 1, 
              x: 0,
              y: [0, 15, 0],
              rotate: [0, -15, 15, 0]
            }}
            transition={{ 
              duration: 1.5, 
              delay: 1,
              y: { repeat: Infinity, duration: 5, ease: "easeInOut" },
              rotate: { repeat: Infinity, duration: 7, ease: "easeInOut" }
            }}
            className="absolute top-20 left-10 w-20 h-20 hidden lg:block"
          >
            <Suspense fallback={null}>
              <SlimeModel variant="electric" size="small" animated={false} />
            </Suspense>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="space-y-6"
          >
            <h1 className="text-4xl sm:text-6xl lg:text-8xl font-bold bg-gradient-to-r from-neon-400 via-electric-400 to-cyber-400 bg-clip-text text-transparent">
              ScamShield
            </h1>
            <motion.p 
              className="text-xl md:text-2xl text-gray-300 max-w-4xl mx-auto leading-relaxed"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3, duration: 0.8 }}
            >
              Protect users from scams and fraudulent activities with AI-powered detection
            </motion.p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="flex flex-col sm:flex-row gap-4 sm:gap-6 justify-center items-center px-4"
          >
            <Link
              to="/analyze"
              className="group relative overflow-hidden bg-gradient-to-r from-neon-500 to-electric-500 text-white font-semibold text-lg px-10 py-5 rounded-2xl shadow-neon hover:shadow-neon-lg transition-all duration-300 transform hover:scale-105"
            >
              <span className="relative z-10 flex items-center space-x-3">
                <Upload className="w-6 h-6" />
                <span>Upload File to Analyze</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </span>
              <div className="absolute inset-0 bg-gradient-to-r from-electric-500 to-neon-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            </Link>
            
            <Link
              to="/compare"
              className="group bg-dark-800/80 backdrop-blur-sm border border-neon-500/30 text-neon-400 font-semibold text-lg px-10 py-5 rounded-2xl hover:bg-neon-500/10 hover:border-neon-500/50 transition-all duration-300 transform hover:scale-105"
            >
              <span className="flex items-center space-x-3">
                <GitCompare className="w-6 h-6" />
                <span>Compare Files</span>
              </span>
            </Link>
          </motion.div>

          {/* Animated Shield */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8, rotateY: -180 }}
            animate={{ opacity: 1, scale: 1, rotateY: 0 }}
            transition={{ duration: 1.2, delay: 0.6, type: "spring" }}
            className="relative mx-auto w-40 h-40 mt-12"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-neon-500/20 to-electric-500/20 rounded-full animate-pulse-slow"></div>
            <div className="absolute inset-4 bg-gradient-to-r from-neon-600 to-electric-600 rounded-full flex items-center justify-center shadow-neon">
              <Shield className="w-20 h-20 text-white animate-glow" />
            </div>
          </motion.div>
        </section>

        {/* Stats Section with 3D Elements */}
        <section className="relative overflow-hidden">
          {/* Multiple floating slimes */}
          <motion.div
            initial={{ opacity: 0, scale: 0 }}
            animate={{ 
              opacity: 1, 
              scale: 1,
              y: [0, -25, 0],
              x: [0, 10, 0]
            }}
            transition={{ 
              delay: 1, 
              duration: 1,
              y: { repeat: Infinity, duration: 6, ease: "easeInOut" },
              x: { repeat: Infinity, duration: 8, ease: "easeInOut" }
            }}
            className="absolute right-10 top-10 w-16 h-16 hidden md:block"
          >
            <Suspense fallback={null}>
              <SlimeModel variant="electric" size="small" animated={false} />
            </Suspense>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0 }}
            animate={{ 
              opacity: 1, 
              scale: 1,
              y: [0, 20, 0],
              rotate: [0, 180, 360]
            }}
            transition={{ 
              delay: 1.5, 
              duration: 1,
              y: { repeat: Infinity, duration: 7, ease: "easeInOut" },
              rotate: { repeat: Infinity, duration: 10, ease: "linear" }
            }}
            className="absolute left-5 bottom-10 w-12 h-12 hidden md:block"
          >
            <Suspense fallback={null}>
              <SlimeModel variant="cyber" size="small" animated={false} />
            </Suspense>
          </motion.div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 lg:gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, scale: 0.8, y: 50 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ 
                  duration: 0.8, 
                  delay: 0.2 * index,
                  type: "spring",
                  stiffness: 120
                }}
                whileHover={{ 
                  scale: 1.05,
                  y: -5,
                  transition: { duration: 0.2 }
                }}
                className="text-center space-y-4 relative group"
              >
                {/* Glowing Background */}
                <div className="absolute inset-0 bg-gradient-to-br from-neon-500/10 to-electric-500/10 rounded-2xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                
                <div className="relative z-10 p-6 bg-dark-800/50 backdrop-blur-sm border border-gray-700/50 rounded-2xl group-hover:border-neon-500/30 transition-all duration-300">
                  <motion.div 
                    className="text-5xl md:text-6xl font-bold bg-gradient-to-r from-neon-400 to-electric-400 bg-clip-text text-transparent mb-2"
                    whileHover={{ scale: 1.1 }}
                    transition={{ duration: 0.2 }}
                  >
                    {stat.value}
                  </motion.div>
                  <div className="text-gray-300 font-semibold text-lg mb-1">
                    {stat.label}
                  </div>
                  <div className="text-sm text-gray-500">
                    {stat.description}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        {/* Features Section */}
        <section className="space-y-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center space-y-4"
          >
            <h2 className="text-3xl md:text-4xl font-bold text-white">
              Advanced Threat Detection
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Our cutting-edge technology combines static analysis with machine learning 
              to provide comprehensive APK security assessment.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-2 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 30, rotateX: -15 }}
                animate={{ opacity: 1, y: 0, rotateX: 0 }}
                transition={{ 
                  duration: 0.8, 
                  delay: 0.1 * index,
                  type: "spring",
                  stiffness: 100
                }}
                whileHover={{ 
                  y: -10,
                  scale: 1.02,
                  rotateY: 5,
                  transition: { duration: 0.3 }
                }}
                className="relative group"
              >
                {/* Glassmorphism Card */}
                <div className="relative bg-gradient-to-br from-dark-800/80 to-dark-900/80 backdrop-blur-xl border border-neon-500/20 rounded-2xl p-6 shadow-glass hover:shadow-neon transition-all duration-500 overflow-hidden">
                  {/* Animated Background Gradient */}
                  <div className="absolute inset-0 bg-gradient-to-br from-neon-500/5 via-transparent to-electric-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  
                  {/* Floating Icon */}
                  <motion.div 
                    className="relative z-10 mb-6"
                    whileHover={{ rotate: 360 }}
                    transition={{ duration: 0.6 }}
                  >
                    <div className="w-16 h-16 bg-gradient-to-br from-neon-500/20 to-electric-500/20 rounded-2xl flex items-center justify-center group-hover:shadow-neon transition-all duration-300">
                      <feature.icon className="w-8 h-8 text-neon-400 group-hover:text-neon-300" />
                    </div>
                  </motion.div>
                  
                  <div className="relative z-10 space-y-3">
                    <h3 className="text-xl font-bold text-white group-hover:text-neon-300 transition-colors">
                      {feature.title}
                    </h3>
                    <p className="text-gray-400 group-hover:text-gray-300 transition-colors leading-relaxed">
                      {feature.description}
                    </p>
                  </div>
                  
                  {/* Hover Effect Border */}
                  <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-neon-500 to-electric-500 opacity-0 group-hover:opacity-20 transition-opacity duration-500 -z-10"></div>
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        {/* How It Works */}
        <section className="space-y-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center space-y-4"
          >
            <h2 className="text-3xl md:text-4xl font-bold text-white">
              How It Works
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Simple, fast, and accurate APK analysis in three steps
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {steps.map((item, index) => (
              <motion.div
                key={item.step}
                initial={{ opacity: 0, y: 30, scale: 0.9 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ 
                  duration: 0.8, 
                  delay: 0.1 * index,
                  type: "spring",
                  stiffness: 120
                }}
                whileHover={{ 
                  y: -5,
                  scale: 1.05,
                  transition: { duration: 0.2 }
                }}
                className="text-center space-y-4 relative group"
              >
                {/* Step Card */}
                <div className="relative p-6 bg-dark-800/60 backdrop-blur-sm border border-gray-700/50 rounded-2xl group-hover:border-neon-500/40 transition-all duration-300">
                  <motion.div 
                    className="w-20 h-20 bg-gradient-to-br from-neon-500/20 to-electric-500/20 rounded-full flex items-center justify-center mx-auto mb-4 group-hover:shadow-neon transition-all duration-300"
                    whileHover={{ rotate: 360 }}
                    transition={{ duration: 0.6 }}
                  >
                    <span className="text-3xl font-bold bg-gradient-to-r from-neon-400 to-electric-400 bg-clip-text text-transparent">
                      {item.step}
                    </span>
                  </motion.div>
                  <h3 className="text-xl font-bold text-white group-hover:text-neon-300 transition-colors">
                    {item.title}
                  </h3>
                  <p className="text-gray-400 group-hover:text-gray-300 transition-colors">
                    {item.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        {/* CTA Section */}
        <section className="relative text-center space-y-8 py-16 overflow-hidden">
          {/* Multiple animated 3D Slimes */}
          <motion.div
            initial={{ opacity: 0, scale: 0, y: 100 }}
            animate={{ 
              opacity: 1, 
              scale: 1, 
              y: 0,
              x: [0, -15, 15, 0],
              rotate: [0, 360]
            }}
            transition={{ 
              duration: 1.2, 
              delay: 1.5,
              x: { repeat: Infinity, duration: 8, ease: "easeInOut" },
              rotate: { repeat: Infinity, duration: 12, ease: "linear" }
            }}
            className="absolute bottom-10 left-10 w-20 h-20 hidden lg:block"
          >
            <Suspense fallback={null}>
              <SlimeModel variant="cyber" size="small" animated={false} />
            </Suspense>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0, y: -100 }}
            animate={{ 
              opacity: 1, 
              scale: 1, 
              y: 0,
              y: [0, -30, 0],
              x: [0, 20, -10, 0]
            }}
            transition={{ 
              duration: 1.5, 
              delay: 2,
              y: { repeat: Infinity, duration: 6, ease: "easeInOut" },
              x: { repeat: Infinity, duration: 9, ease: "easeInOut" }
            }}
            className="absolute top-5 right-15 w-16 h-16 hidden lg:block"
          >
            <Suspense fallback={null}>
              <SlimeModel variant="neon" size="small" animated={false} />
            </Suspense>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="space-y-4"
          >
            <h2 className="text-3xl md:text-4xl font-bold text-white">
              Ready to Secure Your Apps?
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Start analyzing APKs today and protect your users from malicious applications
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <Link
              to="/analyze"
              className="group relative overflow-hidden bg-gradient-to-r from-neon-500 to-electric-500 text-white font-semibold text-lg px-12 py-6 rounded-full shadow-neon hover:shadow-neon-lg transition-all duration-300 transform hover:scale-105 hover:rounded-3xl inline-flex items-center space-x-3"
            >
              <Shield className="w-6 h-6" />
              <span>Start Analysis</span>
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              <div className="absolute inset-0 bg-gradient-to-r from-electric-500 to-neon-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            </Link>
          </motion.div>
        </section>
      </div>
    </div>
  )
}

export default HomePage
