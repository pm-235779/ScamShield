import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Home, Search, GitCompare, History } from 'lucide-react'

const Navbar = () => {
  const location = useLocation()
  
  const navItems = [
    { path: '/', icon: Home, label: 'Home' },
    { path: '/analyze', icon: Search, label: 'Analyze' },
    { path: '/compare', icon: GitCompare, label: 'Compare' },
    { path: '/history', icon: History, label: 'History' },
  ]

  return (
    <nav className="bg-gray-800/95 backdrop-blur-md border-b border-gray-700/50 sticky top-0 z-50 shadow-lg">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2 group">
            <motion.div
              whileHover={{ rotate: 360, scale: 1.1 }}
              transition={{ duration: 0.5 }}
              className="p-3 bg-gradient-to-br from-neon-500 to-electric-500 rounded-full shadow-neon"
            >
              <Shield className="w-6 h-6 text-white" />
            </motion.div>
            <span className="text-xl font-bold bg-gradient-to-r from-neon-400 to-electric-400 bg-clip-text text-transparent">
              ScamShield
            </span>
          </Link>

          {/* Navigation Items */}
          <div className="flex items-center space-x-1">
            {navItems.map(({ path, icon: Icon, label }) => (
              <Link
                key={path}
                to={path}
                className={`relative px-6 py-3 rounded-full transition-all duration-300 flex items-center space-x-2 ${
                  location.pathname === path
                    ? 'text-neon-400 bg-neon-500/10 shadow-inner-glow'
                    : 'text-gray-300 hover:text-white hover:bg-gray-700/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="hidden sm:inline">{label}</span>
                
                {location.pathname === path && (
                  <motion.div
                    layoutId="navbar-indicator"
                    className="absolute inset-0 bg-neon-500/20 rounded-full border border-neon-500/30"
                    initial={false}
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                  />
                )}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </nav>
  )
}

export default Navbar
