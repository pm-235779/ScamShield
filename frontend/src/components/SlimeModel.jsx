import React, { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Sphere, MeshDistortMaterial, OrbitControls } from '@react-three/drei'
import * as THREE from 'three'

const SlimeBlob = ({ color = '#00ff88', position = [0, 0, 0], scale = 1 }) => {
  const meshRef = useRef()
  
  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.5) * 0.1
      meshRef.current.rotation.y += 0.01
      meshRef.current.position.y = Math.sin(state.clock.elapsedTime * 0.8) * 0.1
    }
  })

  return (
    <Sphere ref={meshRef} args={[1, 64, 64]} position={position} scale={scale}>
      <MeshDistortMaterial
        color={color}
        attach="material"
        distort={0.4}
        speed={2}
        roughness={0.1}
        metalness={0.8}
        emissive={color}
        emissiveIntensity={0.2}
      />
    </Sphere>
  )
}

const SlimeModel = ({ 
  variant = 'neon', 
  className = '', 
  size = 'medium',
  animated = true 
}) => {
  const getSlimeColor = () => {
    switch (variant) {
      case 'neon': return '#00ff88'
      case 'electric': return '#00d4ff'
      case 'cyber': return '#22c55e'
      case 'warning': return '#fbbf24'
      case 'danger': return '#ff1744'
      default: return '#00ff88'
    }
  }

  const getSlimeScale = () => {
    switch (size) {
      case 'small': return 0.6
      case 'medium': return 1
      case 'large': return 1.4
      case 'xl': return 2
      default: return 1
    }
  }

  return (
    <div className={`${className}`}>
      <Canvas
        camera={{ position: [0, 0, 4], fov: 45 }}
        style={{ background: 'transparent' }}
      >
        <ambientLight intensity={0.4} />
        <pointLight position={[10, 10, 10]} intensity={1} />
        <pointLight position={[-10, -10, -10]} color={getSlimeColor()} intensity={0.5} />
        
        <SlimeBlob 
          color={getSlimeColor()} 
          scale={getSlimeScale()}
        />
        
        {animated && <OrbitControls enableZoom={false} enablePan={false} />}
      </Canvas>
    </div>
  )
}

export default SlimeModel
