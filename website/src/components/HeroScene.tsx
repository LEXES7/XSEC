/* The 3D backdrop: a wireframe shield core, an orbital ring of "scan"
   particles, and a deep parallax starfield. Pointer moves the camera a
   little; scrolling pushes the whole scene away — both eased per-frame. */

import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

function Starfield({ count = 3500 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null);

  const [positions, colors] = useMemo(() => {
    const pos = new Float32Array(count * 3);
    const col = new Float32Array(count * 3);
    const cyan = new THREE.Color("#00f0ff");
    const white = new THREE.Color("#cfe3ef");
    const green = new THREE.Color("#38ff9c");
    for (let i = 0; i < count; i++) {
      // a hollow sphere of stars around the camera
      const r = 14 + Math.random() * 26;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      pos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      pos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      pos[i * 3 + 2] = r * Math.cos(phi);
      const roll = Math.random();
      const c = roll < 0.08 ? cyan : roll < 0.13 ? green : white;
      col[i * 3] = c.r;
      col[i * 3 + 1] = c.g;
      col[i * 3 + 2] = c.b;
    }
    return [pos, col];
  }, [count]);

  useFrame((_, delta) => {
    if (ref.current) ref.current.rotation.y += delta * 0.008;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        <bufferAttribute attach="attributes-color" args={[colors, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.06}
        vertexColors
        transparent
        opacity={0.85}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  );
}

function ShieldCore() {
  const group = useRef<THREE.Group>(null);
  const outer = useRef<THREE.Mesh>(null);
  const ring = useRef<THREE.Points>(null);

  const ringPositions = useMemo(() => {
    const n = 420;
    const pos = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const a = (i / n) * Math.PI * 2;
      const r = 3.4 + (Math.random() - 0.5) * 0.25;
      pos[i * 3] = Math.cos(a) * r;
      pos[i * 3 + 1] = (Math.random() - 0.5) * 0.12;
      pos[i * 3 + 2] = Math.sin(a) * r;
    }
    return pos;
  }, []);

  useFrame(({ clock }, delta) => {
    const t = clock.getElapsedTime();
    if (group.current) {
      group.current.rotation.y += delta * 0.12;
      group.current.position.y = Math.sin(t * 0.6) * 0.12;
    }
    if (outer.current) {
      outer.current.rotation.x += delta * 0.05;
      const mat = outer.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.22 + Math.sin(t * 1.4) * 0.08;
    }
    if (ring.current) ring.current.rotation.y -= delta * 0.25;
  });

  return (
    <group ref={group}>
      {/* inner glowing core */}
      <mesh>
        <icosahedronGeometry args={[1.05, 2]} />
        <meshBasicMaterial color="#062c33" />
      </mesh>
      <mesh>
        <icosahedronGeometry args={[1.06, 2]} />
        <meshBasicMaterial color="#00f0ff" wireframe transparent opacity={0.55} />
      </mesh>
      {/* outer shield lattice */}
      <mesh ref={outer}>
        <icosahedronGeometry args={[2.3, 1]} />
        <meshBasicMaterial color="#38ff9c" wireframe transparent opacity={0.25} />
      </mesh>
      {/* orbital scan ring */}
      <points ref={ring} rotation={[0.5, 0, 0.18]}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[ringPositions, 3]} />
        </bufferGeometry>
        <pointsMaterial color="#00f0ff" size={0.05} transparent opacity={0.9} depthWrite={false} />
      </points>
    </group>
  );
}

function Rig() {
  const { camera, pointer } = useThree();
  useFrame(() => {
    // pointer parallax + scroll dolly, eased every frame
    const scroll = Math.min(window.scrollY / window.innerHeight, 1.4);
    const targetX = pointer.x * 0.7;
    const targetY = -pointer.y * 0.5 + scroll * 2.2;
    const targetZ = 7 + scroll * 5;
    camera.position.x += (targetX - camera.position.x) * 0.04;
    camera.position.y += (targetY - camera.position.y) * 0.04;
    camera.position.z += (targetZ - camera.position.z) * 0.06;
    camera.lookAt(0, 0, 0);
  });
  return null;
}

export default function HeroScene() {
  return (
    <Canvas
      className="hero-canvas"
      camera={{ position: [0, 0, 7], fov: 52 }}
      gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
      dpr={[1, 2]}
    >
      <Starfield />
      <ShieldCore />
      <Rig />
    </Canvas>
  );
}
