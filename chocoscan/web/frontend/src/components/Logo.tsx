export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
      {/* Corps */}
      <ellipse cx="16" cy="19" rx="9" ry="8" fill="#1a1a2e"/>
      {/* Tête */}
      <ellipse cx="16" cy="12" rx="7" ry="6.5" fill="#1a1a2e"/>
      {/* Oreille gauche */}
      <polygon points="10,8 8,1 13,6" fill="#1a1a2e"/>
      {/* Oreille droite */}
      <polygon points="22,8 24,1 19,6" fill="#1a1a2e"/>
      {/* Anneaux cyan shiny */}
      <ellipse cx="16" cy="10"  rx="2.8" ry="1.1" fill="none" stroke="#22d3ee" strokeWidth="1.2" opacity="0.9"/>
      <ellipse cx="16" cy="16"  rx="5"   ry="1.5" fill="none" stroke="#22d3ee" strokeWidth="1.2" opacity="0.85"/>
      <ellipse cx="16" cy="21"  rx="6"   ry="1.5" fill="none" stroke="#22d3ee" strokeWidth="1.2" opacity="0.8"/>
      {/* Yeux rouges */}
      <ellipse cx="13.2" cy="11.5" rx="1.1" ry="1.2" fill="#ef4444"/>
      <ellipse cx="18.8" cy="11.5" rx="1.1" ry="1.2" fill="#ef4444"/>
      <ellipse cx="13.6" cy="11.2" rx="0.4" ry="0.4" fill="white" opacity="0.7"/>
      <ellipse cx="19.2" cy="11.2" rx="0.4" ry="0.4" fill="white" opacity="0.7"/>
    </svg>
  )
}
