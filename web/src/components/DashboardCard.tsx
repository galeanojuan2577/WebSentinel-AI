const ICON_COLORS: Record<string, string> = {
  blue: '#60a5fa', purple: '#a78bfa', emerald: '#34d399', amber: '#fbbf24', cyan: '#22d3ee',
}

export function DashboardCard({ icon: Icon, label, value, color, onClick }: {
  icon: any; label: string; value: string; color: string; onClick: () => void
}) {
  const bgColors: Record<string, string> = {
    blue: 'bg-blue-500/10 border-blue-500/30', purple: 'bg-purple-500/10 border-purple-500/30',
    emerald: 'bg-emerald-500/10 border-emerald-500/30', amber: 'bg-amber-500/10 border-amber-500/30',
    cyan: 'bg-cyan-500/10 border-cyan-500/30',
  }
  const gradColors: Record<string, string> = {
    blue: 'from-blue-600 to-blue-400', purple: 'from-purple-600 to-purple-400',
    emerald: 'from-emerald-600 to-emerald-400', amber: 'from-amber-600 to-amber-400',
    cyan: 'from-cyan-600 to-cyan-400',
  }
  return (
    <button onClick={onClick}
      className={`relative overflow-hidden rounded-xl border p-5 text-left transition-all duration-300 hover:scale-[1.02] hover:shadow-lg ${bgColors[color]}`}>
      <div className={`absolute -top-6 -right-6 w-16 h-16 rounded-full bg-gradient-to-br ${gradColors[color]} opacity-10`} />
      <Icon size={24} className="mb-3" style={{ color: ICON_COLORS[color] || '#94a3b8' }} />
      <p className="text-sm text-[#64748b] font-medium">{label}</p>
      <p className="text-lg font-bold text-white mt-1">{value}</p>
    </button>
  )
}
