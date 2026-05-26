export function StatCard({ label, value, color, mono, small }: {
  label: string; value: string; color?: string; mono?: boolean; small?: boolean
}) {
  return (
    <div className="bg-[#0a0e17] rounded-lg border border-[#1e2d45] p-4">
      <p className="text-[10px] uppercase tracking-wider text-[#64748b] font-semibold">{label}</p>
      <p className={`mt-1 font-bold ${small ? 'text-sm' : 'text-xl'}`}
        style={{ color: color || '#f1f5f9', fontFamily: mono ? "'JetBrains Mono', monospace" : 'inherit' }}>
        {value}
      </p>
    </div>
  )
}
