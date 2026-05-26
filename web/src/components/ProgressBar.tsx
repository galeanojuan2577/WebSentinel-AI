export function ProgressBar({ percent, label }: { percent: number; label?: string }) {
  return (
    <div className="w-full space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-[#94a3b8]">{label || 'Progress'}</span>
        <span className="text-blue-400 font-mono">{percent}%</span>
      </div>
      <div className="w-full h-2 bg-[#0a0e17] rounded-full overflow-hidden border border-[#1e2d45]">
        <div className="h-full rounded-full transition-all duration-500 ease-out bg-gradient-to-r from-blue-600 to-blue-400" style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}
