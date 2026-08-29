export default function TypingIndicator({ text }: { text?: string }) {
  return (
    <div style={{ display:"flex", gap:12, alignItems:"flex-start" }}>
      <div style={{ width:28, height:28, borderRadius:"50%", background:"#161b22", border:"1px solid #30363d", display:"flex", alignItems:"center", justifyContent:"center", fontSize:12 }}>🛡</div>
      <div style={{ background:"#161b22", border:"1px solid #30363d", borderRadius:"0 16px 16px 16px", padding:"10px 16px" }}>
        {text ? <p style={{ color:"#8b949e", fontSize:13, fontStyle:"italic", margin:0 }}>{text}</p>
              : <div style={{ display:"flex", gap:4 }}>{[0,1,2].map(i=><div key={i} style={{ width:6, height:6, borderRadius:"50%", background:"#58a6ff", animation:"b 1s ease infinite", animationDelay:`${i*0.15}s` }}/>)}</div>}
        <style>{`@keyframes b{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-4px)}}`}</style>
      </div>
    </div>
  )
}
