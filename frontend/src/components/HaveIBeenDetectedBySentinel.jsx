export default function Sentinel() {
  return (
    <div className="bg-clip-text bg-gradient-to-r sentinel-font-logo from-white leading-[0] not-italic relative size-full text-[0px] text-[transparent] text-center to-[#5099ff] w-[786px]">
      <p className="bg-clip-text bg-gradient-to-r sentinel-font-logo from-[rgba(255,255,255,0.56)] leading-[normal] mb-0 text-[40px] to-[rgba(80,153,255,0.56)]">
        Have I been detected
      </p>
      <p>
        <span className="bg-clip-text bg-gradient-to-r sentinel-font-logo from-[rgba(255,255,255,0.56)] leading-[normal] not-italic text-[40px] text-[transparent] to-[rgba(80,153,255,0.56)]">
          by
        </span>
        <span className="leading-[normal] text-[96px]">{` `}</span>
        <span className="sentinel-font-logo leading-[normal] not-italic text-[48px]">
          Sentinel
        </span>
      </p>
    </div>
  );
}

