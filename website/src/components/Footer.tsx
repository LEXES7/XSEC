export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <img src="./assets/icon.png" alt="" />
          <span>XSEC</span>
        </div>
        <p className="footer-tag">scan deep · fix fast · trust the diff</p>
        <div className="footer-links">
          <a href="https://github.com/LEXES7/XSEC" target="_blank" rel="noopener noreferrer">GitHub</a>
          <span>·</span>
          <a href="https://github.com/LEXES7/XSEC/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer">Security policy</a>
          <span>·</span>
          <span>MIT license</span>
        </div>
      </div>
    </footer>
  );
}
