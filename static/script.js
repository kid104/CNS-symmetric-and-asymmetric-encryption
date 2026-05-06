// Tab switching
function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}

function copyText(id) {
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.value);
}

// ── Symmetric ──────────────────────────────────────────────

async function doEncrypt() {
  const message   = document.getElementById('enc-input').value.trim();
  const key       = document.getElementById('enc-key').value.trim();
  const algorithm = document.getElementById('algorithm').value;
  if (!message || !key) { alert('Please enter both a message and a key.'); return; }

  const res  = await fetch('/api/encrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, message, key })
  });
  const data = await res.json();
  if (data.error) { alert('Error: ' + data.error); return; }

  document.getElementById('enc-output').value = data.result;
  document.getElementById('dec-input').value  = data.result;
  document.getElementById('dec-key').value    = key;
}

async function doDecrypt() {
  const ciphertext = document.getElementById('dec-input').value.trim();
  const key        = document.getElementById('dec-key').value.trim();
  const algorithm  = document.getElementById('algorithm').value;
  if (!ciphertext || !key) { alert('Please enter both a ciphertext and a key.'); return; }

  const res  = await fetch('/api/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, ciphertext, key })
  });
  const data = await res.json();
  if (data.error) { alert('Error: ' + data.error); return; }
  document.getElementById('dec-output').value = data.result;
}

// ── RSA ────────────────────────────────────────────────────

async function doRsaGenerate() {
  const bits = document.getElementById('rsa-bits').value;
  const btn  = event.target;
  btn.textContent = 'Generating...';
  btn.disabled    = true;

  const res  = await fetch('/api/rsa/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ bits: parseInt(bits) })
  });
  const data = await res.json();
  btn.textContent = 'Generate Keys';
  btn.disabled    = false;

  if (data.error) { alert('Error: ' + data.error); return; }
  document.getElementById('rsa-private').value = data.private_key;
  document.getElementById('rsa-public').value  = data.public_key;
}

async function doRsaEncrypt() {
  const message    = document.getElementById('rsa-plain-input').value.trim();
  const public_key = document.getElementById('rsa-public').value.trim();
  if (!message)    { alert('Please enter a message.'); return; }
  if (!public_key) { alert('Please generate keys first.'); return; }

  const res  = await fetch('/api/rsa/encrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, public_key })
  });
  const data = await res.json();
  if (data.error) { alert('Error: ' + data.error); return; }
  document.getElementById('rsa-cipher-output').value = data.result;
  document.getElementById('rsa-cipher-input').value  = data.result;
}

async function doRsaDecrypt() {
  const ciphertext = document.getElementById('rsa-cipher-input').value.trim();
  const private_key = document.getElementById('rsa-private').value.trim();
  if (!ciphertext)  { alert('Please enter a ciphertext.'); return; }
  if (!private_key) { alert('Please generate keys first.'); return; }

  const res  = await fetch('/api/rsa/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ciphertext, private_key })
  });
  const data = await res.json();
  if (data.error) { alert('Error: ' + data.error); return; }
  document.getElementById('rsa-plain-output').value = data.result;
}