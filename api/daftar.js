// Menerima pendaftaran dari form -> Supabase (tabel `pendaftaran`, foto di bucket privat `pendaftaran-foto`).
// Memakai service_role key yang HANYA ada di Environment Variables Vercel (tidak pernah dikirim ke browser).
const crypto = require('crypto');

const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const BUCKET = process.env.FOTO_BUCKET || 'pendaftaran-foto';
const MAX_PER_HOUR = Number(process.env.MAX_PER_HOUR) || 15; // batas pendaftaran per IP per jam
const SALT = process.env.IP_SALT || 'ansor-daftar';

const auth = (extra) => ({ apikey: SB_KEY, Authorization: 'Bearer ' + SB_KEY, ...extra });

async function rest(method, p, body, extra) {
  const r = await fetch(`${SB_URL}/rest/v1/${p}`, {
    method,
    headers: auth({ 'Content-Type': 'application/json', ...extra }),
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000)
  });
  const text = await r.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (e) { /* bukan JSON */ }
  return { ok: r.ok, status: r.status, json, text };
}

const clean = (v, n = 200) => String(v == null ? '' : v).trim().slice(0, n);
const ALPH = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // tanpa huruf/angka yang mirip (O/0, I/1)
function buatKode() {
  let s = '';
  for (let i = 0; i < 6; i++) s += ALPH[crypto.randomInt(ALPH.length)];
  return 'DFT-' + s;
}

function parseFoto(dataUrl) {
  if (!dataUrl) return null;
  const s = String(dataUrl);
  const i = s.indexOf(';base64,');
  if (!s.startsWith('data:image/') || i < 0) return { error: 'Format foto tidak valid' };
  const buf = Buffer.from(s.slice(i + 8), 'base64');
  if (buf.length < 100) return { error: 'Foto tidak valid' };
  if (buf.length > 3 * 1024 * 1024) return { error: 'Foto terlalu besar. Pilih foto lain.' };
  const head = buf.subarray(0, 12);
  if (head[0] === 0xff && head[1] === 0xd8) return { buf, mime: 'image/jpeg', ext: 'jpg' };
  if (head.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) return { buf, mime: 'image/png', ext: 'png' };
  if (head.subarray(0, 4).toString() === 'RIFF' && head.subarray(8, 12).toString() === 'WEBP') return { buf, mime: 'image/webp', ext: 'webp' };
  return { error: 'Foto harus JPG, PNG, atau WEBP' };
}

async function hapusFoto(p) {
  try {
    await fetch(`${SB_URL}/storage/v1/object/${BUCKET}/${p}`, { method: 'DELETE', headers: auth(), signal: AbortSignal.timeout(10000) });
  } catch (e) { /* best effort */ }
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Metode tidak diizinkan' });
  if (!SB_URL || !SB_KEY) return res.status(500).json({ error: 'Server belum dikonfigurasi (cek Environment Variables).' });

  const b = req.body && typeof req.body === 'object' ? req.body : {};
  if (b.website) return res.status(200).json({ ok: true, kode: '', nama: '' }); // honeypot anti-bot

  const nama = clean(b.nama, 120);
  const nik = String(b.nik || '').replace(/\D/g, '');
  const pac = clean(b.pac);
  const tempatLahir = clean(b.tempatLahir, 80);
  const tglLahir = /^\d{4}-\d{2}-\d{2}$/.test(b.tglLahir || '') && !isNaN(new Date(b.tglLahir)) ? b.tglLahir : '';
  if (!nama || !pac) return res.status(400).json({ error: 'Nama lengkap dan PAC/Utusan wajib diisi' });
  if (!/^\d{16}$/.test(nik)) return res.status(400).json({ error: 'NIK harus 16 digit angka' });
  if (!tempatLahir || !tglLahir) return res.status(400).json({ error: 'Tempat dan tanggal lahir wajib diisi' });
  if (b.setuju !== true) return res.status(400).json({ error: 'Pernyataan kesediaan mengikuti kaderisasi wajib dicentang' });

  const foto = parseFoto(b.foto);
  if (foto && foto.error) return res.status(400).json({ error: foto.error });

  try {
    // 1) pembatas spam per IP (IP disimpan sebagai hash, bukan IP asli)
    const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '';
    const ipHash = crypto.createHash('sha256').update(SALT + ip).digest('hex').slice(0, 32);
    const since = new Date(Date.now() - 3600e3).toISOString();
    const rl = await rest('GET', `pendaftaran?select=id&ip_hash=eq.${ipHash}&created_at=gte.${encodeURIComponent(since)}&limit=${MAX_PER_HOUR}`);
    if (!rl.ok) throw new Error('rate-limit query ' + rl.status + ' ' + rl.text.slice(0, 120));
    if (Array.isArray(rl.json) && rl.json.length >= MAX_PER_HOUR) {
      return res.status(429).json({ error: 'Terlalu banyak pendaftaran dari perangkat ini. Coba lagi nanti.' });
    }

    // 2) NIK ganda: sudah mendaftar online, atau sudah jadi peserta di aplikasi panitia
    const d1 = await rest('GET', `pendaftaran?select=id&nik=eq.${nik}&limit=1`);
    if (!d1.ok) throw new Error('cek nik pendaftaran ' + d1.status + ' ' + d1.text.slice(0, 120));
    let sudah = Array.isArray(d1.json) && d1.json.length > 0;
    if (!sudah) {
      const d2 = await rest('GET', `documents?select=id&collection=eq.peserta&data->>nik=eq.${nik}&limit=1`);
      if (d2.ok) sudah = Array.isArray(d2.json) && d2.json.length > 0; // kalau gagal dibaca, unique index NIK tetap melindungi
    }
    if (sudah) return res.status(409).json({ error: 'NIK ini sudah terdaftar sebagai peserta.' });

    // 3) simpan foto (jika ada), lalu datanya
    const kode = buatKode();
    let fotoPath = null;
    if (foto) {
      fotoPath = `${kode}-${crypto.randomBytes(4).toString('hex')}.${foto.ext}`;
      const up = await fetch(`${SB_URL}/storage/v1/object/${BUCKET}/${fotoPath}`, {
        method: 'POST', headers: auth({ 'Content-Type': foto.mime }), body: foto.buf, signal: AbortSignal.timeout(20000)
      });
      if (!up.ok) throw new Error('upload foto ' + up.status + ' ' + (await up.text()).slice(0, 120));
    }

    const data = {
      nama, nik, pac, tempatLahir, tglLahir,
      jabatanOrganisasi: clean(b.jabatanOrganisasi),
      hp: clean(b.hp, 30), email: clean(b.email), alamat: clean(b.alamat, 400),
      pendidikan: clean(b.pendidikan), pekerjaan: clean(b.pekerjaan)
    };
    const ins = await rest('POST', 'pendaftaran', { kode, nik, nama, data, foto_path: fotoPath, ip_hash: ipHash, status: 'baru' }, { Prefer: 'return=minimal' });
    if (!ins.ok) {
      if (fotoPath) await hapusFoto(fotoPath);
      if (ins.status === 409) return res.status(409).json({ error: 'NIK ini sudah terdaftar sebagai peserta.' });
      throw new Error('insert ' + ins.status + ' ' + ins.text.slice(0, 160));
    }
    return res.status(200).json({ ok: true, kode, nama });
  } catch (e) {
    console.error('daftar gagal:', e.message);
    return res.status(502).json({ error: 'Layanan sedang bermasalah. Coba lagi beberapa saat lagi.' });
  }
};
