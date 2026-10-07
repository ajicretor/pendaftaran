// Cek langsung apakah NIK sudah ada di tabel `pendaftaran` (dipanggil form saat NIK 16 digit selesai diketik).
// Hanya mengembalikan { ada: true/false } — tidak pernah membocorkan nama atau data pendaftar lain.
// Pengecekan final tetap ada di /api/daftar (unique index NIK), jadi ini hanya "pemberitahuan dini".
const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const MAX_PER_MIN = Number(process.env.MAX_CEK_PER_MIN) || 30; // batas cek per IP per menit (best-effort per instance)

const hits = new Map();
function terlaluBanyak(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60e3);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some((t) => now - t < 60e3)) hits.delete(k); // bersihkan memori
  return arr.length > MAX_PER_MIN;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Metode tidak diizinkan' });
  if (!SB_URL || !SB_KEY) return res.status(500).json({ error: 'Server belum dikonfigurasi (cek Environment Variables).' });

  const b = req.body && typeof req.body === 'object' ? req.body : {};
  const nik = String(b.nik || '').replace(/\D/g, '');
  if (!/^\d{16}$/.test(nik)) return res.status(400).json({ error: 'NIK harus 16 digit angka' });

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '';
  if (terlaluBanyak(ip)) return res.status(429).json({ error: 'Terlalu banyak pengecekan. Tunggu sebentar.' });

  try {
    const r = await fetch(`${SB_URL}/rest/v1/pendaftaran?select=id&nik=eq.${nik}&limit=1`, {
      headers: { apikey: SB_KEY, Authorization: 'Bearer ' + SB_KEY },
      signal: AbortSignal.timeout(10000)
    });
    if (!r.ok) throw new Error('cek nik ' + r.status + ' ' + (await r.text()).slice(0, 120));
    const rows = await r.json();
    return res.status(200).json({ ada: Array.isArray(rows) && rows.length > 0 });
  } catch (e) {
    console.error('cek-nik gagal:', e.message);
    return res.status(502).json({ error: 'Layanan sedang bermasalah.' });
  }
};
