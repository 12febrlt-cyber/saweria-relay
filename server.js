const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 8080;
const SAWERIA_WEBHOOK_TOKEN = process.env.SAWERIA_WEBHOOK_TOKEN || "";
const API_KEY = process.env.API_KEY || "ganti-dengan-api-key-rahasia";

const pendingDonations = [];
const donationHistory = [];
const MAX_HISTORY = 100;

function verifySignature(req) {
  if (!SAWERIA_WEBHOOK_TOKEN) return true;
  const signature = req.headers["x-saweria-webhook-signature"];
  if (!signature) return false;
  const expected = crypto
    .createHmac("sha256", SAWERIA_WEBHOOK_TOKEN)
    .update(JSON.stringify(req.body))
    .digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

function validateApiKey(req, res) {
  const key = req.headers["x-api-key"] || req.query.api_key;
  if (key !== API_KEY) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

app.post("/webhook/saweria", (req, res) => {
  if (!verifySignature(req)) {
    return res.status(403).json({ error: "Invalid signature" });
  }
  const body = req.body;
  const donation = {
    id: body.id || crypto.randomUUID(),
    donator_name: body.donator_name || body.name || "Anonim",
    amount: parseInt(body.amount_raw || body.amount || 0),
    message: body.message || "",
    media: body.media || null,
    timestamp: new Date().toISOString(),
  };
  pendingDonations.push(donation);
  donationHistory.unshift(donation);
  if (donationHistory.length > MAX_HISTORY) donationHistory.splice(MAX_HISTORY);
  res.status(200).json({ success: true });
});

app.get("/donations", (req, res) => {
  if (!validateApiKey(req, res)) return;
  const toSend = pendingDonations.splice(0, pendingDonations.length);
  res.json({ donations: toSend, count: toSend.length });
});

app.get("/donations/history", (req, res) => {
  if (!validateApiKey(req, res)) return;
  const limit = parseInt(req.query.limit) || 20;
  res.json({ donations: donationHistory.slice(0, limit), total: donationHistory.length });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: Math.floor(process.uptime()), pending: pendingDonations.length });
});

// ============================================================
// TAMBAHAN: Endpoint /tiers
// Letakkan di server.js, sebelum app.listen(...)
// ============================================================

// Daftar nominal donasi yang disarankan (tampil sebagai tombol di Roblox)
const DONATION_TIERS = [
  { id: 1, amount: 10000 },
  { id: 2, amount: 25000 },
  { id: 3, amount: 50000 },
  { id: 4, amount: 100000 },
  { id: 5, amount: 500000 },
  { id: 6, amount: 1000000 },
];

app.get("/tiers", (req, res) => {
  if (!validateApiKey(req, res)) return;
  res.json({ tiers: DONATION_TIERS });
});

app.get("/", (req, res) => {
  res.json({ message: "Saweria Relay Server aktif" });
});

app.listen(PORT, () => {
  console.log("Relay server berjalan di port " + PORT);
});
