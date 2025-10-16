const express = require("express");
const axios = require("axios");
const helmet = require("helmet");

const app = express();
app.use(express.json());
app.use(helmet());

// simpan key->ip di memori (untuk testing, nanti bisa pakai Redis)
const keyIpMap = new Map();

const SELLER_KEY = process.env.SELLER_KEY;
const APP_NAME = process.env.APP_NAME;
const KEYAUTH_HOST = "https://keyauth.cc";

app.post("/validate", async (req, res) => {
  const key = req.body?.key;
  if (!key) return res.status(400).json({ status: "error", message: "missing key" });
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

  // 1️⃣ Verifikasi ke KeyAuth
  try {
    const resp = await axios.get(`${KEYAUTH_HOST}/api/seller/?sellerkey=${SELLER_KEY}&type=verify&key=${key}&app=${APP_NAME}`);
    const data = resp.data;
    if (data.success !== true) return res.json({ status: "invalid" });
  } catch (err) {
    console.error(err.message);
    return res.json({ status: "error", message: "keyauth error" });
  }

  // 2️⃣ Cek IP
  const known = keyIpMap.get(key);
  if (!known) {
    keyIpMap.set(key, clientIp);
    return res.json({ status: "active", bound_ip: clientIp });
  }
  if (known === clientIp) return res.json({ status: "active" });
  return res.json({ status: "used_by_other_ip", owner_ip: known });
});

app.listen(10000, () => console.log("✅ Server running on port 10000"));
