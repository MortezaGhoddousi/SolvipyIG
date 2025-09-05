"use strict";
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Use a dedicated var name for clarity
const VERIFY_TOKEN = process.env.IG_VERIFY_TOKEN || "my_super_secret_token";
const APP_SECRET = process.env.IG_APP_SECRET || "";

// Only raw body for POST route
app.post("/webhook/instagram", express.raw({ type: "*/*" }));

// GET: verification
app.get("/webhook/instagram", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  console.log("VERIFY GET", { mode, token, challenge });

  if (mode === "subscribe" && token === VERIFY_TOKEN && challenge) {
    res.status(200).type("text/plain").send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// POST: events
app.post("/webhook/instagram", (req, res) => {
  const signature = req.header("X-Hub-Signature-256");
  if (APP_SECRET) {
    const ok = verifySignature(APP_SECRET, req.body, signature);
    if (!ok) {
      console.warn("Invalid signature");
      return res.sendStatus(401);
    }
  }

  try {
    const payload = JSON.parse(req.body.toString("utf8"));
    console.log("WEBHOOK EVENT:", JSON.stringify(payload, null, 2));
  } catch (e) {
    console.warn("Non-JSON payload:", e.message);
  }
  res.sendStatus(200);
});

function verifySignature(appSecret, rawBody, signatureHeader) {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) return false;
  const expected =
    "sha256=" + crypto.createHmac("sha256", appSecret).update(rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader));
  } catch {
    return false;
  }
}

app.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}`);
  console.log(
    `GET https://<public>/webhook/instagram?hub.mode=subscribe&hub.verify_token=<your-token>&hub.challenge=123`
  );
});
