// Serverless function for Vercel
import crypto from "crypto";

// Disable Vercel's JSON parser so we can read the RAW body (required for signature verify)
export const config = {
  api: { bodyParser: false },
};

const VERIFY_TOKEN = process.env.IG_VERIFY_TOKEN || "my_super_secret_token";
const APP_SECRET   = process.env.IG_APP_SECRET || "";

// Helper: read raw body as Buffer
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

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

export default async function handler(req, res) {
  // 1) GET: Verification
  if (req.method === "GET") {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    console.log("VERIFY GET", { mode, token, challenge });

    if (mode === "subscribe" && token === VERIFY_TOKEN && challenge) {
      res.status(200).setHeader("Content-Type", "text/plain").send(challenge);
    } else {
      res.status(403).end();
    }
    return;
  }

  // 2) POST: Events
  if (req.method === "POST") {
    const raw = await readRawBody(req);

    if (APP_SECRET) {
      const sig = req.headers["x-hub-signature-256"];
      if (!verifySignature(APP_SECRET, raw, sig)) {
        console.warn("Invalid signature");
        return res.status(401).end();
      }
    }

    try {
      const payload = JSON.parse(raw.toString("utf8"));
      console.log("WEBHOOK EVENT:", JSON.stringify(payload, null, 2));
    } catch (e) {
      console.warn("Non-JSON payload:", e.message);
    }
    return res.status(200).end();
  }

  res.setHeader("Allow", "GET, POST");
  res.status(405).end("Method Not Allowed");
}
