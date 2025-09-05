// api/instagram.js
"use strict";
require("dotenv").config();
const crypto = require("crypto");

const VERIFY_TOKEN = process.env.IG_VERIFY_TOKEN || "my_super_secret_token";
const APP_SECRET = process.env.IG_APP_SECRET || "";

module.exports = async (req, res) => {
    // Instagram verification (GET)
    if (req.method === "GET") {
        const mode = req.query["hub.mode"];
        const token = req.query["hub.verify_token"];
        const challenge = req.query["hub.challenge"];

        console.log("VERIFY GET", { mode, token, challenge });
        if (mode === "subscribe" && token === VERIFY_TOKEN && challenge) {
            res.status(200).type("text/plain").send(challenge);
        } else {
            res.sendStatus(403);
        }
        return;
    }

    // Webhook events (POST) — read RAW body
    if (req.method === "POST") {
        const signature = req.headers["x-hub-signature-256"];

        // Read the raw request body (no body parser here)
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const rawBody = Buffer.concat(chunks);

        if (APP_SECRET) {
            const ok = verifySignature(APP_SECRET, rawBody, signature);
            if (!ok) {
                console.warn("Invalid signature");
                res.sendStatus(401);
                return;
            }
        }

        try {
            const payload = JSON.parse(rawBody.toString("utf8"));
            console.log("WEBHOOK EVENT:", JSON.stringify(payload, null, 2));
        } catch (e) {
            console.warn("Non-JSON payload:", e.message);
        }

        res.sendStatus(200);
        return;
    }

    res.status(405).send("Method Not Allowed");
};

function verifySignature(appSecret, rawBody, signatureHeader) {
    if (!signatureHeader || !signatureHeader.startsWith("sha256="))
        return false;
    const expected =
        "sha256=" +
        crypto.createHmac("sha256", appSecret).update(rawBody).digest("hex");
    try {
        return crypto.timingSafeEqual(
            Buffer.from(expected),
            Buffer.from(signatureHeader)
        );
    } catch {
        return false;
    }
}
