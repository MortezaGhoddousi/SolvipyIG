"use strict";
require("dotenv").config();
const crypto = require("crypto");

const VERIFY_TOKEN = process.env.IG_VERIFY_TOKEN || "my_super_secret_token";
const APP_SECRET = process.env.IG_APP_SECRET || "";

module.exports = async (req, res) => {
    if (req.method === "GET") {
        const mode = req.query["hub.mode"];
        const token = req.query["hub.verify_token"];
        const challenge = req.query["hub.challenge"];
        if (mode === "subscribe" && token === VERIFY_TOKEN && challenge) {
            return res.status(200).type("text/plain").send(challenge);
        }
        return res.sendStatus(403);
    }

    if (req.method === "POST") {
        const signature = req.headers["x-hub-signature-256"];
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const rawBody = Buffer.concat(chunks);

        if (APP_SECRET) {
            const expected =
                "sha256=" +
                crypto
                    .createHmac("sha256", APP_SECRET)
                    .update(rawBody)
                    .digest("hex");
            const ok =
                signature &&
                signature.startsWith("sha256=") &&
                crypto.timingSafeEqual(
                    Buffer.from(expected),
                    Buffer.from(signature)
                );
            if (!ok) return res.sendStatus(401);
        }

        try {
            const payload = JSON.parse(rawBody.toString("utf8"));
            console.log("WEBHOOK EVENT:", JSON.stringify(payload, null, 2));
        } catch {}
        return res.sendStatus(200);
    }

    res.status(405).send("Method Not Allowed");
};
