require("dotenv").config();
const express = require("express");
const crypto = require("crypto");

const app = express();

// Keep the raw body so we can verify Meta's signature
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// 1) Verification: Meta calls this once when you save the webhook
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === process.env.VERIFY_TOKEN) {
    console.log("Webhook verified");
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

// 2) Receive events: messages, delivery status, etc.
app.post("/webhook", (req, res) => {
  // Verify the request really came from Meta
  const signature = req.get("X-Hub-Signature-256");
  const expected =
    "sha256=" +
    crypto
      .createHmac("sha256", process.env.APP_SECRET)
      .update(req.rawBody)
      .digest("hex");

  if (!signature || signature !== expected) {
    return res.sendStatus(401);
  }

  // Acknowledge immediately, then process
  res.sendStatus(200);

  const value = req.body.entry?.[0]?.changes?.[0]?.value;
  const message = value?.messages?.[0];

  if (message) {
    console.log("From:", message.from);
    console.log("Type:", message.type);
    console.log("Text:", message.text?.body);
  }
});

app.listen(process.env.PORT, () =>
  console.log(`Listening on port ${process.env.PORT}`)
);
