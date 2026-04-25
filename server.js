import express from "express";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 10000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "public")));

// Simple metals endpoint (safe starter)
app.get("/api/metals", async (req, res) => {
  try {
    // FREE fallback data (replace later with real API)
    res.json({
      gold: 2325.12,
      silver: 27.45,
      platinum: 980.55,
      palladium: 1022.30
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch metals" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
