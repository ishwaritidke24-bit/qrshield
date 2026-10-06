import "dotenv/config";
import { GoogleGenAI } from "@google/genai";
import fs from "node:fs";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const image = fs.readFileSync("./uploads/test-poster.png", {
  encoding: "base64",
});

try {
  const response = await ai.models.generateContent({
    model: "gemma-4-26b-a4b-it",
    contents: [
      {
        inlineData: {
          mimeType: "image/png",
          data: image,
        },
      },
      {
        text: `
Analyze this poster for QRShield.

Tell me:
1. What is the poster about?
2. What organization or offer does it claim?
3. What action is the user being asked to take?
4. Is it claiming the offer is free?
5. What deadline is mentioned?
6. List any potentially important or suspicious claims.

Keep the answer structured and simple.
`,
      },
    ],
  });

  console.log("\n✅ GEMMA IMAGE ANALYSIS\n");
  console.log(response.text);
} catch (error) {
  console.error("\n❌ ERROR\n");
  console.error(error);
}