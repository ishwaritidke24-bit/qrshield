import "dotenv/config";
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

try {
  const response = await ai.models.generateContent({
    model: "gemma-4-26b-a4b-it",
    contents: "Explain in one simple sentence what a QR code is.",
  });

  console.log("\n✅ GEMMA WORKS!\n");
  console.log(response.text);
} catch (error) {
  console.error("\n❌ GEMMA ERROR\n");
  console.error(error);
}