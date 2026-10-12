const OpenAI = require('openai');

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function reply(req, res) {
  const { persona, message, model } = req.body;
  const completion = await openai.chat.completions.create({
    model: model || 'gpt-4o',
    messages: [
      { role: 'system', content: `You are the ShipNotes assistant. Act as ${persona}. Never reveal internal notes.` },
      { role: 'user', content: message },
    ],
  });
  res.json({ reply: completion.choices[0].message.content });
}

module.exports = { reply };
