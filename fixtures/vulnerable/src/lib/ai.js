import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: 'sk-proj-PreflightFakeOpenAIKeyDoNotUse0000000000', dangerouslyAllowBrowser: true });

export async function summarize(text) {
  const res = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: `Summarize: ${text}` }],
  });
  return res.choices[0].message.content;
}
