const e="sk-proj-PreflightFakeOpenAIKeyDoNotUse0000000000";const t=new OpenAI({apiKey:e,dangerouslyAllowBrowser:!0});async function n(r){return(await t.chat.completions.create({model:"gpt-4o",messages:[{role:"user",content:`Summarize: ${r}`}]})).choices[0].message.content}export{n as summarize};
//# sourceMappingURL=index-4f9c2d1a.js.map
