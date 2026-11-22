# Locard: The Long Way

<img width="800" height="480" alt="image" src="https://github.com/user-attachments/assets/6d48ed85-814c-4b4f-bea8-ffb5082aefc4" />


## It started with MiniCPM

It all began with a conversation about **MiniCPM**.

I was intrigued by the idea that a relatively small language model could be genuinely useful. The enormous models made sense: give them enough resources and they could do impressive things. But how could a much smaller one still deliver? What could you realistically ask of it? Where was the intelligence coming from, and where did the limitations begin?

Then came the dangerous question: **What if we used it for digital forensics?**

ChatGPT was enthusiastic. “Great idea,” was the gist of the response. Yeah, I know. LLMs have a tendency to flatter, especially OpenAI (They're working on it: https://mixed-news.com/en/openai-gpt-6-chatgpt-less-flattering-shorter-free-go/). My AI assistant said it totally doable. It does not have to spend its evenings and Weekends implementing it.

<img width="360" height="260" alt="image" src="https://github.com/user-attachments/assets/17302a22-1311-4ba1-a353-ba89eaa5f932" />

A small local model might help an investigator ask ordinary questions about evidence, connect related observations, and explain what happened without shipping an entire case to a cloud provider. 

## 6 steps

<img width="1468" height="750" alt="image" src="https://github.com/user-attachments/assets/dadc31d7-b54b-4265-a097-bb9a923143f1" />

The software started with 6 steps. OpenAI had a very clear roadmap and delivery in mind. Great! 

There is another strange part of this story that would have sounded implausible a few years ago: **I am not programming Locard myself.**

I used to program. But with Locard, my daily development method became something different. I describe a problem to one AI. Together we shape an implementation prompt. I give that prompt to another AI—Codex—which writes and revises the code. I examine what it reports, try the software, point out what is wrong, and send it back for another round.

**I have one AI prompting another AI to generate code. Welcome to 2026.**

I am not pretending that I would type Python faster than the coding agent. I would not. At the work of producing and modifying code, AI is faster than me and often better.

So my job gradually changed. I became the product owner, test analyst, architect, reviewer, and sometimes the manager. I would read an AI's explanation, challenge its assumptions, send it to investigate a defect, reject the wrong solution, and insist on preserving the evidence and the bigger goal.

Step 1 to 5 were done in a few weeks. Just need to review the user interface and we're good to go!

## Oh, the humanity!

<img width="700" height="500" alt="image" src="https://github.com/user-attachments/assets/799841df-3a94-4cd4-8e72-cdd6c3c51548" />

I wanted the interface to be text. And Locard was verbose inside out. You had to enter extremely long and complex commands and Locard would answer with extremely, complex, and pedantic answers. And MiniCPM... Well, let's put it this way. I have rocks in my driveway that are smarter than MiniCPM. It's not fair. MiniCPM is awesome. It's just I don't think it is the right model for this job, contrary to what my LLM told me.

And then, the more I tried Locard the more I saw it fall flat on its face. It was pedantic, impractical, and really unusable by a human.


So I tried Qwen 4b.

<img width="360" height="260" alt="image" src="https://github.com/user-attachments/assets/65b37453-b7dc-4df8-8090-002bf5c1af21" />

Qwen 4b was better but it did not cut it. Now, the issue is that I don't have a $6000 gaming machine at home and I refuse to pay the outrageous price of today's IT. I can't test bigger local models.

Anthropic, DeepSeek, OpenAI and Google could laugh at me. I will use their greater power for my task. So much for "your data never leaves the forensic environment" stance. But I'm not done yet. I still believe Locard can work with Local AI first in mind.

<img width="360" height="260" alt="image" src="https://github.com/user-attachments/assets/71eb7e5e-5ed1-4671-a18a-0a27fefd9ed5" />

So now that I call the big dawgs, it will be a breeze, right? I mean we can even go further. There's There’s no way a forensic investigator would learn so mega long and complex Locard command. My idea is to go to the next phase with full AI mode.
1 Plug a copy of the SSD of the machine to investigate to the machine where Locard run.
2 Let Locard chug the SSD data.
3 Describe what you think happen.
4 Let Locard look for evidence and ask you questions.
5 Let Locard give its conclusions and you to approve.
6 Let Locard write the report. Thank you. Good bye. Done.

That would be awesome, right?


## Pedantic, rigourous and stuborn Locard

Locard had to ingest artifacts, normalize them, preserve their identities, associate them with sources, and make the results searchable. Even this mundane work carried traps. 

A forensic tool can be wrong in a very professional-looking way. Analyst assertions versus artifact-reported information, observations versus hypotheses, evidence sources versus host claims, known limitations versus actual failures.



<img width="360" height="260" alt="image" src="https://github.com/user-attachments/assets/3c0db642-174e-4bfe-aca6-32adbf7347dc" />

Ingesting a disk properly took 2 months (All my weekends, all my evenings). And yet, sometimes it fails because Locard does not consider the condition as perfect to chug the data. Bro! Do your best effort to chug the data and add a comment or warning about the context but don't flat out refuse to scan the disk.




<img width="360" height="260" alt="image" src="https://github.com/user-attachments/assets/4d7a7702-330a-4784-8e74-48f9e3ca27f7" />

I was naively thinking that Locard would talk to the AI in free text format and retrieve the answer for me to approve. Nope. Codex insisted that the data must be strictly format input and output. And guess what? ChatGPT, Claude, and Gemini cannot agree on that format. So I have to adapt for each LLM. DeepSeek's API is just OpenAI's API. I wanted to do Grok but I gave up. Also, I might not do Gemini. The obvious answer was to use OpenRouter or LiteLLM. ChatGPT recommended LiteLLM but there's so many changes to the request that I am now challenging if writing a procedure directly for each LLM would not have been better.



## Coding through AI

Again, LLMs are awesome. They're better than me. But sometimes, they get stuck in a loop to fix a minutia. They insist on running lengthy and expensive tests that bring little. I've spent 5 nights working on a useless item that the AI was trying to fix like a fly is trying to go through the glass of a closed window. 

We have an agreement with my AI. I am polite and respectful. I expect my AI to challenge my challenges and questions.

I've learned a few things

**Forensic rigor can become an obstacle to forensic work.** 

**Progress indicators can break progress.** 

**A common AI interface is not common AI behavior.**

**A model can cite evidence and still miss the point.** 

**A tool can be safer and harder to use at the same time.**

## What remains on the other side of the mountain

To this day, Locard is still unable to reconstruct an incident. 
That hurts.

And yet, if I ask an LLM to help me perform a forensic analysis without Locard in the way, it works, most of the time.

<img width="607" height="368" alt="image" src="https://github.com/user-attachments/assets/423853f3-7a30-49c0-8228-3482c6fad55f" />

Locard might fail, as a project but I've learned so much in the process.

The thing is, Locard might be stuborn but I am relentless.
