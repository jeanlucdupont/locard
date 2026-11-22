# Locard: The Long Way

<img width="800" height="480" alt="image" src="https://github.com/user-attachments/assets/6d48ed85-814c-4b4f-bea8-ffb5082aefc4" />


## It started with MiniCPM

It all began with a conversation about **MiniCPM**.

I was intrigued by the idea that a relatively small language model could be genuinely useful. The enormous models made sense: give them enough resources and they could do impressive things. But how could a much smaller one still deliver? What could you realistically ask of it? Where was the intelligence coming from, and where did the limitations begin?

Then came the dangerous question: **What if we used it for digital forensics?**

ChatGPT was enthusiastic. “Great idea,” was the gist of the response. Yeah, I know. LLMs have a tendency to flatter, especially OpenAI (They're working on it: https://mixed-news.com/en/openai-gpt-6-chatgpt-less-flattering-shorter-free-go/). My AI assistant said it totally doable. It does not have to spend its evenings and Weekends implementing it.

<img width="750" height="512" alt="image" src="https://github.com/user-attachments/assets/17302a22-1311-4ba1-a353-ba89eaa5f932" />

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

<img width="560" height="760" alt="image" src="https://github.com/user-attachments/assets/799841df-3a94-4cd4-8e72-cdd6c3c51548" />

I wanted the interface to be text. And Locard was verbose inside out. You had to enter extremely long and complex commands and Locard would answer with extremely, complex, and pedantic answers. And MiniCPM... Well, let's put it this way. I have rocks in my driveway that are smarter than MiniCPM. It's not fair. MiniCPM is awesome. It's just I don't think it is the right model for this job, contrary to what my LLM told me.

And then, the more I tried Locard the more I saw it fall flat on its face. It was pedantic, impractical, and really unusable by a human.


So I tried Qwen 4b.

<img width="600" height="360" alt="image" src="https://github.com/user-attachments/assets/65b37453-b7dc-4df8-8090-002bf5c1af21" />

Qwen 4b was better but it did not cut it. Now, the issue is that I don't have a $6000 gaming machine at home and I refuse to pay the outrageous price of today's IT. I can't test bigger local models.

Anthropic, DeepSeek, OpenAI and Google could laugh at me. I will use their greater power for my task. So much for "your data never leaves the forensic environment" stance. But I'm not done yet. I still believe Locard can work with Local AI first in mind.

<img width="560" height="360" alt="image" src="https://github.com/user-attachments/assets/71eb7e5e-5ed1-4671-a18a-0a27fefd9ed5" />

So now that I call the big dawgs, it will be a breathe, right? I mean we can even go further. There's no way a forensic would learn so mega long and complex Locard command. My idea is to go to the next phase with full AI mode.
1 Plug a copy of the SSD of the machine to investigate to the machine where Locard run.
2 Let Locard chug the SSD data.
3 Describe what you think happen.
4 Let Locard look for evidence and ask you questions.
5 Let Locard give its conclusions and you to approve.
6 Let Locard write the report. Thank you. Good bye. Done.

That would be awesome, right?


## Pedantic, rigourous, and stuborn Locard

Locard had to ingest artifacts, normalize them, preserve their identities, associate them with sources, and make the results searchable. Even this mundane work carried traps. 

A forensic tool can be wrong in a very professional-looking way. Analyst assertions versus artifact-reported information, observations versus hypotheses, evidence sources versus host claims, known limitations versus actual failures.


<img width="550" height="370" alt="image" src="https://github.com/user-attachments/assets/3c0db642-174e-4bfe-aca6-32adbf7347dc" />

Ingesting a disk properly took 2 months (All my weekends, all my evenings). And yet, sometimes it fails because Locard does not consider the condition as perfect to chug the data. Bro! Do your best effort to chug the data and add a comment or warning about the context but don't flat out refuse to scan the disk.

<img width="690" height="430" alt="image" src="https://github.com/user-attachments/assets/4d7a7702-330a-4784-8e74-48f9e3ca27f7" />

I was naively thinking that Locard would talk to the AI in free text format and retrieve the answer for me to approve. Nope. Codex insisted that the data must be strictly format in and out. And guess what? ChatGPT, Claude, and Gemini cannot agree on that format. So I have to adapt for each LLM. DeepSeek is just OpenAI. I wanted to do Grok but I gave up. Also, I might not do Gemini. The obvious answer was to use OpenRouter or LiteLLM. ChatGPT recommended LiteLLM but there's so many changes to the request that I am now challenging if writing a procedure directly for each LLM would not have been better.


This became part of our rhythm: focused tests while developing, real manual acceptance on the intended workflow, broader regression work at the appropriate release boundary. Hundreds of green checkmarks are not a substitute for understanding what changed.

Beneath all this was a design promise we kept repeating: finish the CLI first, but build services a future local web interface can reuse. The eventual UI should not have to simulate an analyst typing commands into a terminal.

There was a very good reason for that. We were about to become intimately familiar with how exhausting that terminal could be.

## Interlude — I stopped writing code. I did not stop developing software.

nd this was not some effortless hobby running in the background. **Most of my evenings and weekends went into Locard.** Launch a test, read a console, find a regression, prepare another prompt, examine the fix, pull a new version, and do it again. Sometimes the reward was thousands of recovered forensic records. Sometimes the reward was a better error message. Sometimes the reward was learning that we had built an impressively sophisticated mechanism for not getting to the next screen.

The coding had become easier for me to delegate. The responsibility for deciding what mattered had not.

## Act II — The case that made everything real

Synthetic test fixtures are agreeable. They are small, well-behaved, and rarely bring their entire extended family of corrupted companion files.

A real Windows disk is less polite.

Our decisive experiment concerned suspicious activity on a Windows machine on **November 17, 2026**. We had already examined the incident through Defender telemetry. That made it an unusually useful benchmark: could Locard, knowing none of the answers, reconstruct the important activity from disk evidence alone?

The rules were clear. The briefing would be neutral. We would not tell Locard the suspicious command, the domains, the suspected technique, or what the earlier investigation had suggested. It needed to find the story itself, or fail honestly.

We mounted the evidence on **E:**, created a fresh case on **D:**, and called it `KFI-5070790-V2`. The source had an analyst-supplied machine identity and an America/Chicago time zone. The volume was not a frozen forensic image. That imperfection would follow us everywhere, as it should.

Then we started ingestion.

**Fifty-five minutes and thirty-one seconds later**, we had a case full of evidence and a very mixed report card.

Registry, EVTX and Prefetch had yielded **1,723,437 retained records** in total. MFT had failed. Browser History had failed. Registry transaction logs could not be replayed. Some hives were dirty. Several event logs were imperfect.

We had made considerable progress toward investigating the computer, except for two of the artifact families most useful for understanding what the user and system had actually done.

This was the point at which Locard stopped behaving like a software demonstration and started behaving like a forensic product under test.

## Act III — The MFT that was defeated by a progress indicator

The MFT had been a troublesome character for a while. We had compared native acquisition with independent extraction, investigated differences in bytes, watched staging space grow, and learned that a worker could be doing useful work long after a simplistic timeout had declared the job dead.

A timeout is meant to protect an investigator from a hung process. It should not protect them from a successful investigation.

So we made supervision progress-aware: a worker that advances should be allowed to continue. A worker that stops advancing should not run forever. We retained clear limits, cleanup rules and stage validation.

Then the real case failed again, for a different reason: **“MFT worker progress communication; staged output rejected.”**

Codex investigated and found an almost absurd Windows race. The worker published its progress to a tiny JSON file. The parent checked that file periodically. Under Windows file-sharing rules, the parent's brief read could prevent the worker from replacing it.

The parser could work successfully for minutes, finish reconstructing the MFT, and then lose the entire staged result because the final message saying “complete” could not replace a progress file.

The guardrail had tripped over its own shoelaces.

The fix was small in concept and important in practice: make the progress-file reads compatible with atomic replacement, and keep the integrity checks that decide whether staged evidence is safe to publish.

On the next MFT-only attempt, Locard worked for **21 minutes and 17 seconds** and retained **918,450 MFT records**. It reported **2,451 parsing errors**, so the result was partial. The surviving records were real; the limitations were real too.

We checked the case. We checked the audit. The old failed attempt remained in history. The new evidence was there. Nothing had quietly been rewritten to make the outcome look prettier.

For a project devoted to AI, one of our most satisfying victories was an entirely unglamorous line saying that 918,450 filesystem records had been retained.

And after another overnight exercise, we noticed that Locard could tell us everything about progress except how long the operation had taken. Eventually we added the clock.

After all the machinery, a stopwatch turned out to be a feature.

## Act IV — The SQLite journal that nearly became the investigation

Browser History looked straightforward. The Edge database was around eight megabytes. Surely we could ingest that.

Instead, Locard said no. A rollback journal existed alongside the SQLite database, and the tool refused to proceed.

We tried to be responsible. We learned to distinguish inactive journals from active ones. We built synthetic interrupted transactions. We introduced a recovery service that worked only on disposable copies, preserved hashes, recorded transformations, and refused to write to original evidence.

The tests passed. The real Browser History still yielded **zero records**.

Its journal was an awkward specimen. The first eight bytes were zero, while the remainder of the header was populated. A separate read-only diagnostic examined the file sizes, hashes, page counts and header geometry. The database declared **2,014 pages**, but the physical file contained **2,016**. The repeated hashes matched.

The evidence did not prove corruption. Nor did it prove that every transaction was consistent or complete.

We responded by writing more checks. Then more diagnostics. Then another proposal for further analysis.

Finally, the human investigator asked the question the project needed:

> “What are we doing? Why don't we just get the information from the browser instead of using very conservative measures to not get the info?”

That question changed the direction of the work.

We had confused forensic rigor with forensic paralysis. A real investigator can use imperfect evidence without pretending it is perfect. The correct response to an uncertain transaction is not necessarily to discard thousands of otherwise readable browsing records. It may be to read them carefully, preserve the uncertainty, and avoid claims the evidence cannot support.

So Locard gained a **best-effort immutable extraction** path. It worked on a protected copy, did not apply the questionable journal, and labeled the result as potentially incomplete.

**Five seconds later: 5,388 Browser records.**

There were **5,378 visits and 10 downloads**. The output was partial, explicitly noting that some transactions might not be represented and that the extra pages were not carved. But the evidence was finally available to investigate.

This gave us one of the central lessons of the project:

**Evidence accessibility, evidence consistency, and evidence completeness are not the same thing.**

A tool should be strict about its claims and practical about what it can learn.

The case now held **2,647,275 records** across all five families. The audit chain verified. We had collected enough evidence to begin the experiment we actually cared about.

Or so we thought.

## Act V — The wizard that sent us on a scavenger hunt

Our neutral briefing asked Locard to investigate potentially suspicious user-initiated activity on November 17, examine browser activity, downloads, execution and persistence, and build a timeline without assuming a compromise.

The guided workflow began well. It opened an editor. We entered the briefing. We saved it.

Then it asked: **“Proceed to explicit local evidence scope and assessment?”**

We answered yes.

The wizard stopped and told us which separate command to type next.

A wizard that asks whether to proceed, then explains how to proceed after exiting, is not quite the concierge experience we had in mind.

I had been trying to make Locard more human-friendly for some time. We grouped commands, cleaned up help, added colors, introduced a guided workflow, simplified labels, and tried to stop the terminal from looking like a database had exploded inside it. Each step was a real improvement in isolation. Taken together, they had not solved the problem.

The product was **overly complicated**. Its commands were increasingly specialized and its output could be nearly unreadable. To do something that should have felt natural—*investigate this day on this computer*—I had to remember which command created a briefing, which one analyzed it, which one assessed it, how to specify a source identifier, how to authorize a search, and which completely different command displayed a saved result. We had made a maze with better signs, but it was still a maze.

I kept asking for simpler screens. The AIs kept making the existing screens a little more elegant. We were polishing the machinery rather than removing the burden from the operator.

We manually analyzed the briefing, reviewed the proposed structure, accepted a cautious editorial summary, and entered the investigation window. Along the way we found that a source time zone could be stored in the case while the scope wizard still reported the incident time zone as unknown. The distinction was legitimate, but the interface did little to explain it.

Then came the hostname **`on`**.

An ordinary word from the briefing had been promoted to a computer name. Locard had discovered the sort of host that exists everywhere in prose and nowhere on the network.

We tightened hostname extraction. That fixed the new lead. Unfortunately, the stricter validator was also used when reopening a historical briefing that already contained the old accepted value.

Suddenly the case would not open. **`BRIEFING_MALFORMED`.**

The new software had decided that yesterday's accepted analyst record was no longer acceptable.

We fixed the compatibility reader without changing the old record. It was a beautiful illustration of an unglamorous truth: **when historical decisions are part of the evidence trail, backward compatibility becomes a matter of forensic integrity.**

The case reopened. The evidence counts matched. Ten completed audit sessions verified with no integrity failures.

We tried again.

## Act VI — Five hundred records and no story

Locard's improved time-scoped assessment could finally start from an authorized date and source without requiring a suspicious filename or domain. That was a meaningful advancement. An investigation should be able to start before the investigator knows what to look for.

It proposed searches across all five artifact families. We approved them.

About **28 seconds later**, Locard reported **495 distinct records** from Browser, EVTX, MFT, Prefetch and Registry. We had a chronology, evidence references, source boundaries, caveats and a saved assessment.

We also had an astonishing number of lines saying essentially the same thing:

“Browser record matches.”

“MFT metadata matches.”

“Event record matches.”

“Associated reported indicators: file metadata.”

Everything was precise, bounded and remarkably unhelpful to a human who wanted to know what happened.

The console advised us to inspect `--details`. The help for the command did not actually offer `--details`. The JSON alternative was enormous. The clipboard gave up. Our first attempt to capture it with PowerShell transcript saved only the tail because we started recording too late.

We had built a respectable library of forensic evidence. We had not built a particularly good librarian.

It was an uncomfortable moment for the person who had proposed an AI-assisted forensic application. I could read JSON and understand forensic artifacts. But why was I—the user—doing all this translation? If the software needed a thousand lines to describe what it had found, surely the AI should have been doing some of the work of making those lines intelligible.

Codex had seen a related problem earlier in the AI work: useful findings were sometimes available but absent from the final response because the prompt budget had not carried them forward. Evidence could be collected correctly, then lost somewhere between retrieval and explanation.

The warning was the same in both cases: **having information in the system is not the same as getting it to the investigator—or to the model—when it matters.**

At least the 495 records were saved, bounded and traceable. We did not need to collect them again. What we needed was a way to investigate them.

## Act VII — “Configured” is not “ready”

We authorized an autonomous OpenAI investigation. Locard asked permission to disclose evidence, decompose the question and use bounded synthesis requests. We agreed.

Then it stopped.

The last message told us to verify OpenAI investigation compatibility. It looked like a command, not an explanation. No useful analysis had occurred.

The provider was “configured,” we protested reasonably. Yes, said the code, but configured was not the same as compatibility-checked.

Autonomous investigation required a successful check cached in the **current running process**. Once we performed the explicit synthetic check, all relevant compatibility indicators became ready. The model was not rejected; the readiness prerequisite had simply not been met or explained properly.

Another rule entered the journal: **a safety check that is difficult to understand can look indistinguishable from a software failure.**

And when progress text said “Waiting for local AI...” during an explicitly OpenAI-backed operation, we learned the complementary lesson. The model routing may be correct and the message wrong, but the analyst cannot know that from a misleading screen.

Presentation is not decoration when it governs trust.

Having finally passed preflight, we tried again.

Then the authorization revealed that Locard's five-family assessment had become a **Browser-only investigation**.

Why?

The evidence IDs had been sorted. Browser came first alphabetically. The engine took the first twelve IDs and built its scope from them.

After all the work on investigative intelligence, **alphabetical order had quietly become the chief detective**.

We declined the authorization. No evidence was retrieved and no model was called. We fixed selection to sample across the five families deterministically, without expanding the budgets or smuggling in extra permission.

The new grant selected three Browser records, three EVTX records, two MFT records, two Prefetch records and two Registry records. It admitted that **483 assessment records had been omitted** and that the engine could inspect at most **six** of the twelve selected items. No follow-up searches were allowed.

That was not a broad investigation. But it was an honest, comprehensible grant.

We approved it.

## Act VIII — The first real answer, and why it was not enough

At last, Locard carried out a real autonomous AI investigation against the case.

It inspected **three evidence records**. Two analysis batches passed validation. A later batch failed validation, and the engine stopped, retaining the earlier accepted material. Two synthesis requests completed. A local explanation was saved at revision three.

The answer was marked **PARTIAL**.

The readable findings concerned a Chromium visit to a FortiClient EMS proxy SAML login address and a Windows event with **Event ID 41**. Without more context, neither established suspicious behavior. Locard did not reconstruct the known suspicious sequence. It did not independently discover the incident's key events.

We had wanted Sherlock Holmes. We received a cautious clerk who had looked at three documents and was admirably unwilling to invent the fourth.

There was disappointment in that. But there was also evidence of real progress.

The disclosed material stayed within the authorized grant. The invalid AI batch was rejected rather than promoted into a finding. Earlier accepted observations survived. Unknowns remained unknown. The underlying read view and cleanup were confirmed. An explanation was persisted rather than lost in a sea of scrolling terminal output.

Even the failure taught us something precise. The final report counted **four accumulated observations** but made only two evidence descriptions easy to identify. It showed the model asking questions without the authority to follow them. We were finally seeing the system's real bottleneck: not merely *can the AI respond?*, but *can it pursue the next useful question, inspect relevant evidence, and return a coherent, grounded explanation?*

That is a more important question than whether we can fit another twenty records into the first prompt.

## Interlude — “Blocked” does not mean “executed”

Throughout all these episodes, another case kept reminding us why some of Locard's caution was indispensable.

Earlier work had involved a suspicious download, possible follow-on command activity and a defensive blocking event. It was exactly the kind of situation a language model could turn into a polished but unjustified story.

The pieces were close in time. Filenames suggested relationships. It would be easy to write that a script had executed, persisted, and compromised a machine.

But a downloaded file is not proof of execution. A file timestamp is not a process instance. A defensive block is not evidence that the blocked action completed. A missing event does not prove that nothing occurred.

We learned to keep observations, interpretations, hypotheses and analyst decisions separate. A citation is useful; it is not an incantation that converts an attractive sentence into a fact.

This was also why rejecting the invalid AI batch during our first live investigation was the *right kind* of failure—even if we must now understand why that batch was rejected and improve the usefulness of the overall workflow.

The objective is not a timid assistant that refuses to say anything. It is an investigative assistant that knows the difference between being uncertain and being wrong.

## When the AIs lost the plot

The technical bugs were not the only loops. More than once, the conversation with my OpenAI assistant got stuck in a cycle of increasingly narrow corrections. A safeguard failed, so we made the safeguard more precise. The new rule blocked an edge case, so we added another distinction. The distinction needed a diagnostic, and the diagnostic suggested another validation step. Each suggestion was individually defensible. Taken together, they sometimes moved us further away from the thing we were trying to accomplish.

The Browser History saga was the clearest example. We were well on our way to becoming experts on a rollback journal while still having **zero browser visits to investigate**. I had to interrupt and provide the bigger picture: the goal was not to win an argument with SQLite. It was to get useful forensic information, preserve the originals, and tell the analyst what could not be trusted.

That felt familiar. It was what I would do with a human team. When talented people become absorbed in solving the problem immediately in front of them, a manager sometimes has to ask what the customer actually needs. In our case, the developers were AIs. The manager was still human.

The lesson was not that AI was incapable. On the contrary, it was capable enough to keep producing plausible next steps indefinitely. The danger was mistaking motion for direction. I had to supply the context, the priorities, the acceptance criteria, and occasionally the permission to stop engineering a perfect answer to the wrong question.

This also made the Dunning–Kruger metaphor less amusing and more useful. At the start, I underestimated the difficulty. Later, after so many detours, I risked underestimating what we had achieved. Both extremes distorted the picture. We had real forensic ingestion, durable audit trails, and functioning AI analysis. We also had a product I could barely use without a notebook of commands.

## The lessons we did not expect

**Forensic rigor can become an obstacle to forensic work.** The SQLite episode taught us to preserve original evidence and be explicit about limitations without throwing away readable data.

**Progress indicators can break progress.** A spinner is not just a nice animation. Its implementation must not interfere with a worker that is actually doing the work.

**History deserves protection from new cleverness.** A stricter validator for tomorrow's input cannot retroactively invalidate yesterday's accepted briefing.

**A verified audit chain matters most after a bad day.** The failed ingestions, the rejected authorizations, the partial records and the accepted AI findings survived in recognizable form. We did not need to pretend mistakes had never happened.

**A common AI interface is not common AI behavior.** Different providers, models, response formats and token budgets behave differently. The practical approach is to test the OpenAI path end to end while preserving the abstraction for later work.

**A model can cite evidence and still miss the point.** If prompt assembly drops relevant findings, or the initial selection is alphabetical, a well-behaved model can produce a perfectly grounded but practically useless answer.

**A tool can be safer and harder to use at the same time.** Repeated authorizations, mysterious IDs, scattered continuation commands, vague failures and thousands of JSON lines are not themselves forensic protections. Each needs to justify its cost to the analyst.

**Testing should serve the risk.** Keep the tests that protect publication, evidence, authorization and audit uncompromising. Do not launch the entire test universe every time we change a heading or spinner. And do not mistake a synthetic pass for a completed real-world acceptance.

**A good forensic assistant asks the next question.** Retrieval, validation, reporting and memory are essential. But without focused follow-up investigation, those capabilities remain a very elaborate filing system.

**AI can write the code faster than I can; it cannot relieve me of the product decisions.** The human still has to decide when complexity is justified and when the obvious answer has become buried beneath safeguards, commands, and perfectly correct output nobody wants to read.

## What remains on the other side of the mountain

The case has millions of retained records. The evidence integrity checks pass. The five artifact families are present, though all with some coverage limitations. Deterministic discovery runs. Bounded OpenAI investigation has begun. None of this is hypothetical anymore.

But the original challenge remains unresolved: **can Locard independently reconstruct the November 17 incident without borrowing the conclusions from Defender?**

Not yet.

Our immediate work is to understand the failed AI analysis batch, retain precise diagnostics, and make every accepted observation readable and inspectable. Four accepted observations should not feel like two unexplained lines in a report.

Then comes the larger leap: **controlled, iterative investigation**. Let the AI identify a possible lead, propose a specific follow-up search, have a deterministic service validate that request against the analyst's actual grant, retrieve bounded evidence, and give the AI an opportunity to revise or reject its hypothesis. No unlimited SQL, no hidden permission expansion, and no automatic promotion of model prose into forensic fact.

The CLI also needs a genuine journey from briefing to findings without requiring the investigator to memorize the route: write the briefing, review it, scope it, assess it, authorize searches, investigate, revisit leads, accept findings, produce a report. We already know where the guided path breaks. Frankly, after all our attempts at simplifying it, I no longer believe that a slightly friendlier terminal is the final answer.

**The next major step is a local, web-based interface.** Not because web pages are fashionable, and certainly not because buttons can rescue a broken investigative engine. The reason is simpler: the human analyst should not have to speak Locard's internal command language.

I want to tell the application what I am trying to learn, in ordinary language. The AI should translate that intent into the appropriate **validated, constrained backend operations**—the complex commands and parameters I currently have to construct myself—and then interpret the structured results into something a human can read. If a search returns hundreds of records, I want a useful explanation and a way to drill down, not a demand that I scroll through a small novel of JSON. If the tool needs permission to search a wider period or disclose evidence to a model, it should explain the real scope and ask me to authorize it. The AI must not quietly invent permissions or turn its own hypotheses into forensic facts.

In other words, let the software handle the complexity it created. Let me do the investigating.

The CLI-first effort was not wasted. Its services, evidence model, audit rules, and retrieval capabilities are the foundations on which that interface can stand. But the web UI should consume those services directly, not pretend to be an invisible person typing CLI commands in the background. An elegant front end over an incoherent workflow would only give our maze a nicer entrance.

Evidence navigation must become better. A saved assessment should help an analyst find a meaningful URL, executable, file or event rather than a forest of anonymous timestamps. Long-running operations should tell us what is happening and why they stopped. Limitations should be visible without drowning out the answer.

And some forensic gaps will remain for honest reasons: unsupported Registry transaction-log replay, partial EVTX and MFT parsing, best-effort Browser History, conflicting artifact hostnames, and the limits of a live-source acquisition. We should fix what we can, state what we cannot, and never use missing evidence as proof of absence.

There is also the quieter maintenance work: documentation, release discipline, version increments, backward compatibility and making sure the next improvement does not close a case that opened yesterday.

The task is no longer simply to add capabilities. It is to make the capabilities behave like **one trustworthy investigative product**.

## Epilogue — Still a long way

There is something wonderfully strange about spending evenings and weekends building a forensic application without personally writing most of its code. I started by asking whether a small model like MiniCPM could do something useful. I ended up directing one AI to brief another AI, supervising their work, and arguing with them about the meaning of “useful.”

We set out to investigate Windows computers. Along the way, we spent nights investigating a timeout, a progress file, a rollback journal, an ordinary English preposition, a provider compatibility cache, and the alphabetical ordering of evidence IDs.

Sometimes the evidence was incomplete. Sometimes the model was wrong. Sometimes the model was right but our prompt had failed to give it what it needed. Sometimes tests defended an old goodbye message. Sometimes Windows simply said “access denied.”

The most important breakthroughs were not always clever. One was fixing a worker's file-sharing behavior. Another was letting SQLite's readable records be read. Another was a human refusing to approve an investigation grant that covered the wrong evidence. Each time, a little more of Locard became useful instead of merely impressive.

I can still remember the early confidence: *It will be easy.* I also recognize the late-night thought: *It might never work.* Between those two exaggerations sits something tangible—millions of preserved forensic records, an auditable investigation process, and the beginnings of an AI that can examine evidence without automatically inventing a story.

It is not the product I want yet. The commands remain too complicated, the output too difficult, and the AI too constrained to follow a promising lead on its own. The web interface, the natural-language workflow, and the genuinely investigative reasoning are still ahead of us.

Locard has learned to collect traces. It has learned to remember where they came from. It has learned, most of the time, not to dress uncertainty up as certainty. It has begun to explain what it finds.

Now it must learn to follow a lead—and tell the human what it found without requiring a second investigation into its own output.

**Still a long way.**

At least we have a spinner.

*To be continued.*
