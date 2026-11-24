# Locard: A Forensic Investigation Into Our Own Software

*A project journal — November 21, 2026*

There is a particular kind of optimism involved in saying, “We should add Tab completion.”

It sounds manageable. A small improvement. A pleasant afternoon. Press a key, finish a command, move on.

Somewhere along the way, that afternoon acquired native filesystem acquisition, several generations of AI investigation, a durable memory of analyst decisions, a reporting backend, and a very strong opinion about not confusing a blocked script with a successfully executed one.

Locard has been quite a journey.

This is the story as it unfolded through our work together. It begins with a project already underway, rather than pretending we remember the exact moment the first line was written.

## When the terminal was the main event

In the earlier chapters, much of the work was wonderfully concrete: make the help consistent, improve the interactive shell, explain the commands, and present Windows artifacts in a way a person could actually read.

MFT records needed better presentation. Registry output needed attention. Prefetch needed cleanup. Event logs needed to stop looking like a machine had emptied its pockets onto the screen.

These were useful improvements. An investigator should not have to reverse-engineer the interface before investigating the evidence.

We also discovered that tiny presentation changes have surprisingly large fan clubs among automated tests. Change a shutdown separator and suddenly a collection of tests insists that civilization has ended.

That gave us an early rule worth keeping: tests protect the product, but an old expected sentence is not automatically the product specification. Preserve the intended interface. Update stale presentation assertions. Do not casually relax the tests protecting evidence or authorization.

And yes, the goodbye message received more attention than anyone might have predicted.

## The evidence had other plans

Small synthetic examples are agreeable guests. They arrive on time, follow instructions, and rarely bring a damaged browser database.

Real Windows evidence behaves differently.

It brings hundreds of event logs, Registry companions, dirty hives, partial records, enormous filesystem tables, and browser files whose housekeeping was interrupted at an inconvenient moment.

One of the great recurring scenes in this project was the apparently simple ingestion command that became a much longer conversation:

Did acquisition succeed? Did parsing finish? Were any records retained? Was the worker still making progress? Did the audit finish? What, exactly, does “partial” mean here?

The MFT became a major character. We acquired it, compared it with an independent extraction, investigated differing bytes, examined staging growth, reduced unnecessary storage, and learned that a parser can be working very hard while a poorly chosen timeout declares it dead.

A timeout was supposed to protect the investigation. Sometimes it was protecting us from completing it.

The answer was not to remove the safeguards. It was to understand what they were measuring. An active, advancing parser and a frozen worker are different situations. So are a failed acquisition and a successful acquisition followed by failed parsing.

Eventually, there was the overnight run: start ingestion, go to bed, wake up to a result, and realize the application had neglected to answer the most human question of all.

“How long did that take?”

After everything we had built, a clock was still a feature.

## A spinner is a promise

Progress reporting went through its own education.

At first, we needed visibility. What was happening? Was anything happening? Was the process alive, or merely taking up space?

Then we had visibility. Quite a lot of it. Worker details, paths, parser stages, elapsed times, staging information. The terminal began to resemble a control room.

The correction was simple and important: normal operation should look normal.

A compact progress line. A spinner that keeps moving. Useful counts. Clear exceptions at the end. Detailed diagnostics available when needed.

The analyst should not have to monitor the software’s pulse continuously.

That lesson extended beyond ingestion. “Waiting for local AI...” is not a harmless label when the investigator has explicitly authorized OpenAI. In that instance, the routing was correct; the message was wrong. But the person reading it had every reason to be concerned.

Presentation is part of trust. A reassuring label that misstates reality is still a defect.

## The AI could talk before it could investigate

Early AI work exposed a familiar temptation: if a model can produce a convincing paragraph, perhaps we are close to a useful investigator.

We were not close enough.

There were invalid responses, schema disagreements, provider-specific surprises, output that ran out of room, and errors that explained almost nothing. A useful diagnostic repeatedly began with the same instruction: do not send another paid request yet. Inspect what happened first.

The provider abstraction helped with shared plumbing, but it did not abolish the differences between providers. We had to stop treating a common interface as a guarantee of common behavior.

Even a successful response was only the beginning.

Did the model actually receive the evidence it cited? Did the evidence support the statement? Was it reporting an observation, repeating an analyst’s suspicion, or proposing a hypothesis? Had a useful detail been retrieved and then quietly squeezed out of the next request?

At one point, several important findings were available to the investigation but absent from the final narrative. The problem was not simply that the model had failed to notice them. The prompt allocation had failed to preserve them.

We had built a system that could collect the right material and then forget to put it in front of the person—or model—doing the explaining.

That was an expensive lesson, even without counting API bills.

## “Blocked” does not mean “executed”

A recurring investigation involved a download, filesystem activity, and a defensive blocking event.

It was a useful test because it invited an attractive story. The pieces were nearby in time. The filenames and commands seemed related. A model could connect them into a confident sequence with very little encouragement.

But attractive is not the same as supported.

A download does not prove delivery caused execution. A file timestamp does not prove a program ran. A blocking event does not prove a script completed successfully. Missing evidence does not automatically establish that nothing happened.

Locard’s task became harder and more interesting: help the analyst explain what the evidence supports, while keeping the gaps visible.

This is where the project began to grow beyond “AI attached to a forensic CLI.” We needed observations, interpretations, hypotheses, uncertainty, and analyst decisions to remain distinguishable throughout the investigation.

A citation is useful. It is not a magic spell that turns a sentence into a fact.

## We almost made the briefing harder than the investigation

The briefing workflow had its own long series of revisions.

We tried to extract indicators, classify narrative statements, build structured summaries, ask useful follow-up questions, and identify missing information. Each improvement uncovered another way to be unhelpfully strict—or confidently wrong.

Ordinary prose became supposed entities. Paraphrases were treated suspiciously. Useful summaries were incomplete. The interface sometimes seemed more interested in filling categories than understanding the analyst.

Eventually, the guiding principle became much clearer:

**AI proposes, the analyst decides, and forensic evidence verifies.**

A briefing is the analyst’s working account, not a court finding. It can contain uncertainty, incomplete information, and imperfect organization. The analyst should be able to accept, correct, move, or reject proposed material without battling an overenthusiastic semantic referee.

Concrete search identifiers still need care. But ordinary explanatory language should not have to pass for a literal quotation before it can be useful.

That distinction simplified a great deal of thinking, even when implementing it took several releases.

## Teaching an investigation to remember

Once bounded autonomous investigation began working, another problem became obvious: six successful analysis batches do not automatically produce one useful answer.

The system could accumulate observations, preserve interpretations, and propose hypotheses, yet finish with “No supported conclusion was produced.”

That was frustrating, but it was also an honest warning. We needed to understand whether the answer had failed, the synthesis opportunity had disappeared, or the available evidence simply could not support the requested conclusion.

We resisted the easy solution of pouring everything into one enormous final prompt.

Instead, the work moved toward incremental investigation: retain validated findings, bring original support forward in bounded pieces, organize relationships carefully, and build explanations without letting yesterday’s AI prose become today’s evidence.

This led to the alphabet of development stages. By then, S4-B2 and D1b sounded less like milestones and more like seats on a very complicated airplane.

But the stages served a purpose. They made it possible to separate “this works” from “we would like this to work next.”

Persistent findings, analyst decisions, reconstructed investigations, and readable reporting became substantial parts of the project. The ambition was no longer merely to get an answer. It was to retain a defensible account of how that answer came to exist.

## The bugs that kept us humble

Some failures were architectural. Others were almost comic in their precision.

A diagnostic script needed its own diagnosis after PowerShell and Python disagreed about quotation marks. A computer crash left us asking whether a test run had completed. Memory exhaustion interrupted validation without proving anything was wrong with the application. Git operations became something to approach with caution rather than casual confidence.

Then came the hostname `on`.

An ordinary word in a neutral briefing became a proposed hostname. Tightening the rule fixed new extraction, but it also made an older accepted briefing unreadable. A correction to future behavior had accidentally invalidated the past.

That was a particularly clear lesson: historical analyst decisions are records to preserve, not drafts to reinterpret whenever a validator becomes cleverer.

Next, an investigation stopped because “configured” did not mean “compatibility verified.” The safety check was deliberate; the explanation was inadequate.

And then an assessment containing five artifact families produced a Browser-only grant. Why? The evidence IDs were sorted, Browser came first, and the first twelve won.

After all the sophisticated reasoning work, alphabetical order had quietly become the lead investigator.

## What we have learned

The strongest habits came from these disappointments.

We learned to inspect before fixing. To distinguish an application defect from an environment failure. To keep real evidence untouched while reproducing problems synthetically. To preserve partial results without pretending they were complete. To record why an operation stopped, not merely that it stopped.

We learned that authorization must describe what will actually happen. A sample is not full coverage. A configured provider is not a verified capability. A valid response is not necessarily a grounded conclusion.

We also learned to use a more sustainable testing rhythm: focused regressions during development, manual acceptance on the intended workflow, then the complete suite at the agreed release boundary. Repeatedly running everything is not a substitute for knowing what a change could break.

Most of all, we learned that useful AI needs a dependable application around it. Models do not excuse vague errors, lost history, misleading progress, or poor evidence selection.

## Where we are—and what remains

At this point in the journal, the checkout is at 6.163. The latest correction replaces the accidental Browser-first sample with bounded, coverage-aware selection and scheduling. Focused tests have passed. Real-case manual acceptance of that change is still the next practical checkpoint, not a success we should announce in advance.

There is more work ahead.

The investigations need to become more consistently useful across unrelated cases, rather than merely succeeding on a familiar example. Explanations need to answer the analyst’s questions clearly without hiding uncertainty. Broader follow-up retrieval needs a carefully reviewed authorization design; it should not sneak in as a convenient extra lookup.

Reporting, long-running reliability, and the everyday workflow still need continued real-world testing. The future local web interface remains a possibility, but it should inherit dependable services rather than give unfinished behavior a prettier front door.

And there is the less glamorous work: keeping documentation current, preserving compatibility, making releases repeatable, and ensuring that a new improvement does not make an old case impossible to open.

The remaining challenge is not simply to add more capabilities. It is to make the capabilities we have feel like one trustworthy tool.

## Still investigating

Locard has become an investigation of two things at once: the evidence in a case, and the assumptions in the software examining it.

Sometimes the evidence is incomplete. Sometimes the model is wrong. Sometimes Windows says access denied. Sometimes we wrote the wrong sentence. Sometimes the answer was there, but our own selection logic never gave it a chance.

The progress has been real. So have the detours.

We started this stretch of the journey making the shell easier to use. We are now asking how an AI-assisted investigation can remember, explain, qualify, and defend its work without claiming more than it knows.

That is a much bigger question.

Fortunately, we have a spinner now.
