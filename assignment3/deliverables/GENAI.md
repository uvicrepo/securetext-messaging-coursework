GENAI.md - AI Use Disclosure

Assignment: ECE 572 Assignment 3
Tool used: Claude (Anthropic)

Summary

I used Claude as a design and debugging assistant across the three tasks and for drafting and revising the written report. Claude did not have direct access to my repository or environment. All code was typed into my own files by hand based on the conversation, and I ran and tested everything myself. The prompts below are representative examples of how the conversation went, paraphrased rather than exact transcripts, since the actual conversation was sometimes iterative.

Representative prompts and responses

Prompt: Asked about a bug where the session expiration warning wasn't appearing correctly.
Response: Claude helped trace the issue to how the session's idle timer was being reset, and suggested separating status checks from actual user activity so the timer behaved correctly.

Prompt: Asked about a bug where a user's message would sometimes fail to decrypt or return no shared key.
Response: Claude helped identify a threading issue where the background message listener could get stuck waiting on its own response queue, and suggested handling that one case differently.

Prompt: Asked about a crash that occurred after a session timeout, re-login, and then sending a message.
Response: Claude helped trace this to a leftover background thread that kept running after a session ended, which caused conflicts once a new session started.

Prompt: The 5-minute warning wasn't behaving right, it printed conflicting numbers.
Response: Claude spotted that the act of checking the timer was resetting the timer.

Prompt: One user gets "no shared key" the first time someone messages them.
Response: Claude diagnosed a thread deadlock, the background listener thread was blocking on a queue only it could fill, and fixed that one path specifically.

What I did not use AI for

I did not use AI to generate the codebase unattended, run or test the application on my behalf, or finalize the report without reviewing it against my own code. All testing, all typed code changes, and the final wording of the report were done by me, and I did not accept every suggestion as given, several were simplified, rejected, or reworked.
