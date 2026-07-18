GENAI.md - AI Use Disclosure

Assignment: ECE 572 Assignment 2
Tool used: Claude (Anthropic)

Summary

I used Claude as a design and debugging assistant across all three tasks (TOTP, OAuth, and Zero Trust) and for drafting and revising the written report. Claude did not have direct access to my repository or environment. All code was typed into my own files by hand based on the conversation, and I ran and tested everything myself. The prompts below are representative examples of how the conversation went, paraphrased rather than exact transcripts, since the actual conversation was long and iterative.

Representative prompts and responses

Prompt: Why does the assignment ask for a TOTP secret to be generated at account creation if TOTP is supposed to be time based?
Response: Claude explained the difference between the shared secret, which is generated once, and the rotating code, which is derived from that secret and the current time every 30 seconds.

Prompt: My instructor never mentioned this library in lecture, what else can I use?
Response: Claude suggested switching from a higher level wrapper library to calling AES directly with a lower level library, and later to PyCryptodome specifically once asked.

Prompt: Why can't the client just use the TOTP secret for challenge-response too?
Response: Claude explained that a phone based authenticator app can only produce standard TOTP codes, not an HMAC over an arbitrary server sent challenge, so a separate secret stored locally by the client program was needed instead.

Prompt: Where does OAuth account creation actually get hashed, client or server?
Response: Claude walked through why authenticate() and the stored user file are both server only, and concluded password hashing had to happen server side, with the client sending the plaintext password over the existing unencrypted connection.

Prompt: I'm getting an UnboundLocalError on response in handle_client, here's the traceback.
Response: Claude identified a missing response = {...} line in the account creation branch based on the traceback and the surrounding code I pasted in.

Prompt: Every command times out once I'm already logged in, but login itself works fine.
Response: Claude traced this to the client's listener thread silently discarding any response that wasn't a chat message, so responses to commands sent after login were never reaching the code waiting for them, and proposed routing non chat messages into that queue instead.

What I did not use AI for

I did not use AI to generate the codebase unattended, run or test the application on my behalf, or finalize the report without reviewing it against my own code. All testing, all typed code changes, and the final wording of the report were done by me, and I did not accept every suggestion as given, several were simplified, rejected, or reworked.
