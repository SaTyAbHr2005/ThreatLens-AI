# Free-tier limits

Everything in the demo build runs on free plans. Providers change these limits without notice, so each row says where to check the current value. "Seen here" is what this deployment actually hit. Last checked: October 2026.

| Service | Limit that matters | Seen here | How ThreatLens handles it |
|---------|--------------------|-----------|---------------------------|
| **Render** web service (free) | 512 MB RAM, shared CPU. Sleeps after about 15 idle minutes; the first request after that waits for a cold start. 750 free instance hours a month, shared by every free service in the workspace. No persistent disk. | API uses 214 MB idle, 229 MB under load (ARCHITECTURE §10.3). Cold start about 30 s. | Models are baked into the Docker image. The console shows *Gateway: waking up* instead of failing, and the landing's numbers are bundled so it never waits on the API. A cron-job.org ping keeps it warm during judging only, to save instance hours. |
| **Vercel** Hobby | Personal, non-commercial use. Bandwidth and build minutes are capped per month. | A static build; no serverless functions. | The landing's first load is about 150 KB of gzipped JS. three.js and the console load only when needed. |
| **MongoDB Atlas** M0 | 512 MB storage, 500 connections, shared CPU, no backups. | 0.2 MB of 512 MB after the demo runs. | Raw action events expire after 7 days and minute rollups after 90 days (TTL indexes), so storage stays flat. The API keeps one client per process. |
| **Groq** (free) | Requests and tokens per minute and per day, set per model. See console.groq.com → Settings → Limits. | Arena and the A1 LLM mode stay well inside it. | The LLM router puts a rate-limited provider on cooldown for the time it asks and moves to the next one in the chain. Detection never calls an LLM. |
| **Gemini** API (free) | Requests per minute and per day, set per model. See Google AI Studio → Rate limits. Free-tier prompts may be used to improve Google's products, so only synthetic data goes there. | One Arena step took over 30 s. | Arena steps get 60 s each and each model 90 s. A slow model is marked "no answer" with the reason, never counted as resisting. |
| **OpenRouter** free models (`:free`) | Requests per minute per key, a small daily cap until the account has bought credit, and per-model limits upstream. See openrouter.ai/docs → Limits. | `poolside/laguna-xs-2.1:free` was "rate-limited upstream" while another model on the same key was answering. | The Arena waits out short limits (up to 30 s, twice) inside the model's 90 s, then shows the provider's own reason. The daily cap is reported as such, with no retries. |
| **cron-job.org** | Free jobs, down to one run a minute. | `GET /v1/health` every 10 minutes during judging. | Only keeps Render awake; nothing depends on it. |
| **Discord** webhook | About 30 messages a minute per webhook. | One message per Step-up or Isolate decision. | Only those two containment decisions are sent, never individual actions. |
| **Resend** (optional) | 100 emails a day on the free plan. | Not enabled in the demo build. | Off unless `RESEND_API_KEY` is set. |

## Before a demo

1. Open `/v1/health` about a minute before you start, so the cold start happens off camera. The status strip should read *Gateway: warm*.
2. Run the Arena once at most. Free LLM quotas are shared by everyone using the demo account.
3. If an LLM provider is rate-limited, the status strip says so. Detection, containment and every scenario in replay mode keep working without any LLM.
