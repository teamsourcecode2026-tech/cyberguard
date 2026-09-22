CYBER GAURD



\# CyberGuard - AI Powered Cyber Threat, Phishing \& Digital Impersonation Detection System



> Team setup guide — read this before writing any code.

> (This section will be replaced with the final project description once the hackathon build is complete.)



\## Tech Stack (fixed for everyone — do not change without team agreement)

\- Language: Python 3.11 (backend + all AI/ML modules)

\- Backend: FastAPI

\- Database: MongoDB Atlas (ONE shared cluster — ask Manish for access, never create your own)

\- Frontend: React.js (Vite) + Tailwind CSS

\- Version control: This repo, feature branches + Pull Requests only



\## Folder Ownership — Work ONLY inside your assigned folder



| Folder          | Owner            | What goes here                                  |

|------------------|-------------------|--------------------------------------------------|

| `backend/`       | Manish            | FastAPI app, API routes, DB connection           |

| `ml\\\_phishing/`   | Member 2          | Phishing/NLP detection model                     |

| `ml\\\_deepfake/`   | Member 3          | Deepfake/impersonation detection model           |

| `ml\\\_anomaly/`    | Member 4          | Anomaly/technical threat model + risk scoring    |

| `frontend/`      | Member 5          | React dashboard                                  |

| `datasets/`      | Member 6          | Sample/synthetic data for testing all modules    |

| `docs/`          | Shared            | API contract, architecture notes                 |



\*\*Rule:\*\* Never edit a file inside another member's folder without asking first. This is what prevents conflicts when everyone pushes.



\## First-Time Setup (do this once)



1\. Clone the repo: git clone https://github.com/teamsourcecode2026-tech/cyberguard.git



cd cyberguard



2\. Copy `.env.example` to a new file named `.env` in the root folder.

3\. Ask Manish for the real MongoDB connection string and paste it into your `.env` (never commit `.env` — it's already git-ignored).

4\. `cd` into your assigned folder from the table above and start working there.



\## Daily Workflow (every time you work)



1\. \*\*Before starting:\*\* `git pull` — get everyone else's latest changes.

2\. \*\*Do your work\*\* inside your assigned folder only.

3\. \*\*Before pushing:\*\* create/use a branch named after your task:

git checkout -b feature/your-task-name



4\. Save your work:

git add .

git commit -m "clear description of what you did"

git push origin feature/your-task-name



5\. On GitHub, open a \*\*Pull Request\*\* from your branch into `main` and ask a teammate to review before merging. Never push straight to `main`.



\## API Contract



Every AI module must return this exact shape — see `docs/API\_CONTRACT.md` for full endpoint details: { "score": 0-100, "verdict": "string", "indicators": \["reason1", "reason2"] }



The backend is the ONLY component that talks to the database. AI modules never write to MongoDB directly — they just return this format to the backend.



\## Questions?

Ask in the team group before changing anything in this file, the API contract, or the tech stack above.

