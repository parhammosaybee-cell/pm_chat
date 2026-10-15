# PM Chat — complete starter

Black/green private chat app with account registration/login, searchable users, 14 menu-language choices, private text messages, image/video stories that expire after 24 hours, story deletion, and recorded voice messages.

## Deploy on Render
Upload all four files to the root of your GitHub repository. In Render, use New + → Blueprint and select the repository (or update your existing web service).

## Important
This starter stores data in SQLite, including uploaded story/voice media as data URLs. On hosts with ephemeral storage, data can be lost on restart/redeploy. For a real public app, migrate to managed PostgreSQL plus persistent object storage, add moderation/reporting, limits and backups. Voice recording requires microphone permission and HTTPS. Stories are removed when the API is accessed after their 24-hour expiry.
