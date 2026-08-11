# Portfolio System

Portfolio management system dengan tampilan publik & admin panel. 

## Setup

1. Rename `.env.example` ke `.env` dan isi GitHub credentials:
   - `GITHUB_TOKEN`: Personal access token dari GitHub
   - `GITHUB_OWNER`: Username GitHub
   - `GITHUB_REPO`: Nama repository
   - `GITHUB_BRANCH`: Branch (default: main)
   - `JWT_SECRET`: Secret key untuk token

2. Deploy ke Vercel

## Admin Login

Password default: `admin123`

Ubah di `api/index.js` function `simplePasswordVerify()`

## Struktur

- `index.html` - Public portfolio view
- `admin.html` - Admin login & dashboard
- `api/index.js` - Serverless functions
- `data/portfolio.json` - Data storage (via GitHub API)
