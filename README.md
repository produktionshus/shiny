# Shiny-binderen

Pokémon GO shiny-tracker som en samlekort-binder. Danske UI, login og per-bruger samlinger.

- Shiny-liste hentes live fra [pogoapi.net](https://pogoapi.net)
- Shiny rates fra [shinyrates.com](https://shinyrates.com) (lokalt snapshot i `shinyrates.json`)
- Billeder fra [PokéAPI](https://pokeapi.co)

## Kør lokalt

```bash
npm install
npm start          # kræver Node >= 24 (bruger indbygget node:sqlite)
```

Åbn http://localhost:3000. Uden login gemmes samlingen i localStorage; med login gemmes den i SQLite på serveren og følger brugeren på tværs af enheder.

## Deploy på Railway

1. Push repoet til GitHub.
2. Railway → New Project → Deploy from GitHub repo → vælg repoet. Railway finder selv `npm start`.
3. Tilføj en **Volume** (fx mount path `/data`) — ellers nulstilles databasen ved hvert deploy.
4. Sæt variabler under Settings → Variables:
   - `DB_PATH=/data/shiny.db`
   - `SESSION_SECRET=<lang tilfældig streng>`
   - `NODE_ENV=production`
5. Settings → Networking → Generate Domain (eller peg egen subdomain, fx `shiny.kulldorf.com`, via CNAME).

## API

| Metode | Sti | Beskrivelse |
|---|---|---|
| POST | `/api/register` | `{username, password}` → opretter bruger + logger ind |
| POST | `/api/login` | `{username, password}` |
| POST | `/api/logout` | |
| GET | `/api/me` | `{username \| null}` |
| GET | `/api/collection` | `{collected: [dexId, …]}` (kræver login) |
| PUT | `/api/collection` | `{collected: [dexId, …]}` (kræver login) |
