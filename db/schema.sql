CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('user', 'agent', 'admin')),
    full_name     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id         SERIAL PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES users(id),
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open',
    priority   TEXT NOT NULL DEFAULT 'normal',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS comments (
    id         SERIAL PRIMARY KEY,
    ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id  INTEGER NOT NULL REFERENCES users(id),
    body       TEXT NOT NULL,
    internal   BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tickets_owner ON tickets(owner_id);
CREATE INDEX IF NOT EXISTS idx_comments_ticket ON comments(ticket_id);
