# FastAPI Users Migration Guide

## Panoramica

Questo documento descrive la migrazione del sistema di autenticazione di `open-security-identity` da un'implementazione custom con JWT a `fastapi-users`, una libreria robusta e ben mantenuta per la gestione degli utenti in FastAPI.

## Cambiamenti Principali

### 1. Dipendenze Aggiornate

**Nuove dipendenze aggiunte a `requirements.txt`:**
```
fastapi-users[sqlalchemy]==12.1.3
fastapi-users-db-sqlalchemy==6.0.1
python-multipart==0.0.7  # aggiornato per compatibilità
```

### 2. Modelli Database

**`app/models.py`:**
- La classe `User` ora eredita da `SQLAlchemyBaseUserTableUUID`
- I campi standard (`id`, `email`, `hashed_password`, `is_active`, `is_superuser`, `is_verified`) sono forniti automaticamente
- Mantenuti i campi custom (`stripe_customer_id`, timestamps, relationships)
- Aggiornata la sintassi delle relationships con `Mapped` e `mapped_column`

### 3. Nuovo User Manager

**`app/user_manager.py` (nuovo file):**
- Configurazione centrale di `fastapi-users`
- `UserManager` custom con logica `on_after_register` per:
  - Creazione automatica del team
  - Creazione della membership
  - Creazione della subscription gratuita
  - Integrazione con Stripe

### 4. Schemi Pydantic Aggiornati

**`app/schemas.py`:**
- Nuovi schemi `UserRead`, `UserCreate`, `UserUpdate` basati su `fastapi-users`
- Mantenuti schemi legacy per compatibilità durante la transizione

### 5. Router Aggiornati

**`app/main.py`:**
- Rimosso `auth.router` (sostituito dai router di `fastapi-users`)
- Aggiunti router pre-costruiti:
  - `/auth/jwt/login` - Login con JWT
  - `/auth/register` - Registrazione utenti
  - `/users/me` - Profilo utente corrente
  - `/auth/forgot-password` - Reset password
  - `/auth/verify` - Verifica email
- Aggiunto middleware per la sessione DB (necessario per `on_after_register`)

### 6. Endpoint Dependencies

**Tutti i file di endpoint (`api_v1/endpoints/`):**
- Sostituito `get_current_active_user` con `current_active_user`
- Aggiornati gli import per usare `user_manager.py`

## Nuovi Endpoint Disponibili

### Autenticazione
- `POST /api/v1/auth/register` - Registrazione
- `POST /api/v1/auth/jwt/login` - Login (form data)
- `POST /api/v1/auth/jwt/logout` - Logout
- `POST /api/v1/auth/forgot-password` - Reset password
- `POST /api/v1/auth/reset-password` - Conferma reset password
- `POST /api/v1/auth/request-verify-token` - Richiesta verifica email
- `POST /api/v1/auth/verify` - Verifica email

### Gestione Utenti
- `GET /api/v1/users/me` - Profilo utente corrente
- `PATCH /api/v1/users/me` - Aggiorna profilo
- `GET /api/v1/users/{id}` - Leggi utente (admin)
- `PATCH /api/v1/users/{id}` - Aggiorna utente (admin)
- `DELETE /api/v1/users/{id}` - Elimina utente (admin)

## Migrazione Database

**File di migrazione:** `alembic/versions/b1c2d3e4f5g6_add_is_verified_field.py`

Aggiunge il campo `is_verified` richiesto da `fastapi-users`:
```sql
ALTER TABLE users ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE;
```

## Compatibilità

### Cosa Rimane Invariato
- Tutti i modelli esistenti (`Team`, `TeamMembership`, `Subscription`, `ApiKey`)
- La logica di business per team e billing
- I token JWT esistenti (stessa chiave segreta)
- Gli endpoint admin custom

### Cosa Cambia
- URL di login: `/auth/login` → `/auth/jwt/login`
- URL di registrazione: `/auth/register` → `/auth/register` (uguale)
- Formato delle risposte (più standardizzato)
- Verifica email ora disponibile (opzionale)

## Testing

Usa il script `test_migration.py` per verificare la migrazione:

```bash
python test_migration.py
```

## Vantaggi della Migrazione

1. **Sicurezza Migliorata:** Password hashing, gestione token e reset password seguono best practices
2. **Meno Codice da Mantenere:** La logica di autenticazione è gestita dalla libreria
3. **Funzionalità Aggiuntive:** Verifica email, reset password, gestione admin built-in
4. **Standardizzazione:** API conformi agli standard OAuth2/OpenAPI
5. **Manutenibilità:** Aggiornamenti e fix di sicurezza tramite la libreria

## Note per il Deploy

1. Eseguire la migrazione database: `alembic upgrade head`
2. Aggiornare le variabili d'ambiente se necessario
3. Testare tutti gli endpoint dopo il deploy
4. Aggiornare la documentazione API per i client

## Rollback

Per fare rollback:
1. Ripristinare i file originali
2. Eseguire `alembic downgrade -1` per rimuovere il campo `is_verified`
3. Reinstallare le dipendenze precedenti
