#!/bin/bash
set -e

echo "🚀 Starting Open Security Identity Service..."

# Function to wait for database to be ready
wait_for_db() {
    echo "⏳ Waiting for database to be ready..."
    
    # Wait for PostgreSQL to be ready
    until python -c "
import asyncio
import asyncpg
import sys
import os

async def check_db():
    try:
        # Parse DATABASE_URL 
        db_url = os.getenv('DATABASE_URL', 'postgresql+asyncpg://postgres:postgres@postgres:5432/identity')
        # Convert to asyncpg format
        asyncpg_url = db_url.replace('postgresql+asyncpg://', 'postgresql://')
        
        conn = await asyncpg.connect(asyncpg_url)
        await conn.execute('SELECT 1')
        await conn.close()
        print('✅ Database is ready!')
        return True
    except Exception as e:
        print(f'❌ Database not ready: {e}')
        return False

if not asyncio.run(check_db()):
    sys.exit(1)
"; do
        echo "Database not ready, waiting 5 seconds..."
        sleep 5
    done
}

# Function to run database migrations
run_migrations() {
    echo "🔄 Running database migrations..."
    
    # Run Alembic migrations
    alembic upgrade head
    
    if [ $? -eq 0 ]; then
        echo "✅ Database migrations completed successfully!"
    else
        echo "❌ Database migrations failed!"
        exit 1
    fi
}

# Function to create initial superuser (optional)
create_superuser() {
    echo "👤 Creating initial superuser (if needed)..."
    
    python -c "
import asyncio
import os
import sys
from app.database import get_db
from app.models import User
from app.user_manager import get_user_manager, get_user_db
from sqlalchemy import select

async def create_initial_superuser():
    admin_email = os.getenv('INITIAL_ADMIN_EMAIL', 'admin@wildbox.security')
    admin_password = os.getenv('INITIAL_ADMIN_PASSWORD', 'INSECURE-DEFAULT-PASSWORD')
    
    if admin_password == 'INSECURE-DEFAULT-PASSWORD':
        print('🚨 CRITICAL SECURITY WARNING: Using insecure default password!')
        print('   Set INITIAL_ADMIN_PASSWORD environment variable to a secure password')
        print('   See .env.example for configuration guidance')
        sys.exit(1)
    
    try:
        # Get database session
        db_gen = get_db()
        db = await db_gen.__anext__()
        
        # Check if admin already exists
        result = await db.execute(select(User).where(User.email == admin_email))
        existing_admin = result.scalar_one_or_none()
        
        if existing_admin:
            print(f'ℹ️  Admin user {admin_email} already exists, skipping creation.')
            await db.close()
            return
        
        # Get user manager
        user_db_gen = get_user_db(db)
        user_db = await user_db_gen.__anext__()
        user_manager_gen = get_user_manager(user_db)
        user_manager = await user_manager_gen.__anext__()
        
        # Create admin user
        from app.schemas import UserCreate
        user_create = UserCreate(email=admin_email, password=admin_password)
        
        admin_user = await user_manager.create(user_create, safe=False)
        
        # Make user superuser
        admin_user.is_superuser = True
        admin_user.is_verified = True
        db.add(admin_user)
        await db.commit()
        
        print(f'✅ Created initial admin user: {admin_email}')
        print(f'🔑 Password: {admin_password}')
        print('⚠️  Please change the default password after first login!')
        
        await db.close()
        
    except Exception as e:
        print(f'❌ Failed to create admin user: {e}')

# Only create superuser if explicitly requested
if os.getenv('CREATE_INITIAL_ADMIN', 'false').lower() == 'true':
    asyncio.run(create_initial_superuser())
else:
    print('ℹ️  Skipping admin user creation (set CREATE_INITIAL_ADMIN=true to enable)')
"
}

# Main initialization sequence
main() {
    echo "📋 Open Security Identity - Initialization Script"
    echo "================================================="
    
    # Wait for database
    wait_for_db
    
    # Run migrations
    run_migrations
    
    # Create superuser if requested
    create_superuser
    
    echo ""
    echo "🎉 Initialization completed successfully!"
    echo "🚀 Starting application server..."
    echo ""
    
    # Start the application
    exec uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
}

# Run main function
main
