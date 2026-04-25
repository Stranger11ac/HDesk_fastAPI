import psycopg2
import psycopg2.extras
from settings import settings

def get_connection():
    print("✅ Connecting to database...")
    print("DB_HOST:", settings.db_host)
    print("DB_NAME:", settings.db_name)

    return psycopg2.connect(
        host=settings.db_host,
        user=settings.db_user,
        password=settings.db_pass,
        database=settings.db_name,
        port=5432
    )
