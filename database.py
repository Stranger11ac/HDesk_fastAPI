import psycopg2
import psycopg2.extras
from settings import settings

def get_connection():
    return psycopg2.connect(
        host=settings.db_host,
        user=settings.db_user,
        password=settings.db_pass,
        database=settings.db_name,
        port=5432
    )
