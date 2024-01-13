NUM_WORKERS=3
TIMEOUT=600

exec gunicorn app:app \
--workers $NUM_WORKERS \
--timeout $TIMEOUT \
--log-level=debug \
--bind=127.0.0.1:8000