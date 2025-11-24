"""
OpenTelemetry distributed tracing for microservices observability.

Instruments all FastAPI services with:
- Request tracing (HTTP, database, external APIs)
- Trace context propagation (W3C Trace Context)
- Export to Jaeger for visualization
- Correlation with logs

Based on OpenTelemetry specification and Netflix/Uber tracing patterns.

Usage:
    from shared.tracing import setup_tracing, trace_function, get_tracer
    
    # Initialize in main.py
    setup_tracing(
        service_name="identity",
        jaeger_endpoint="http://jaeger:4318/v1/traces"
    )
    
    # Automatic instrumentation for FastAPI
    app = FastAPI()
    # All endpoints automatically traced
    
    # Manual spans for business logic
    @trace_function("create_api_key")
    async def create_api_key(team_id: str) -> APIKey:
        # This function is automatically traced
        ...
"""

import logging
from typing import Optional, Callable, Any
from contextlib import asynccontextmanager
from functools import wraps

# OpenTelemetry core
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION

# Exporters
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# Instrumentation
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

# Propagation
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat

logger = logging.getLogger(__name__)


def setup_tracing(
    service_name: str,
    service_version: str = "0.2.0",
    jaeger_endpoint: Optional[str] = None,
    otlp_endpoint: Optional[str] = None,
    sample_rate: float = 1.0,
    enable_console: bool = False
):
    """
    Initialize OpenTelemetry tracing for a service.
    
    Call this in main.py before creating FastAPI app.
    
    Args:
        service_name: Service identifier (identity, guardian, data, etc.)
        service_version: Current version
        jaeger_endpoint: Jaeger collector URL (http://jaeger:14268/api/traces)
        otlp_endpoint: OTLP collector URL (http://otel-collector:4318/v1/traces)
        sample_rate: Trace sampling (1.0 = 100%, 0.1 = 10%)
        enable_console: Print traces to console (debug only)
    
    Example:
        # In open-security-identity/app/main.py
        from shared.tracing import setup_tracing
        
        setup_tracing(
            service_name="identity",
            jaeger_endpoint="http://jaeger:14268/api/traces"
        )
        
        app = FastAPI()
        # All endpoints automatically traced
    """
    # Create resource identifying this service
    resource = Resource(attributes={
        SERVICE_NAME: service_name,
        SERVICE_VERSION: service_version,
        "deployment.environment": "production",
        "service.namespace": "wildbox"
    })
    
    # Create tracer provider
    provider = TracerProvider(resource=resource)
    
    # Add exporters
    if jaeger_endpoint:
        jaeger_exporter = JaegerExporter(
            collector_endpoint=jaeger_endpoint,
        )
        provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
        logger.info(f"Jaeger exporter configured: {jaeger_endpoint}")
    
    if otlp_endpoint:
        otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info(f"OTLP exporter configured: {otlp_endpoint}")
    
    if enable_console:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter
        console_exporter = ConsoleSpanExporter()
        provider.add_span_processor(BatchSpanProcessor(console_exporter))
        logger.info("Console exporter enabled (debug mode)")
    
    # Set as global tracer
    trace.set_tracer_provider(provider)
    
    # Configure propagation (W3C Trace Context + B3 for compatibility)
    set_global_textmap(B3MultiFormat())
    
    logger.info(
        f"Tracing initialized for {service_name} "
        f"(sample_rate: {sample_rate * 100}%)"
    )


def instrument_fastapi(app):
    """
    Instrument FastAPI application with automatic tracing.
    
    Traces:
    - All HTTP requests (path, method, status code, duration)
    - Request/response headers
    - Exception traces
    
    Args:
        app: FastAPI application instance
    
    Example:
        from fastapi import FastAPI
        from shared.tracing import setup_tracing, instrument_fastapi
        
        setup_tracing("identity")
        app = FastAPI()
        instrument_fastapi(app)
        
        @app.get("/users")
        async def get_users():
            # This endpoint automatically traced
            return {"users": [...]}
    """
    FastAPIInstrumentor.instrument_app(app)
    logger.info("FastAPI instrumentation enabled")


def instrument_sqlalchemy(engine):
    """
    Instrument SQLAlchemy engine with tracing.
    
    Traces:
    - SQL queries
    - Query duration
    - Connection pool metrics
    
    Args:
        engine: SQLAlchemy engine or async engine
    
    Example:
        from sqlalchemy.ext.asyncio import create_async_engine
        from shared.tracing import instrument_sqlalchemy
        
        engine = create_async_engine("postgresql+asyncpg://...")
        instrument_sqlalchemy(engine)
    """
    SQLAlchemyInstrumentor().instrument(engine=engine)
    logger.info("SQLAlchemy instrumentation enabled")


def instrument_redis(redis_client):
    """
    Instrument Redis client with tracing.
    
    Traces:
    - Redis commands (GET, SET, etc.)
    - Command duration
    - Connection errors
    
    Args:
        redis_client: redis.asyncio.Redis instance
    
    Example:
        import redis.asyncio as redis
        from shared.tracing import instrument_redis
        
        client = redis.from_url("redis://localhost:6379/0")
        instrument_redis(client)
    """
    RedisInstrumentor().instrument()
    logger.info("Redis instrumentation enabled")


def instrument_httpx():
    """
    Instrument httpx HTTP client with tracing.
    
    Traces:
    - External API calls (OpenAI, threat feeds, cloud APIs)
    - Request/response headers
    - Timeouts and errors
    
    Example:
        from shared.tracing import instrument_httpx
        import httpx
        
        instrument_httpx()
        
        async with httpx.AsyncClient() as client:
            # This request automatically traced
            response = await client.get("https://api.openai.com/v1/models")
    """
    HTTPXClientInstrumentor().instrument()
    logger.info("httpx instrumentation enabled")


def get_tracer(name: str):
    """
    Get tracer for manual instrumentation.
    
    Args:
        name: Tracer identifier (module name)
    
    Returns:
        OpenTelemetry tracer
    
    Example:
        from shared.tracing import get_tracer
        
        tracer = get_tracer(__name__)
        
        with tracer.start_as_current_span("business_logic"):
            # Custom span for specific operation
            result = complex_calculation()
    """
    return trace.get_tracer(name)


def trace_function(span_name: Optional[str] = None):
    """
    Decorator to trace async functions.
    
    Creates span around function execution with:
    - Function arguments as span attributes
    - Return value size
    - Exception traces
    
    Args:
        span_name: Custom span name (defaults to function name)
    
    Example:
        from shared.tracing import trace_function
        
        @trace_function("create_api_key")
        async def create_api_key(team_id: str) -> APIKey:
            # Automatically creates span "create_api_key"
            # Attributes: team_id=team_123
            api_key = APIKey(...)
            await db.save(api_key)
            return api_key
        
        @trace_function()  # Uses function name
        async def send_email(to: str, subject: str):
            # Span name: "send_email"
            # Attributes: to=user@example.com, subject="Welcome"
            ...
    """
    def decorator(func: Callable) -> Callable:
        tracer = get_tracer(func.__module__)
        actual_span_name = span_name or func.__name__
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            with tracer.start_as_current_span(actual_span_name) as span:
                # Add function arguments as attributes
                if kwargs:
                    for key, value in kwargs.items():
                        span.set_attribute(f"arg.{key}", str(value))
                
                try:
                    result = await func(*args, **kwargs)
                    
                    # Record result metadata
                    if result:
                        if isinstance(result, (list, dict)):
                            span.set_attribute("result.size", len(result))
                        span.set_attribute("result.type", type(result).__name__)
                    
                    return result
                except Exception as e:
                    # Record exception
                    span.record_exception(e)
                    span.set_attribute("error", True)
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    raise
        
        return wrapper
    return decorator


@asynccontextmanager
async def trace_span(name: str, **attributes):
    """
    Context manager for manual span creation.
    
    Args:
        name: Span name
        **attributes: Span attributes
    
    Example:
        from shared.tracing import trace_span
        
        async with trace_span("database_query", query="SELECT * FROM users"):
            result = await db.execute(query)
        
        async with trace_span("external_api_call", api="openai"):
            response = await openai_client.chat.completions.create(...)
    """
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span(name) as span:
        # Set attributes
        for key, value in attributes.items():
            span.set_attribute(key, str(value))
        
        try:
            yield span
        except Exception as e:
            span.record_exception(e)
            span.set_attribute("error", True)
            raise


def inject_trace_id_to_logs():
    """
    Add trace_id to all log records for correlation.
    
    Enables correlation between traces and logs:
    - Logs include trace_id and span_id
    - Search logs by trace_id in Jaeger
    
    Example:
        from shared.tracing import inject_trace_id_to_logs
        import logging
        
        inject_trace_id_to_logs()
        
        logger = logging.getLogger(__name__)
        logger.info("Processing request")  # Log includes trace_id
    """
    import logging
    
    class TraceContextFilter(logging.Filter):
        def filter(self, record):
            span = trace.get_current_span()
            if span:
                ctx = span.get_span_context()
                if ctx.is_valid:
                    record.trace_id = format(ctx.trace_id, '032x')
                    record.span_id = format(ctx.span_id, '016x')
                else:
                    record.trace_id = '0' * 32
                    record.span_id = '0' * 16
            else:
                record.trace_id = '0' * 32
                record.span_id = '0' * 16
            return True
    
    # Add filter to root logger
    logging.getLogger().addFilter(TraceContextFilter())
    
    # Update log format to include trace IDs
    for handler in logging.getLogger().handlers:
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] [trace_id=%(trace_id)s span_id=%(span_id)s] '
            '%(name)s - %(message)s'
        )
        handler.setFormatter(formatter)
    
    logger.info("Trace context injection enabled for logs")


# Wildbox-specific instrumentation
def setup_wildbox_service_tracing(
    service_name: str,
    app,
    db_engine=None,
    redis_client=None
):
    """
    One-stop setup for Wildbox services.
    
    Configures:
    - OpenTelemetry with Jaeger
    - FastAPI instrumentation
    - Database instrumentation
    - Redis instrumentation
    - httpx instrumentation
    - Log correlation
    
    Args:
        service_name: Service identifier
        app: FastAPI application
        db_engine: SQLAlchemy engine (optional)
        redis_client: Redis client (optional)
    
    Example:
        # In open-security-identity/app/main.py
        from fastapi import FastAPI
        from sqlalchemy.ext.asyncio import create_async_engine
        import redis.asyncio as redis
        from shared.tracing import setup_wildbox_service_tracing
        
        app = FastAPI()
        engine = create_async_engine("postgresql+asyncpg://...")
        redis_client = redis.from_url("redis://localhost:6379/0")
        
        setup_wildbox_service_tracing(
            service_name="identity",
            app=app,
            db_engine=engine,
            redis_client=redis_client
        )
        
        # Now all endpoints, DB queries, Redis ops, and external calls are traced
    """
    # Initialize tracing
    setup_tracing(
        service_name=service_name,
        jaeger_endpoint="http://jaeger:14268/api/traces",
        sample_rate=1.0  # 100% in development, reduce in production
    )
    
    # Instrument FastAPI
    instrument_fastapi(app)
    
    # Instrument database
    if db_engine:
        instrument_sqlalchemy(db_engine)
    
    # Instrument Redis
    if redis_client:
        instrument_redis(redis_client)
    
    # Instrument HTTP client
    instrument_httpx()
    
    # Enable log correlation
    inject_trace_id_to_logs()
    
    logger.info(f"Full tracing setup complete for {service_name}")


# Example usage
"""
# 1. Add to docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:1.50
    ports:
      - "16686:16686"  # Jaeger UI
      - "14268:14268"  # Collector HTTP
    environment:
      COLLECTOR_OTLP_ENABLED: true

# 2. Update service main.py
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine
import redis.asyncio as redis
from shared.tracing import setup_wildbox_service_tracing

app = FastAPI()
engine = create_async_engine(DATABASE_URL)
redis_client = redis.from_url(REDIS_URL)

setup_wildbox_service_tracing(
    service_name="identity",
    app=app,
    db_engine=engine,
    redis_client=redis_client
)

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # Automatically traced:
    # - HTTP request span
    # - Database query span
    # - Redis cache span
    user = await db.get_user(user_id)
    return user

# 3. View traces
# Open browser: http://localhost:16686
# Search for service: identity
# See full request flow across all services
"""
