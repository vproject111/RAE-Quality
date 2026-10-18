# packages/rae-quality/tests/test_iteration3_architecture_db_openapi.py
import pytest
from engines.architecture.architecture_engine import ArchitectureEngine
from models.security_v2 import GatewayVerdict


def test_architecture_engine_detects_missing_tx_n_plus_1_and_race_condition():
    engine = ArchitectureEngine()

    bad_service_code = """
    def checkout(order, items, db, redis):
        save_order(order)
        save_order_items(items)
        for item in items:
            db.execute("SELECT * FROM products WHERE id = :id", {"id": item.product_id})
        redis.set("cache_key", "val")

    def save_project(project_data):
        db.update(project_data)
    """
    res = engine.check_architecture(
        code=bad_service_code,
        file_path="services/order_service.py",
        technologies=["mariadb", "redis"],
    )
    assert res["verdict"] == GatewayVerdict.BLOCK.value
    assert res["postgres_vacuum_applicable"] is False
    assert res["kafka_consumer_groups_applicable"] is False

    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "RAE-SEC-048" in rule_ids  # Missing atomic transaction
    assert "RAE-SEC-043" in rule_ids  # N+1 query inside loop
    assert "RAE-SEC-090" in rule_ids  # Race condition on save_project without optimistic locking
    assert "RAE-SEC-100" in rule_ids  # Redis set without TTL


def test_architecture_engine_detects_missing_down_migration_and_openapi_breakage():
    engine = ArchitectureEngine()

    migration_code = """
    def upgrade():
        op.add_column('orders', sa.Column('discount', sa.Float()))
    """
    before_openapi = {
        "paths": {
            "/v1/orders": {
                "post": {"required_fields": ["product_id", "quantity"]},
                "get": {"required_fields": []},
            }
        }
    }
    after_openapi = {
        "paths": {
            "/v1/orders": {
                "post": {"required_fields": ["product_id", "quantity", "mandatory_new_field"]}
            }
        }
    }

    res = engine.check_architecture(
        code=migration_code,
        file_path="migrations/0042_add_discount.py",
        technologies=["postgresql", "kafka"],
        openapi_before=before_openapi,
        openapi_after=after_openapi,
    )
    assert res["verdict"] == GatewayVerdict.BLOCK.value
    assert res["postgres_vacuum_applicable"] is True
    assert res["kafka_consumer_groups_applicable"] is True
    assert res["openapi_compatibility"]["compatible"] is False

    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "RAE-SEC-047" in rule_ids  # Missing down migration
    assert "RAE-SEC-129" in rule_ids  # Breaking OpenAPI change
