CREATE PUBLICATION IF NOT EXISTS daisi_pub FOR ALL TABLES WITH (publish_via_partition_root = true);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_replication_slots
        WHERE slot_name = 'daisi_slot'
    ) THEN
        PERFORM pg_create_logical_replication_slot('daisi_slot', 'pgoutput');
    END IF;
END;
$$;

DO $$
    DECLARE
        v_schema_name TEXT := 'daisi_CompanyAAA01'; -- Configurable schema name
        v_table_name TEXT := 'messages';
        t regclass;
    BEGIN
        EXECUTE format('ALTER TABLE %I.chats REPLICA IDENTITY FULL', v_schema_name);
        EXECUTE format('ALTER TABLE %I.agents REPLICA IDENTITY FULL', v_schema_name);
        -- parent
        EXECUTE format('ALTER TABLE %I.%I REPLICA IDENTITY FULL', v_schema_name, v_table_name);

        FOR t IN
            SELECT inhrelid::regclass
            FROM pg_catalog.pg_inherits -- Explicitly qualify pg_inherits
            WHERE inhparent = (quote_ident(v_schema_name) || '.' || quote_ident(v_table_name))::regclass
            LOOP
                EXECUTE format('ALTER TABLE %s REPLICA IDENTITY FULL;', t);
            END LOOP;
    END;
$$;