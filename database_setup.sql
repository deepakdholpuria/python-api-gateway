-- Database setup script for Gateway Router

-- Create the routes table
CREATE TABLE gateway_routes (
    id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    full_url VARCHAR2(1000) NOT NULL,
    replaced_variables VARCHAR2(100) NOT NULL,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active NUMBER(1) DEFAULT 1 NOT NULL
);

-- Create index on full_url for faster lookups
CREATE INDEX idx_gateway_routes_url ON gateway_routes(full_url);

-- Add some sample routes
INSERT INTO gateway_routes (full_url, replaced_variables) 
VALUES ('http://main.com/xzy/gfc', 'OBPM');

INSERT INTO gateway_routes (full_url, replaced_variables) 
VALUES ('http://main.com/api/users', 'HOST');

INSERT INTO gateway_routes (full_url, replaced_variables) 
VALUES ('http://main.com/api/orders', 'OBRH');

-- Create an audit log table for request tracking
CREATE TABLE gateway_audit_log (
    id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trace_id VARCHAR2(36) NOT NULL,
    request_url VARCHAR2(1000) NOT NULL,
    target_url VARCHAR2(1000) NOT NULL,
    request_method VARCHAR2(10) NOT NULL,
    status_code NUMBER,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    response_timestamp TIMESTAMP,
    processing_time_ms NUMBER,
    request_headers CLOB,
    response_headers CLOB,
    error_message VARCHAR2(1000)
);

-- Create index on trace_id for faster lookups
CREATE INDEX idx_gateway_audit_trace_id ON gateway_audit_log(trace_id);
CREATE INDEX idx_gateway_audit_timestamp ON gateway_audit_log(request_timestamp);

-- Create stored procedure to log requests
CREATE OR REPLACE PROCEDURE log_gateway_request(
    p_trace_id IN VARCHAR2,
    p_request_url IN VARCHAR2,
    p_target_url IN VARCHAR2,
    p_request_method IN VARCHAR2,
    p_request_headers IN CLOB
) AS
BEGIN
    INSERT INTO gateway_audit_log (
        trace_id, 
        request_url, 
        target_url, 
        request_method, 
        request_headers
    ) VALUES (
        p_trace_id,
        p_request_url,
        p_target_url,
        p_request_method,
        p_request_headers
    );
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        -- Log error but continue - don't block the main application flow
        NULL;
END;
/

-- Create stored procedure to update audit log with response
CREATE OR REPLACE PROCEDURE update_gateway_audit(
    p_trace_id IN VARCHAR2,
    p_status_code IN NUMBER,
    p_response_headers IN CLOB,
    p_error_message IN VARCHAR2 DEFAULT NULL
) AS
BEGIN
    UPDATE gateway_audit_log
    SET 
        status_code = p_status_code,
        response_timestamp = CURRENT_TIMESTAMP,
        processing_time_ms = ROUND((CURRENT_TIMESTAMP - request_timestamp) * 86400000),
        response_headers = p_response_headers,
        error_message = p_error_message
    WHERE trace_id = p_trace_id;
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        -- Log error but continue - don't block the main application flow
        NULL;
END;
/

-- Grant permissions if needed
-- GRANT SELECT, INSERT, UPDATE ON gateway_routes TO gateway_user;
-- GRANT SELECT, INSERT, UPDATE ON gateway_audit_log TO gateway_user;
-- GRANT EXECUTE ON log_gateway_request TO gateway_user;
-- GRANT EXECUTE ON update_gateway_audit TO gateway_user;