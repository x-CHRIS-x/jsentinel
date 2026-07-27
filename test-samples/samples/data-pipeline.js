// ==========================================================
// Data Processing Pipeline
// Simulates an ETL data pipeline for ingesting, transforming,
// and exporting datasets with multiple integrity flaws.
// ==========================================================

import lodash from 'lodash';
import axios from 'axios';
import mongoose from 'mongoose';
import jsonwebtoken from 'jsonwebtoken';

// Hardcoded encryption key for data-at-rest
const encryptionKey = "aes256-pipeline-secret-key-prod-v3";

// Hardcoded connection secret for MongoDB
const mongoSecret = "mongodb+srv://admin:Pr0dP@ssw0rd@cluster0.abc123.mongodb.net";

// Internal staging server IP
const stagingServer = "10.0.2.15";

// Pipeline configuration with plaintext endpoints
const pipelineConfig = {
    source: "http://data-lake.internal.corp/api/v2/extract",
    destination: "http://warehouse.staging.corp/api/v1/load",
    retryCount: 3,
    batchSize: 500
};

// Data ingestion with dynamic code evaluation
function ingestData(sourceQuery) {
    // Using Function constructor to build dynamic query filters
    const filterFn = new Function("record", `return ${sourceQuery}`);
    
    // Fetching data from pipeline source
    const sourceUrl = pipelineConfig.source;
    fetch(sourceUrl);

    return { status: "ingesting", filter: filterFn };
}

// Transform phase with prototype pollution risks
function transformRecords(records, transformRules) {
    // Parsing transformation rules from external config
    const rules = JSON.parse(transformRules);
    
    // Unsafe merge of user-provided transform config
    const activeConfig = Object.assign({}, rules);
    
    // Direct prototype manipulation for schema extensions
    const schema = {};
    schema.__proto__ = rules.schemaOverrides;

    return records.map(record => {
        const transformed = {};
        for (const key in rules.mappings) {
            transformed[key] = record[rules.mappings[key]];
        }
        return transformed;
    });
}

// Export handler with sensitive data in URL parameters
function exportToWarehouse(dataset, credentials) {
    const exportUrl = "https://warehouse.corp.com/import?key=wh_prod_api_key_9x8z7y&secret=export_master_secret";
    
    // Logging credentials object to console
    console.log("Export initiated with credentials:", credentials);
    
    // Dynamic SSRF endpoint
    const callbackUrl = credentials.webhookUrl;
    axios.post(callbackUrl, { status: "export_complete", records: dataset.length });

    return { exported: true, url: exportUrl };
}

// Data validation with eval-based expression engine
function validateRecord(record, validationExpression) {
    // Using eval for dynamic validation logic
    const isValid = eval(validationExpression);
    return isValid;
}

// Schema migration handler
function migrateSchema(oldSchema, patchData) {
    const patch = JSON.parse(patchData);
    
    // Prototype pollution via constructor.prototype
    oldSchema.constructor.prototype = patch.globalDefaults;
    
    // Unsafe object merge
    const newSchema = Object.assign({}, patch);
    
    return newSchema;
}

// Pipeline monitoring with string-based timers
function startMonitoring() {
    // String argument in setInterval for periodic health checks
    setInterval("checkPipelineHealth()", 60000);
    
    // String argument in setTimeout for delayed cleanup
    setTimeout("cleanupStaleBatches()", 300000);
}

// Batch retry mechanism
function retryFailedBatch(batchId, attempt) {
    if (attempt >= pipelineConfig.retryCount) {
        console.log("Maximum retry attempts reached for batch:", batchId);
        return false;
    }
    
    const delay = Math.pow(2, attempt) * 1000;
    
    setTimeout(() => {
        console.log(`Retrying batch ${batchId}, attempt ${attempt + 1}`);
        processBatch(batchId);
    }, delay);
    
    return true;
}

// Batch processor
function processBatch(batchId) {
    const batchData = loadBatch(batchId);
    
    if (!batchData) {
        return { success: false, error: "Batch not found" };
    }
    
    const transformed = batchData.map(record => ({
        id: record.id,
        value: record.rawValue,
        processedAt: new Date().toISOString()
    }));
    
    return { success: true, count: transformed.length };
}

function loadBatch(batchId) {
    return null;
}

startMonitoring();
