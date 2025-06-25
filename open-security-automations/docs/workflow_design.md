# 🎨 Workflow Design Guide

This guide outlines best practices and design patterns for creating effective workflows in the Wildbox Open Security Automations platform.

## 📋 Table of Contents

- [Core Design Principles](#-core-design-principles)
- [Workflow Structure](#-workflow-structure)
- [Node Naming Conventions](#-node-naming-conventions)
- [Error Handling Patterns](#-error-handling-patterns)
- [Performance Optimization](#-performance-optimization)
- [Security Considerations](#-security-considerations)
- [Testing Guidelines](#-testing-guidelines)
- [Documentation Requirements](#-documentation-requirements)

---

## 🎯 Core Design Principles

### 1. Single Responsibility
Each workflow should have a clear, single purpose:
- ✅ **Good**: "Support Ticket Triage"
- ❌ **Bad**: "Support and Marketing and Analytics"

### 2. Modular Design
Break complex processes into smaller, reusable workflows:
```
Main Workflow → Sub-workflow 1 → Sub-workflow 2
```

### 3. Idempotent Operations
Workflows should produce the same result when run multiple times with the same input.

### 4. Fail-Fast Principle
Validate inputs early and fail quickly if something is wrong.

### 5. Observable Execution
Include logging and monitoring nodes to track workflow execution.

---

## 🏗️ Workflow Structure

### Recommended Flow Pattern

```
[Trigger] → [Validation] → [Processing] → [Decision] → [Actions] → [Notification] → [Cleanup]
```

### 1. **Trigger Nodes**
- Always start with a clear trigger
- Include trigger validation
- Document trigger requirements

```javascript
// Webhook validation example
const payload = $input.first().json;
if (!payload.timestamp || !payload.event_type) {
    throw new Error('Invalid payload: missing required fields');
}
```

### 2. **Validation Nodes**
- Validate all inputs early
- Check required fields
- Sanitize data

### 3. **Processing Nodes**
- Keep processing logic focused
- Use meaningful variable names
- Comment complex operations

### 4. **Decision Nodes**
- Use Switch nodes for multiple paths
- Use IF nodes for binary decisions
- Always handle the "else" case

### 5. **Action Nodes**
- One action per node when possible
- Include timeout configurations
- Handle API errors gracefully

### 6. **Notification Nodes**
- Always notify on completion
- Include relevant context
- Use appropriate channels

### 7. **Cleanup Nodes**
- Clean up temporary data
- Close connections
- Log completion status

---

## 📝 Node Naming Conventions

### Node Names Should Be:
- **Descriptive**: Clearly explain what the node does
- **Action-Oriented**: Use verbs for action nodes
- **Consistent**: Follow the same pattern throughout

### Examples:

#### ✅ Good Node Names
- `Parse Email Content`
- `Classify with AI Agent`
- `Send Discord Notification`
- `Update Database Record`
- `Validate Input Data`

#### ❌ Bad Node Names
- `Node 1`
- `HTTP Request`
- `Code`
- `Do Stuff`
- `Check`

### Category Prefixes
Use prefixes to group related nodes:
- `Validate: Email Format`
- `API: Get User Data`
- `Transform: Clean Text`
- `Notify: Send Alert`

---

## 🛡️ Error Handling Patterns

### 1. **Global Error Handling**
Every workflow should have a global error handler:

```javascript
// Global error handler node
const error = $input.first().json.error;
const context = $input.first().json.context;

const errorData = {
    workflow_name: "{{ workflow.name }}",
    node_name: context.node_name,
    error_message: error.message,
    timestamp: new Date().toISOString(),
    input_data: context.input_data
};

// Log error and send notification
return [{ json: errorData }];
```

### 2. **Retry Logic**
For external API calls, implement retry logic:

```javascript
// Retry configuration
const maxRetries = 3;
const retryDelay = 1000; // ms
const currentRetry = $node.context.retry || 0;

if (currentRetry < maxRetries) {
    // Increment retry counter
    $node.context.retry = currentRetry + 1;
    
    // Wait before retry
    await new Promise(resolve => setTimeout(resolve, retryDelay * currentRetry));
    
    // Return original input to retry
    return $input.all();
} else {
    throw new Error(`Max retries (${maxRetries}) exceeded`);
}
```

### 3. **Graceful Degradation**
Handle partial failures gracefully:

```javascript
// Process items individually to handle partial failures
const results = [];
const errors = [];

for (const item of $input.all()) {
    try {
        const result = await processItem(item.json);
        results.push({ json: result });
    } catch (error) {
        errors.push({ 
            json: { 
                item: item.json, 
                error: error.message 
            } 
        });
    }
}

// Return both successes and failures
return [results, errors];
```

---

## ⚡ Performance Optimization

### 1. **Batch Processing**
Process multiple items together when possible:

```javascript
// Good: Process in batches
const batchSize = 10;
const batches = [];

for (let i = 0; i < items.length; i += batchSize) {
    batches.push(items.slice(i, i + batchSize));
}

return batches.map(batch => ({ json: { items: batch } }));
```

### 2. **Async Operations**
Use Promise.all for parallel operations:

```javascript
// Process multiple APIs in parallel
const promises = urls.map(url => 
    fetch(url).then(response => response.json())
);

const results = await Promise.all(promises);
return results.map(result => ({ json: result }));
```

### 3. **Memory Management**
Clean up large objects:

```javascript
// Clean up after processing
const result = processLargeData(largeObject);
largeObject = null; // Free memory
return [{ json: result }];
```

### 4. **Conditional Execution**
Skip unnecessary processing:

```javascript
// Skip processing if conditions not met
if (!shouldProcess(inputData)) {
    return [{ json: { skipped: true, reason: "Conditions not met" } }];
}
```

---

## 🔒 Security Considerations

### 1. **Credential Management**
- Never hardcode credentials
- Use n8n credential system
- Rotate credentials regularly

### 2. **Input Validation**
Always validate and sanitize inputs:

```javascript
// Input sanitization
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        throw new Error('Input must be a string');
    }
    
    // Remove potentially dangerous characters
    return input
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .trim();
}
```

### 3. **Data Privacy**
- Don't log sensitive data
- Mask PII in outputs
- Use secure communication channels

### 4. **Rate Limiting**
Respect API rate limits:

```javascript
// Simple rate limiting
const lastCall = $node.context.lastCall || 0;
const minInterval = 1000; // 1 second
const now = Date.now();

if (now - lastCall < minInterval) {
    await new Promise(resolve => 
        setTimeout(resolve, minInterval - (now - lastCall))
    );
}

$node.context.lastCall = Date.now();
```

---

## 🧪 Testing Guidelines

### 1. **Test Data**
Create comprehensive test datasets:

```javascript
// Test data structure
const testCases = [
    {
        name: "valid_email",
        input: { subject: "Test", body: "Hello world" },
        expected: { category: "general", priority: "normal" }
    },
    {
        name: "malformed_email",
        input: { subject: "" },
        expected: { error: "Missing subject" }
    }
];
```

### 2. **Unit Testing**
Test individual code nodes:

```javascript
// Test function in isolation
function classifyEmail(subject, body) {
    // Your classification logic here
    return { category: "general", priority: "normal" };
}

// Test cases
const testSubject = "Test subject";
const testBody = "Test body";
const result = classifyEmail(testSubject, testBody);

// Assertions
if (result.category !== "general") {
    throw new Error("Classification failed");
}
```

### 3. **Integration Testing**
Test complete workflow with real data:
- Use test environments
- Mock external services when needed
- Verify end-to-end functionality

### 4. **Load Testing**
Test workflow performance:
- High volume of inputs
- Concurrent executions
- Resource usage monitoring

---

## 📚 Documentation Requirements

### 1. **Workflow Documentation**
Each workflow must include:

```javascript
/**
 * Workflow: Support Ticket Triage
 * Purpose: Automatically classify and route support emails
 * Trigger: IMAP email monitoring
 * 
 * Inputs:
 * - Email subject (string)
 * - Email body (string)
 * - Sender address (string)
 * 
 * Outputs:
 * - Classification result
 * - Routing decision
 * - Confidence score
 * 
 * Dependencies:
 * - Wildbox Agents API
 * - Support database
 * - Discord webhook
 * 
 * Error Handling:
 * - Invalid email format → Archive as unprocessed
 * - API timeout → Retry 3 times
 * - Classification failure → Route to human review
 * 
 * Performance:
 * - Avg execution time: 5-10 seconds
 * - Max concurrent executions: 5
 * - Rate limit: 100 emails/hour
 */
```

### 2. **Node Documentation**
Complex nodes should include comments:

```javascript
// Node: Process and Categorize Articles
// Purpose: Filter recent articles and group by security themes
// Performance: Processes up to 1000 articles in ~2 seconds

const articles = $input.all().map(item => item.json);
const currentTime = new Date();

// Filter articles from last 24 hours
const oneDayAgo = new Date(currentTime.getTime() - 24 * 60 * 60 * 1000);
const recentArticles = articles.filter(article => {
    const pubDate = new Date(article.pubDate);
    return pubDate >= oneDayAgo;
});

// Categorization logic...
```

### 3. **Change Log**
Document workflow changes:

```markdown
## Workflow Change Log

### v1.2.0 - 2025-01-26
- Added retry logic for API failures
- Improved error handling for malformed emails
- Updated classification thresholds

### v1.1.0 - 2025-01-20
- Added Discord notifications
- Implemented batch processing
- Fixed memory leak in article processing

### v1.0.0 - 2025-01-15
- Initial version
- Basic email classification
- GitHub issue creation
```

---

## 🏆 Best Practices Summary

### ✅ Do:
- Use descriptive node names
- Implement comprehensive error handling
- Include logging and monitoring
- Validate inputs early
- Document complex logic
- Test thoroughly
- Use credentials system
- Optimize for performance

### ❌ Don't:
- Hardcode sensitive data
- Ignore error conditions
- Create overly complex workflows
- Skip input validation
- Forget to handle edge cases
- Use generic node names
- Process large datasets inefficiently
- Mix multiple concerns in one workflow

---

## 📞 Support

For questions about workflow design:
- Check existing workflows for examples
- Review n8n documentation
- Ask in the team Discord channel
- Create a GitHub issue for complex problems

---

*Last updated: January 26, 2025*
