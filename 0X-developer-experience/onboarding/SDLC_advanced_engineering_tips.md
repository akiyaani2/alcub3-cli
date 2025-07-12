# Advanced Engineering Tips & Techniques

*From good to exceptional - but knowing when NOT to use them*

---

## 🚫 When NOT to Use These Patterns (Start Here!)

### The Golden Rule for Solo Developers
**If you can't explain why you need it in one sentence, you don't need it.**

### Quick Decision Matrix

| Pattern | Use When | DON'T Use When | Your Context |
|---------|----------|----------------|--------------|
| **Microservices** | 50+ developers, clear bounded contexts | Solo/small team, < 1M users | ❌ Stay monolith |
| **Event Sourcing** | Audit requirements, time-travel needed | CRUD apps, simple state | ❌ Overkill |
| **CQRS** | Read/write at different scales | Balanced load, simple queries | ❌ Not needed |
| **GraphQL** | Multiple client types, complex data needs | Single client, REST works | ❌ REST is fine |
| **Kubernetes** | Multi-region, auto-scaling critical | Single server works, < 100 deploys/year | ❌ Use Docker |
| **Service Mesh** | 100+ microservices | Monolith or < 10 services | ❌ Not applicable |
| **Distributed Tracing** | Actual microservices | Monolith with good logs | ❌ Logs suffice |

### Your Specific Anti-Patterns

1. **Don't add "enterprise" patterns** - You're not an enterprise
2. **Don't optimize for problems you don't have** - No premature optimization
3. **Don't add layers of abstraction** - Your 3-layer architecture is enough
4. **Don't automate things you do monthly** - Manual is fine for rare tasks
5. **Don't add process overhead** - You're solo, not a team

---

## 🧠 Mental Models for Better Engineering

### 1. **The Three-Layer Architecture Rule**

✅ **USE THIS** - It's perfect for your needs

```typescript
// Interface Layer (API/CLI)
class RobotController {
  async moveRobot(id: string, coordinates: Coordinates): Promise<Result> {
    return this.robotService.move(id, coordinates);
  }
}

// Business Logic Layer
class RobotService {
  async move(id: string, coordinates: Coordinates): Promise<Result> {
    const robot = await this.robotRepo.findById(id);
    const validation = this.validator.validateMove(robot, coordinates);
    if (!validation.isValid) throw new InvalidMoveError(validation.errors);
    
    const movement = new Movement(robot, coordinates);
    return this.robotRepo.executeMovement(movement);
  }
}

// Data Layer
class RobotRepository {
  async findById(id: string): Promise<Robot> {
    return this.db.robots.findOne({ id });
  }
}
```

**❌ DON'T ADD MORE LAYERS** - No "Domain layer", "Application layer", "Infrastructure layer" etc. Three is enough!

### 2. **The 10/10 Rule**
If it takes more than 10 minutes to understand or 10 lines to explain, it's too complex.

**Reality Check**: Most of your functions should be < 5 lines. If not, you're over-engineering.

### 3. **The Two-Pizza Team Rule**
Any component should be maintainable by a team that can be fed with two pizzas (5-8 people).

**Your Reality**: You're ONE person. Every component should be maintainable by YOU after 6 months away.

---

## 🚀 Performance Optimization Patterns

### 1. **Request Batching Pattern**

**✅ USE WHEN**: 
- Making 100+ similar requests/second
- API has batch endpoints
- Network latency is significant

**❌ DON'T USE WHEN**:
- < 10 requests/second (YOUR CASE)
- Adds complexity without measurable benefit
- Real-time requirements conflict with batching

**Your Alternative**:
```typescript
// Simple rate limiting is probably enough
const rateLimiter = {
  lastCall: 0,
  minInterval: 100, // ms
  
  async call(fn: () => Promise<any>) {
    const now = Date.now();
    const timeSinceLastCall = now - this.lastCall;
    
    if (timeSinceLastCall < this.minInterval) {
      await sleep(this.minInterval - timeSinceLastCall);
    }
    
    this.lastCall = Date.now();
    return fn();
  }
};
```

### 2. **Circuit Breaker Pattern**

**✅ USE WHEN**: 
- Calling external services that may fail
- Failure cascades are possible
- You have fallback behavior

**❌ DON'T USE WHEN**:
- Services rarely fail
- No meaningful fallback exists
- Adds more complexity than reliability

**Your Simple Alternative**:
```typescript
// Just retry with exponential backoff
async function callWithRetry<T>(
  fn: () => Promise<T>,
  maxRetries = 3
): Promise<T> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await sleep(Math.pow(2, i) * 1000); // Exponential backoff
    }
  }
  throw new Error('Unreachable');
}
```

### 3. **Memory-Efficient Streaming**

**✅ DEFINITELY USE THIS** for files > 100MB

**Your Reality**: Most config files are < 1MB. Just use `fs.readFile()` until you hit actual memory issues.

---

## 🔐 Security Patterns Beyond Basics

### 1. **Defense in Depth**

**✅ USE THIS** - Security layers are always worth it for defense software

But **SIMPLIFY** for solo development:

```typescript
// Combine validation and authorization in middleware
export const secureEndpoint = [
  validateInput,      // Zod schema validation
  authenticate,       // JWT verification
  authorize,          // Check permissions
  rateLimit,         // Basic rate limiting
  auditLog,          // Log all access
  handleRequest      // Actual logic
];

// DON'T create 15 different middleware classes
```

### 2. **Secure Secrets Management**

**❌ DON'T BUILD** a complex secrets rotation system

**✅ DO USE** environment variables + validation:
```typescript
// This is enough for your needs
const config = {
  jwtSecret: process.env.JWT_SECRET || panic('JWT_SECRET required'),
  dbUrl: process.env.DATABASE_URL || panic('DATABASE_URL required'),
};

function panic(msg: string): never {
  console.error(`FATAL: ${msg}`);
  process.exit(1);
}
```

**Use AWS Secrets Manager or similar when you have a team, not before.**

---

## 🧪 Advanced Testing Strategies

### 1. **Property-Based Testing**

**✅ USE WHEN**: 
- Testing algorithms with mathematical properties
- Security-critical code (encryption, hashing)
- Parser/serializer code

**❌ DON'T USE WHEN**:
- Simple CRUD operations
- UI components
- Business logic with few invariants

**Your Reality**: Start with example-based tests. Add property tests only for crypto/security code.

### 2. **Mutation Testing**

**❌ SKIP THIS** - It's a time sink for solo developers

**Your Alternative**: Focus on test coverage > 80% and meaningful assertions.

### 3. **Chaos Engineering**

**❌ DEFINITELY SKIP** - This is for distributed systems with 100+ services

**Your Alternative**: 
```typescript
// Simple error injection for testing
const DEBUG_FAIL_RATE = process.env.DEBUG_FAIL_RATE || 0;

function maybeInjectError() {
  if (Math.random() < DEBUG_FAIL_RATE) {
    throw new Error('Injected test error');
  }
}
```

---

## 📊 Observability & Monitoring

### 1. **Structured Logging**

**The Solo Developer's Rule**: Start with `console.log`, upgrade when you need to search logs.

```typescript
// Start with this
const log = (level: string, msg: string, data?: any) => {
  console.log(JSON.stringify({ 
    timestamp: new Date().toISOString(), 
    level, 
    msg, 
    ...data 
  }));
};

// DON'T start with OpenTelemetry, Jaeger, Zipkin, etc.
```

### 2. **Custom Metrics**

**❌ DON'T BUILD** a metrics collection system

**✅ DO USE** simple counters:
```typescript
// This is enough to start
const metrics = {
  requests: 0,
  errors: 0,
  
  log() {
    console.log(`Requests: ${this.requests}, Errors: ${this.errors}`);
  }
};
```

**Add Prometheus/Grafana when you have real traffic, not before.**

---

## 🏗️ Architecture Patterns

### 1. **Event-Driven Architecture**

**🚨 WARNING**: This is where most solo developers over-engineer

**❌ DON'T USE WHEN**:
- You have < 10 event types
- No real-time requirements
- Simple request/response works
- You're building CRUD (YOUR CASE)

**Your Alternative**:
```typescript
// Just use async functions and callbacks
class RobotService {
  async moveRobot(id: string, position: Position) {
    const robot = await this.updatePosition(id, position);
    await this.auditLog('robot.moved', { id, position });
    await this.notifyIfNeeded(robot);
    return robot;
  }
}

// DON'T add event buses, CQRS, event sourcing, etc.
```

### 2. **Hexagonal Architecture**

**❌ TOO MUCH ABSTRACTION** for solo projects

**Your Alternative**: Stick with your 3-layer architecture. It's hexagonal enough.

---

## 🛠️ Solo Developer's Productivity Guide

### What Actually Matters for You

1. **Pre-commit hooks** ✅ (saves hours)
2. **Automated tests** ✅ (confidence in changes)
3. **Performance budgets** ✅ (meet requirements)
4. **Security scanning** ✅ (contract requirement)
5. **Simple deployment** ✅ (Docker + script)

### What's Premature Optimization

1. **Microservices** ❌
2. **Event sourcing** ❌
3. **CQRS** ❌
4. **Service mesh** ❌
5. **Kubernetes** ❌
6. **GraphQL** ❌
7. **Distributed tracing** ❌
8. **Complex CI/CD** ❌

### Your Actual Tech Stack Should Be

```yaml
Core:
  - TypeScript (type safety)
  - Node.js (you know it)
  - PostgreSQL or SQLite (simple, reliable)
  - Express (battle-tested)

Testing:
  - Vitest (fast, simple)
  - Supertest (API testing)

DevOps:
  - Docker (containerization)
  - GitHub Actions (CI)
  - Simple bash scripts (deployment)

Monitoring:
  - Console.log → JSON (good enough)
  - Sentry (error tracking)
  - UptimeRobot (availability)
```

---

## 💡 Solo Developer Pro Tips

### 1. **The YAGNI Principle**
"You Aren't Gonna Need It" - Don't add features/patterns for hypothetical future needs.

### 2. **The KISS Principle**
"Keep It Simple, Stupid" - The simplest solution that works is the best solution.

### 3. **The Boring Technology Principle**
Choose boring, proven technology over exciting new things. Boring = reliable.

### 4. **The One-Person Rule**
If you can't maintain it alone when sick/tired/distracted, it's too complex.

### 5. **The 6-Month Test**
If you won't understand it in 6 months, rewrite it simpler now.

---

## 🎯 Your Personalized Checklist

### Must-Haves (Do These)
- [x] Pre-commit hooks
- [x] 80%+ test coverage
- [x] Performance budgets
- [x] Security scanning
- [x] Simple documentation
- [x] Error boundaries
- [x] Input validation
- [x] Audit logging

### Nice-to-Haves (Consider Later)
- [ ] API versioning (when you have external users)
- [ ] Feature flags (when deploying gets risky)
- [ ] A/B testing (when you have users to test)
- [ ] Advanced monitoring (when simple logs aren't enough)

### Never-Needs (Skip These)
- ❌ Microservices architecture
- ❌ Event sourcing / CQRS
- ❌ Kubernetes orchestration
- ❌ Service mesh
- ❌ GraphQL
- ❌ Complex CI/CD pipelines
- ❌ Distributed tracing
- ❌ Chaos engineering

---

## 🚀 The Bottom Line

You're building defense-grade software as a solo developer. Your constraints are:
- **Time**: You only have 24 hours/day
- **Complexity Budget**: You can only hold so much in your head
- **Maintenance**: Future-you needs to understand it
- **Requirements**: Security and performance are non-negotiable

Every pattern in this document can be useful, but most aren't useful FOR YOU RIGHT NOW.

Start simple. Add complexity only when simple breaks. Your monolith with 3 layers, good tests, and security focus is exactly right.

**Remember**: Facebook started as a monolith. Google started as a monolith. GitHub is still mostly a monolith. You're in good company.

**Final Wisdom**: The best code is no code. The best architecture is the simplest one that works. The best process is the least process that ensures quality.

You're already doing great. Don't let perfect be the enemy of good.