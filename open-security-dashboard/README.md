# 🛡️ Wildbox Security Dashboard

A comprehensive security operations center and threat intelligence platform built with Next.js, TypeScript, and modern UI components.

## 🎯 Overview

The Wildbox Security Dashboard is the central command center for the Wildbox security suite, providing a unified interface to manage and monitor all security operations including:

- **Threat Intelligence**: IOC lookups, threat feeds management
- **Cloud Security**: CSPM scans and compliance monitoring  
- **Endpoint Management**: Agent deployment and monitoring
- **Vulnerability Management**: Security findings and remediation tracking
- **Response Automation**: Playbook execution and incident response
- **AI-Powered Analysis**: Intelligent threat hunting and analysis

## 🚀 Features

### 🔍 **Threat Intelligence**
- Real-time IOC lookup and analysis
- Threat feed management and monitoring
- Reputation scoring and geolocation data
- Integrated WHOIS and certificate intelligence

### ☁️ **Cloud Security (CSPM)**
- Multi-cloud account scanning (AWS, Azure, GCP)
- Compliance framework assessment
- Risk scoring and remediation guidance
- Automated compliance reporting

### 🖥️ **Endpoint Management**
- Agent deployment and health monitoring
- Telemetry collection and analysis
- Endpoint alerts and incident management
- Fleet management and configuration

### 🔧 **Security Toolbox**
- 50+ integrated security tools
- Dynamic form generation for tool parameters
- Real-time execution monitoring
- Output visualization and analysis

### ⚡ **Response Automation**
- Playbook creation and execution
- Workflow orchestration
- Step-by-step execution tracking
- Integration with external systems

### 🧠 **AI-Powered Analysis**
- Intelligent threat analysis
- Automated report generation
- Context-aware recommendations
- Real-time progress tracking

## 🛠️ Technology Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **UI Components**: Shadcn/ui (Radix UI + Tailwind)
- **State Management**: TanStack Query (React Query)
- **HTTP Client**: Axios with interceptors
- **Authentication**: JWT with secure cookie storage
- **Charts**: Recharts
- **Icons**: Lucide React

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Wildbox Security Dashboard                  │
├─────────────────────────────────────────────────────────────┤
│  Frontend (Next.js)                                         │
│  ├── Authentication & Authorization                         │
│  ├── Real-time Data Visualization                          │
│  ├── Interactive Tool Execution                            │
│  └── Responsive Mobile-First Design                        │
├─────────────────────────────────────────────────────────────┤
│  API Integration Layer                                       │
│  ├── open-security-api      (Tools & Execution)            │
│  ├── open-security-data     (Threat Intelligence)          │
│  ├── open-security-guardian (Vulnerability Management)     │
│  ├── open-security-sensor   (Endpoint Management)          │
│  ├── open-security-responder (Response Automation)         │
│  └── open-security-agents   (AI Analysis)                  │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
src/
├── app/                          # Next.js 14 App Router
│   ├── auth/                    # Authentication pages
│   ├── dashboard/               # Main dashboard
│   ├── threat-intel/            # Threat intelligence features
│   ├── toolbox/                 # Security tools execution
│   ├── cloud-security/          # CSPM and compliance
│   ├── endpoints/               # Endpoint management
│   ├── vulnerabilities/         # Vulnerability management
│   ├── response/                # Response automation
│   ├── ai-analyst/              # AI-powered analysis
│   ├── settings/                # User settings and configuration
│   ├── layout.tsx               # Root layout
│   ├── page.tsx                 # Home page (redirects to dashboard)
│   ├── globals.css              # Global styles
│   └── providers.tsx            # React Query and theme providers
├── components/                   # React components
│   ├── ui/                      # Base UI components (Shadcn/ui)
│   ├── auth-provider.tsx        # Authentication context
│   ├── main-layout.tsx          # Main application layout
│   └── theme-provider.tsx       # Theme management
├── lib/                         # Utility libraries
│   ├── api-client.ts            # API client with interceptors
│   └── utils.ts                 # Utility functions
├── hooks/                       # Custom React hooks
├── types/                       # TypeScript type definitions
└── utils/                       # Additional utilities
```

## 🔧 Installation & Setup

### Prerequisites

- Node.js 18+ 
- npm, yarn, or pnpm
- Git

### Quick Start

1. **Clone the repository**
   ```bash
   cd open-security-dashboard
   ```

2. **Install dependencies**
   ```bash
   npm install
   # or
   yarn install
   # or  
   pnpm install
   ```

3. **Environment setup**
   ```bash
   cp .env.example .env.local
   ```
   
   Edit `.env.local` with your configuration:
   ```env
   # API Endpoints
   NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
   NEXT_PUBLIC_DATA_API_URL=http://localhost:8002
   NEXT_PUBLIC_GUARDIAN_API_URL=http://localhost:8002
   NEXT_PUBLIC_SENSOR_API_URL=http://localhost:8003
   NEXT_PUBLIC_RESPONDER_API_URL=http://localhost:8004
   NEXT_PUBLIC_AGENTS_API_URL=http://localhost:8005
   
   # Authentication
   NEXTAUTH_SECRET=your-secret-key
   NEXTAUTH_URL=http://localhost:3000
   ```

4. **Start development server**
   ```bash
   npm run dev
   # or
   yarn dev
   # or
   pnpm dev
   ```

5. **Open in browser**
   Navigate to [http://localhost:3000](http://localhost:3000)

## 🔐 Authentication

The dashboard uses JWT-based authentication with secure HTTP-only cookies. Default development credentials:

- **Email**: `admin@wildbox.com`
- **Password**: `admin123`

## 📊 Key Features Implementation

### Dashboard Overview
- Real-time system health monitoring
- Security metrics and trends visualization
- Recent activity feed
- Quick action shortcuts

### Threat Intelligence
- **IOC Lookup**: Analyze IPs, domains, URLs, hashes
- **Feed Management**: Monitor and configure threat feeds
- **Reputation Analysis**: Multi-source reputation scoring
- **Geolocation & WHOIS**: Comprehensive indicator context

### Cloud Security
- **Scan Management**: Schedule and monitor compliance scans
- **Finding Details**: Detailed remediation guidance
- **Compliance Frameworks**: NIST, PCI-DSS, SOX, HIPAA support
- **Risk Scoring**: Context-aware risk prioritization

### Security Toolbox
- **Dynamic Tool Discovery**: Automatic tool registration
- **Parameter Validation**: Type-safe input handling
- **Execution Monitoring**: Real-time progress tracking
- **Output Visualization**: JSON formatting and syntax highlighting

### Response Automation
- **Playbook Management**: Create and manage response playbooks
- **Workflow Execution**: Step-by-step execution tracking
- **Integration Ready**: Connect with SIEM and ticketing systems
- **Audit Trail**: Complete execution history

### AI Analysis
- **Intelligent Analysis**: Context-aware threat analysis
- **Progress Tracking**: Real-time analysis progress
- **Report Generation**: Professional markdown reports
- **Recommendation Engine**: Actionable security insights

## 🧪 Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint
- `npm run type-check` - Run TypeScript checks
- `npm run format` - Format code with Prettier

### Code Style

- **ESLint**: Configured with Next.js recommended rules
- **Prettier**: Consistent code formatting
- **TypeScript**: Strict mode enabled
- **Tailwind CSS**: Utility-first styling approach

### Component Development

UI components follow the Shadcn/ui pattern:
- Base components in `components/ui/`
- Compound components for complex features
- Consistent prop interfaces
- Forward refs for DOM access

## 🚀 Production Deployment

### Build Optimization

```bash
# Build for production
npm run build

# Start production server
npm run start
```

### Docker Deployment

```dockerfile
FROM node:18-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM base AS build
COPY . .
RUN npm run build

FROM base AS runtime
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment Variables

Production environment variables:
```env
NODE_ENV=production
NEXT_PUBLIC_API_BASE_URL=https://api.wildbox.com
NEXTAUTH_SECRET=secure-production-secret
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
```

## 🔧 API Integration

The dashboard integrates with multiple Wildbox microservices:

### Service Endpoints

| Service | Port | Purpose |
|---------|------|---------|
| open-security-api | 8000 | Security tools execution |
| open-security-data | 8002 | Threat intelligence data |
| open-security-guardian | 8003 | Vulnerability management |
| open-security-sensor | 8004 | Endpoint management |
| open-security-responder | 8005 | Response automation |
| open-security-agents | 8006 | AI-powered analysis |

### API Client Features

- **Automatic Authentication**: JWT token management
- **Request/Response Interceptors**: Error handling and logging
- **Retry Logic**: Automatic retry for failed requests
- **Type Safety**: Full TypeScript integration
- **Loading States**: Built-in loading state management

## 🎨 UI/UX Design

### Design System

- **Color Palette**: Security-focused dark/light themes
- **Typography**: Inter font family for readability
- **Spacing**: Consistent 4px grid system
- **Icons**: Lucide React icon library
- **Animations**: Subtle transitions and micro-interactions

### Responsive Design

- **Mobile First**: Optimized for mobile devices
- **Breakpoints**: Tailwind CSS responsive utilities
- **Touch Friendly**: Large touch targets
- **Progressive Enhancement**: Works without JavaScript

### Accessibility

- **WCAG 2.1 AA**: Compliant accessibility standards
- **Keyboard Navigation**: Full keyboard support
- **Screen Readers**: Semantic HTML and ARIA labels
- **High Contrast**: Support for high contrast mode

## 📈 Performance Optimization

### React Query Integration

- **Intelligent Caching**: Automatic data caching and invalidation
- **Background Updates**: Seamless data refresh
- **Optimistic Updates**: Immediate UI updates
- **Error Boundaries**: Graceful error handling

### Next.js Optimizations

- **Image Optimization**: Automatic image optimization
- **Code Splitting**: Automatic route-based splitting
- **Static Generation**: Pre-rendered pages where possible
- **API Route Caching**: Efficient API response caching

## 🔒 Security Considerations

### Data Protection

- **HTTPS Only**: Secure communication channels
- **JWT Tokens**: Secure authentication tokens
- **Input Validation**: Client and server-side validation
- **XSS Protection**: Content Security Policy headers

### Access Control

- **Role-Based Access**: Granular permission system
- **Session Management**: Secure session handling
- **API Key Management**: Secure API key storage
- **Audit Logging**: Complete user action tracking

## 🐛 Troubleshooting

### Common Issues

1. **API Connection Issues**
   - Verify API endpoints in environment variables
   - Check CORS configuration on backend services
   - Ensure proper authentication tokens

2. **Build Errors**
   - Clear `.next` directory: `rm -rf .next`
   - Reinstall dependencies: `rm -rf node_modules && npm install`
   - Check TypeScript errors: `npm run type-check`

3. **Authentication Problems**
   - Verify JWT secret configuration
   - Check cookie settings (secure, sameSite)
   - Ensure proper token expiration handling

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open Pull Request**

### Development Guidelines

- Follow existing code style and patterns
- Add TypeScript types for new features
- Include unit tests for critical functionality
- Update documentation for new features
- Ensure responsive design compliance

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Shadcn/ui**: Beautiful and accessible UI components
- **Tailwind CSS**: Utility-first CSS framework
- **Radix UI**: Low-level UI primitives
- **Lucide**: Beautiful icon library
- **Next.js**: React framework for production

## 📞 Support

- **Documentation**: [Internal Wiki](https://wiki.wildbox.com)
- **Issues**: [GitHub Issues](https://github.com/wildbox/dashboard/issues)
- **Security**: security@wildbox.com
- **General**: support@wildbox.com

---

Built with ❤️ by the Wildbox Security Team
