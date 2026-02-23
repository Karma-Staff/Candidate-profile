# 🏗️ Restoration Talent Platform: PROJECT OVERVIEW

A premium, secure enterprise-level talent marketplace designed specifically for the restoration industry. This platform facilitates the matching of skilled restoration professionals with business owners, ensuring SOC 2 compliance and high-tier security.

---

## 🌟 Executive Summary

The Restoration Talent Platform is a high-performance web application that serves as a bridge between restoration candidates and clients. It provides a highly curated browsing experience with granular access controls, ensuring that PII (Personally Identifiable Information) is protected while allowing for efficient scheduling and candidate assessment.

---

## 🛠️ System Architecture

Built on the modern **Next.js 15 App Router**, the application leverages a split architecture:

- **Frontend**: React 19 components with server-side rendering for optimal performance and SEO.
- **API Layer**: Next.js Route Handlers managed under `app/api/`.
- **Data Layer**: Prisma ORM with PostgreSQL for persistent storage, with a transitional JSON-based persistence layer for rapid prototyping.
- **Authentication**: NextAuth.js implementing secure session management via JWT.

### Project Structure Highlights
- `/app`: Contains all pages and API routes organized by feature.
- `/components`: Modular UI components divided into `candidates`, `layout`, and `ui` (Shadcn-like primitives).
- `/lib`: Core utilities including RBAC logic, audit logging engines, and shared type definitions.
- `/data`: Storage for legacy/mock JSON data.

---

## 🔐 Security & Compliance

The platform is designed with security as a first-class citizen, targeting **SOC 2 compliance** standards.

### Role-Based Access Control (RBAC)
The system supports three distinct roles defined in `lib/rbac.ts`:

| Feature | Admin / Customer Service | Client |
|---------|-------------------------|--------|
| View Candidates | ✅ Full Access | ✅ Restricted |
| View Full PII | ✅ Yes | ❌ No |
| Add/Edit Candidates | ✅ Yes | ❌ No |
| Download Resumes | ✅ Yes | ❌ No |
| Schedule Meetings | ✅ Yes | ✅ Yes |
| View Audit Logs | ✅ Yes | ❌ No |

### Audit Logging
Every interaction involving PII or sensitive resources is captured in the **Audit Logging System**. This ensures a clear trail for compliance audits, tracking the User ID, Action, Timestamp, and IP Address.

---

## 📦 Core Features

### 1. Candidate Management
A sophisticated filtering and search system for restoration professionals.
- **Advanced Filtering**: Filter by experience, skills, and availability.
- **Candidate Grading**: Internal rankings for personality, accent, and technical skill.
- **Video Profiles**: Integration for candidate video introductions.

### 2. Meeting Scheduling
An interactive interface for booking interviews between clients and candidates.
- **Standard & Premium Meetings**: Support for different meeting types.
- **Participant Tracking**: Manage multiple participants per interview.

### 3. Client Assignments
Personalized candidate shortlists created by Admin/CS teams specifically for certain clients, appearing in the client's dashboard.

### 4. AI Coaching (Beta)
An embedded AI agent assistant to help Admins manage the platform and candidates efficiently.

---

## 🚀 Tech Stack

- **Framework**: `Next.js 15` (App Router)
- **Runtime**: `Node.js 18+`
- **Database**: `PostgreSQL` (via Prisma)
- **Styling**: `Tailwind CSS`
- **Authentication**: `NextAuth.js`
- **Icons**: `Lucide React`
- **Type Safety**: `TypeScript`

---

## 🗺️ Roadmap

- [ ] **Full Database Migration**: Complete move from JSON to PostgreSQL.
- [ ] **Email Notifications**: Integration with Resend for meeting confirmations.
- [ ] **Calendar Integration**: Google/Outlook calendar synchronization.
- [ ] **Analytics Dashboard**: Real-time engagement metrics for Admins.
- [ ] **File Storage**: Secure S3/Azure Blob storage for candidate documents.

---

*This document is a living overview of the Restoration Talent Platform. For installation instructions, please refer to the [README.md](file:///c:/Users/Anjan.theeng/OneDrive%20-%20Karma%20Staff/Desktop/profile%20check/README.md).*
