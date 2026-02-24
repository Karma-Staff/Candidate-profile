# 🚀 Render Deployment Guide: Karma Staff Platform

Follow these steps to deploy the application to Render. The project is already configured with a `render.yaml` file that handles the setup of the Flask backend and persistent storage for the database.

## 📋 Prerequisites
1. A **GitHub** account with this project pushed to a repository.
2. A **Render** account (connect it to your GitHub).
3. A **Google Gemini API Key** (from [Google AI Studio](https://aistudio.google.com/)).

---

## 🛠️ Step-by-Step Instructions

### 1. Create a New Blueprint Instance
1. Go to your [Render Dashboard](https://dashboard.render.com/).
2. Click the **"New +"** button and select **"Blueprint"**.
3. Select your repository (`candiate`).
4. Give your deployment a group name (e.g., `karma-staff-platform`).

### 2. Configure Environment Variables
Render will find the `render.yaml` file and ask for the following variables:

| Variable | Recommended Value | Description |
|----------|-------------------|-------------|
| **`GEMINI_API_KEY`** | `your-api-key` | **Required** for the AI Agent. |
| **`FLASK_DEBUG`** | `False` | Keeps the site secure and fast. |
| **`DATABASE_PATH`**| `/data/platform.db`| Path to the persistent database file. |
| **`SECRET_KEY`** | (Automatic) | Render will generate this for you. |

### 3. Apply and Deploy
1. Click **"Apply"**.
2. Render will start two things:
   - **sqlite-data**: A 1GB persistent disk to keep your database safe between restarts.
   - **karma-staff-platform**: The web service that runs your Flask app.
3. The build process will take 2-3 minutes.

### 4. Verify the Deployment
1. Once the service is **"Live"**, click the URL provided (e.g., `https://kappa-staff-platform.onrender.com`).
2. Log in with the default Admin credentials:
   - **User**: `Admin@restoration.com`
   - **Pass**: `demo123`
3. Visit the **Health Check** page at `your-url.com/debug/health` to confirm the database is connected and writable.

---

## ⚠️ Important Notes
- **Database Seeding**: The first time you deploy, the system will automatically create the database and add the demo accounts (`Admin`, `CS Team`, `Client`).
- **File Uploads**: All candidate resumes and avatars are stored on the persistent disk (`/data/uploads`), so they won't be lost when you update the code.
- **Costs**: The persistent disk requires a paid Render plan (starting at $7/mo), but the web service can run on the free tier if configured without a disk (though you would lose data on every restart).
