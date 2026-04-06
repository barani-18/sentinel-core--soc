# Sentinel-Core Deployment Guide

Complete instructions for deploying the Sentinel-Core SOC simulation platform.

## 🎯 Architecture Overview

```
┌─────────────────┐         ┌──────────────────┐
│   Frontend      │  HTTP   │    Backend       │
│   (React/Vite)  │ ──────> │    (FastAPI)     │
│   Vercel/Netlify│         │  HF Spaces/Docker│
└─────────────────┘         └──────────────────┘
        │                            │
        └─────── JWT Auth ───────────┘
```

## 📦 What's Included

### Frontend (Ready to Deploy)
- **Location**: Root directory (built to `dist/`)
- **Tech**: React 18, TypeScript, Tailwind, Recharts
- **Features**: Login portal, SOC dashboard, real-time simulation
- **Size**: ~672 KB (194 KB gzipped)

### Backend (Ready to Deploy)
- **Location**: `backend/`
- **Tech**: FastAPI, Python 3.11, JWT
- **Features**: /login, /reset, /step, /state endpoints
- **Files**: `main.py`, `requirements.txt`, `Dockerfile`

## 🚀 Deployment Options

### Option 1: Full Stack (Recommended)

**Frontend → Vercel**
1. Push code to GitHub
2. Import project in Vercel
3. Set environment variable:
   ```
   VITE_API_URL=https://your-backend.hf.space
   ```
4. Deploy (auto-builds)

**Backend → Hugging Face Spaces**
1. Create new Space at huggingface.co
2. Choose "Docker" SDK
3. Upload these files from `backend/`:
   - `main.py`
   - `requirements.txt`
   - `Dockerfile`
   - `README.md`
4. Space builds automatically
5. API available at `https://username-spacename.hf.space`

### Option 2: Frontend Only (Demo Mode)

Works without backend using built-in simulation:

**Vercel:**
```bash
npm run build
# Upload dist/ folder
```

**Netlify:**
- Drag & drop `dist/` folder
- Or connect GitHub repo

**GitHub Pages:**
```bash
npm run build
# Push dist/ to gh-pages branch
```

### Option 3: Local Development

**Terminal 1 - Backend:**
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

**Terminal 2 - Frontend:**
```bash
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

Visit: http://localhost:5173

## 🔐 Environment Variables

### Frontend (.env)
```env
VITE_API_URL=https://your-backend.hf.space
```

### Backend (optional)
```env
SECRET_KEY=your-secret-key-here-change-in-prod
ACCESS_TOKEN_EXPIRE_HOURS=8
```

## 🐳 Docker Commands

### Build Backend
```bash
cd backend
docker build -t sentinel-core-api:latest .
```

### Run Locally
```bash
docker run -p 8000:8000 sentinel-core-api:latest
```

### Test
```bash
curl http://localhost:8000/health
# {"status":"healthy","timestamp":...}
```

### Push to Registry
```bash
docker tag sentinel-core-api:latest your-registry/sentinel-core:latest
docker push your-registry/sentinel-core:latest
```

## ☁️ Cloud Deployment Details

### Hugging Face Spaces

1. **Create Space**
   - Go to huggingface.co/spaces
   - Click "Create new Space"
   - Name: `sentinel-core-api`
   - SDK: Docker
   - Hardware: CPU basic (free)

2. **Upload Files**
   ```
   ├── Dockerfile
   ├── main.py
   ├── requirements.txt
   └── README.md
   ```

3. **Wait for Build**
   - Takes 2-3 minutes
   - Check logs for errors
   - Test at `https://huggingface.co/spaces/YOURNAME/sentinel-core-api`

4. **Set as Public**
   - Space settings → Visibility → Public

### Vercel Deployment

1. **Via CLI**
```bash
npm i -g vercel
vercel
# Follow prompts
```

2. **Via GitHub**
- Connect repo
- Framework: Vite
- Build command: `npm run build`
- Output: `dist`
- Env var: `VITE_API_URL`

3. **Custom Domain**
- Vercel dashboard → Domains
- Add your domain
- Update DNS

### Netlify Deployment

**Drag & Drop:**
1. Run `npm run build`
2. Go to app.netlify.com/drop
3. Drop `dist/` folder

**Via CLI:**
```bash
npm i -g netlify-cli
netlify deploy --prod --dir=dist
```

## 🔧 Configuration

### CORS Settings
Backend already allows all origins. For production, edit `main.py`:
```python
allow_origins=["https://your-frontend.vercel.app"]
```

### JWT Secret
Change in `backend/main.py`:
```python
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-key")
```

### API Timeout
Frontend auto-falls back to demo mode if backend unavailable (3s timeout).

## 📊 Monitoring

### Health Checks
```bash
# Backend
curl https://your-api.hf.space/health

# Frontend
curl -I https://your-app.vercel.app
```

### Logs
- **Vercel**: Dashboard → Deployments → Functions
- **HF Spaces**: Space → Logs tab
- **Docker**: `docker logs container-id`

## 🔒 Security Checklist

Before production:

- [ ] Change `SECRET_KEY` in backend
- [ ] Enable HTTPS (automatic on Vercel/HF)
- [ ] Set proper CORS origins
- [ ] Add rate limiting to FastAPI
- [ ] Use environment variables for secrets
- [ ] Enable WAF on frontend
- [ ] Rotate JWT secret periodically
- [ ] Add request logging
- [ ] Set up error tracking (Sentry)

## 🧪 Testing Deployment

### 1. Test Backend
```bash
# Health
curl https://your-api.hf.space/health

# Login
curl -X POST https://your-api.hf.space/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"soc2024"}'

# Get state (use token from login)
curl https://your-api.hf.space/state \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Test Frontend
1. Visit your deployed URL
2. Login with `analyst` / `soc2024`
3. Check dashboard loads
4. Click "Run Step" - should work
5. Check browser console for errors

### 3. Test Integration
- Login → should show user name in header
- Take action → logs should appear
- Check network tab → API calls to backend
- If backend down → falls back to demo mode

## 🐛 Troubleshooting

### Frontend can't connect to backend
- Check `VITE_API_URL` is correct
- Verify backend is running (`/health`)
- Check CORS in browser console
- Ensure backend allows your domain

### Backend 502 errors on HF
- Check Dockerfile exposes port 8000
- Verify `uvicorn main:app --host 0.0.0.0 --port 8000`
- Check Space logs for Python errors

### Login fails
- Verify credentials (see README)
- Check MFA code is "123456" for senior roles
- Inspect network tab for 401 errors

### Charts not rendering
- Ensure Recharts is installed
- Check for JavaScript errors
- Verify data format matches expected

## 📈 Scaling

### For Production Use:

1. **Backend**
   - Use PostgreSQL instead of in-memory
   - Add Redis for session storage
   - Deploy to AWS ECS / GCP Cloud Run
   - Add load balancer
   - Enable auto-scaling

2. **Frontend**
   - Use CDN (Cloudflare)
   - Enable caching headers
   - Optimize images
   - Add service worker

3. **Database Schema** (if persisting)
```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  state JSONB,
  created_at TIMESTAMP
);
```

## 💰 Cost Estimate

**Free Tier:**
- Vercel: Free (100GB bandwidth)
- HF Spaces: Free (CPU basic)
- Netlify: Free (100GB bandwidth)
- **Total: $0/month**

**Production:**
- Vercel Pro: $20/month
- HF Spaces upgraded: $0-50/month
- Or AWS: ~$30-100/month
- **Total: $20-150/month**

## 🎓 Next Steps

After deployment:

1. Share demo link with team
2. Monitor usage in dashboards
3. Collect feedback
4. Iterate on features
5. Add real threat intel feeds
6. Integrate with actual SIEM

## 📞 Support

- Frontend issues: Check browser console
- Backend issues: Check HF Space logs
- API docs: Visit `/docs` on backend URL
- Full docs: See README.md

---

**Deployment time**: ~10 minutes for full stack
**Difficulty**: Beginner-friendly