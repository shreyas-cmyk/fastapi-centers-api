# fastapi-centers-api

This is a FastAPI API hosted on Render to fetch center details from a Supabase or Neon PostgreSQL database.

## How to Deploy on Render

### 1. Fork or Push Repo to GitHub
- Create a new repository on GitHub
- Upload these files

### 2. Connect Render
- Go to [https://dashboard.render.com/](https://dashboard.render.com/)
- Click **New Web Service**
- Connect your GitHub
- Select your repo

### 3. Configure Deployment
- **Build Command:** Leave blank
- **Start Command:**
  uvicorn main:app --host 0.0.0.0 --port $PORT

### 4. Set Environment Variables(Modify DB credentials accordingly)
- DB_NAME=postgres
- DB_USER=postgres
- DB_PASSWORD=UmR9sGpLkSuK0PzM
- DB_HOST=db.zpqzrnnjmzmmgpiuouob.supabase.co
- DB_PORT=5432

### 5. Access Swagger Docs
https://<your-app>.onrender.com/docs, here you get options---> to create new user and get authorization---> then token is generated---> enter the token details accordingly in the blank spaces---> then fetch the center details you wish to do, for this you have 3 options- 1)Fuzzy Search(where you can just enter initials or first word of company name or particular center name), 2) Full name of company or full center name and 3) Search through company domain.
If you are searching through account name , then it will list all the relative centers to that account but if you give particular center name then it will give the details of that particular center.
