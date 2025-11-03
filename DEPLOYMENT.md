# Deployment Guide for Replit

This guide will help you deploy the GDG Event Manager on Replit's free tier.

## Quick Start on Replit

### Step 1: Import from GitHub
1. Go to [Replit](https://replit.com)
2. Click "Create Repl"
3. Select "Import from GitHub"
4. Enter repository URL: `https://github.com/oashraff/GDG_Workshop_Manager`
5. Click "Import from GitHub"

### Step 2: Configure Environment Variables
In the Replit Secrets tab (🔒 icon on the left sidebar), add:

```
SECRET_KEY=your_secure_random_secret_key_here
NODE_ENV=production
PORT=3000
```

To generate a secure secret key, you can run in the Replit Shell:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Step 3: Initialize Database
In the Replit Shell, run:
```bash
npm install
npm run build-db
```

### Step 4: Start the Application
Click the "Run" button or use:
```bash
npm start
```

The application will be available at the URL Replit provides (usually `https://your-repl-name.your-username.repl.co`)

## Default Admin Credentials

**Username:** `admin`  
**Password:** `gdg2025admin`

**⚠️ IMPORTANT:** Change these credentials immediately after first login!

## Access Points

- **Home Page:** `/`
- **Public Event Browser:** `/attendee`
- **Organiser Login:** `/login`
- **Organiser Dashboard:** `/organiser` (requires authentication)

## Features

✅ Event creation and management  
✅ Public event browsing and filtering  
✅ Attendee booking system  
✅ GDG member verification  
✅ CSRF protection  
✅ Rate limiting  
✅ Secure authentication  
✅ SQLite database (file-based, perfect for Replit)

## Replit-Specific Notes

1. **Database Persistence:** SQLite database file is stored in Replit's filesystem and will persist across runs.

2. **Environment Variables:** Use Replit's Secrets feature (not `.env` file) for production environment variables.

3. **Port Configuration:** Replit automatically handles port mapping. The app runs on port 3000 internally.

4. **Always On:** For Replit's free tier, your app will sleep after inactivity. Consider using Replit's "Always On" feature (requires Hacker plan) for production use.

5. **Custom Domain:** You can connect a custom domain through Replit's dashboard.

## Troubleshooting

### Database Issues
If you encounter database errors, rebuild the database:
```bash
npm run clean-db
npm run build-db
```

### Port Already in Use
If you see a port conflict, Replit will handle it automatically. Just refresh the preview.

### Module Not Found
Run:
```bash
npm install
```

### Session Issues
Clear your browser cookies or use incognito mode and try again.

## Production Considerations

For a production deployment, consider:

1. **Change Default Credentials:** Update admin password immediately
2. **Secure Secret Key:** Use a strong, randomly generated secret key
3. **Database Backups:** Regularly export and backup your database
4. **SSL/HTTPS:** Replit provides this automatically
5. **Monitoring:** Monitor your application logs in Replit's console
6. **Rate Limiting:** Already configured for security
7. **Updates:** Regularly update dependencies for security patches

## Support

For issues or questions:
- Check the logs in Replit's Console tab
- Review the main README.md for application documentation
- Verify environment variables are correctly set

## Additional Resources

- [Replit Documentation](https://docs.replit.com)
- [Node.js on Replit](https://docs.replit.com/programming-ide/getting-started-nodejs)
- [Project Repository](https://github.com/oashraff/GDG_Workshop_Manager)
