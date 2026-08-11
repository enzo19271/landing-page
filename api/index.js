import crypto from 'crypto';

// ─── AUTH ────────────────────────────────────────────────────────────────────
function generateToken(payload) {
  const secret = process.env.JWT_SECRET || 'default-secret-key';
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyToken(token) {
  try {
    const secret = process.env.JWT_SECRET || 'default-secret-key';
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    const [encodedHeader, encodedPayload, signature] = parts;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    if (signature !== expectedSignature) throw new Error('Invalid signature');
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
    return payload;
  } catch {
    return null;
  }
}

function simplePasswordVerify(inputPassword, storedHash) {
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
  if (storedHash === 'admin' && inputPassword === adminPassword) return true;
  return false;
}

// ─── GITHUB ──────────────────────────────────────────────────────────────────
const GITHUB_API = 'https://api.github.com';

async function getGitHubFile(path) {
  const cacheBuster = Date.now();
  const branch = process.env.GITHUB_BRANCH || 'main';
  const response = await fetch(
    `${GITHUB_API}/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/contents/${path}?ref=${branch}&_=${cacheBuster}`,
    {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: 'application/vnd.github.v3.raw',
        'Cache-Control': 'no-cache'
      },
      cache: 'no-store'
    }
  );
  if (!response.ok) throw new Error(`GitHub API error: ${response.status}`);
  return await response.text();
}

async function updateGitHubFile(path, content, message) {
  const shaResponse = await fetch(
    `${GITHUB_API}/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/contents/${path}`,
    {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: 'application/vnd.github.v3+json'
      }
    }
  );
  let sha = '';
  if (shaResponse.ok) {
    const data = await shaResponse.json();
    sha = data.sha;
  }
  const updateResponse = await fetch(
    `${GITHUB_API}/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/contents/${path}`,
    {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: message || `Update ${path}`,
        content: Buffer.from(content).toString('base64'),
        sha: sha || undefined,
        branch: process.env.GITHUB_BRANCH || 'main'
      })
    }
  );
  if (!updateResponse.ok) throw new Error(`Failed to update file: ${updateResponse.status}`);
  return await updateResponse.json();
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  const { method, url, headers } = req;
  
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    const path = new URL(`http://localhost${url}`).pathname;
    const parts = path.split('/').filter(Boolean);
    
    // Vercel already parses JSON bodies into req.body automatically
    let body = req.body || {};
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch {
        body = {};
      }
    }

    // ─── PUBLIC: GET PORTFOLIO ───────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'portfolio') {
      try {
        const data = await getGitHubFile('data/portfolio.json');
        const portfolio = JSON.parse(data);
        res.status(200).json(portfolio);
      } catch (err) {
        res.status(404).json({ message: 'Portfolio not found' });
      }
      return;
    }

    // ─── PUBLIC: GET PROFILE ─────────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'profile') {
      try {
        const data = await getGitHubFile('data/profile.json');
        res.status(200).json(JSON.parse(data));
      } catch (err) {
        res.status(404).json({ message: 'Profile not found' });
      }
      return;
    }

    // ─── PUBLIC: GET GALLERY ─────────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'gallery') {
      try {
        const data = await getGitHubFile('data/gallery.json');
        res.status(200).json(JSON.parse(data));
      } catch (err) {
        res.status(200).json({ photos: [] });
      }
      return;
    }

    // ─── PUBLIC: GET NEWS ────────────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'news') {
      try {
        const data = await getGitHubFile('data/news.json');
        res.status(200).json(JSON.parse(data));
      } catch (err) {
        res.status(200).json({ items: [] });
      }
      return;
    }

    // ─── ADMIN: LOGIN ────────────────────────────────────────────────────
    if (method === 'POST' && parts[1] === 'admin' && parts[2] === 'login') {
      const { password } = body;
      if (simplePasswordVerify(password, 'admin')) {
        const token = generateToken({ role: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 });
        res.status(200).json({ token, role: 'admin' });
      } else {
        res.status(401).json({ message: 'Invalid password' });
      }
      return;
    }

    // ─── ADMIN: VERIFY TOKEN ────────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'admin' && parts[2] === 'verify') {
      const authHeader = headers.authorization;
      const token = authHeader?.split(' ')[1];
      if (!token) {
        res.status(401).json({ message: 'No token provided' });
        return;
      }
      const payload = verifyToken(token);
      if (!payload) {
        res.status(401).json({ message: 'Invalid token' });
        return;
      }
      res.status(200).json({ valid: true, role: payload.role });
      return;
    }

    // ─── ADMIN: GET ALL PORTFOLIO ───────────────────────────────────────
    if (method === 'GET' && parts[1] === 'admin' && parts[2] === 'portfolio') {
      const authHeader = headers.authorization;
      const token = authHeader?.split(' ')[1];
      const payload = verifyToken(token);
      if (!payload) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      try {
        const data = await getGitHubFile('data/portfolio.json');
        const portfolio = JSON.parse(data);
        res.status(200).json(portfolio);
      } catch {
        res.status(200).json({ works: [] });
      }
      return;
    }

    // ─── ADMIN: ADD WORK ────────────────────────────────────────────────
    if (method === 'POST' && parts[1] === 'admin' && parts[2] === 'work') {
      const authHeader = headers.authorization;
      const token = authHeader?.split(' ')[1];
      const payload = verifyToken(token);
      if (!payload) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      try {
        let portfolio = { works: [] };
        try {
          const data = await getGitHubFile('data/portfolio.json');
          portfolio = JSON.parse(data);
        } catch {}
        
        const newWork = {
          id: Date.now().toString(),
          ...body,
          createdAt: new Date().toISOString()
        };
        portfolio.works.push(newWork);
        
        await updateGitHubFile('data/portfolio.json', JSON.stringify(portfolio, null, 2), 'Add new portfolio work');
        res.status(201).json(newWork);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: UPDATE WORK ─────────────────────────────────────────────
    if (method === 'PUT' && parts[1] === 'admin' && parts[2] === 'work' && parts[3]) {
      const authHeader = headers.authorization;
      const token = authHeader?.split(' ')[1];
      const payload = verifyToken(token);
      if (!payload) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      try {
        const data = await getGitHubFile('data/portfolio.json');
        const portfolio = JSON.parse(data);
        const workId = parts[3];
        const workIndex = portfolio.works.findIndex(w => w.id === workId);
        if (workIndex === -1) {
          res.status(404).json({ message: 'Work not found' });
          return;
        }
        portfolio.works[workIndex] = { ...portfolio.works[workIndex], ...body };
        await updateGitHubFile('data/portfolio.json', JSON.stringify(portfolio, null, 2), 'Update portfolio work');
        res.status(200).json(portfolio.works[workIndex]);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: DELETE WORK ─────────────────────────────────────────────
    if (method === 'DELETE' && parts[1] === 'admin' && parts[2] === 'work' && parts[3]) {
      const authHeader = headers.authorization;
      const token = authHeader?.split(' ')[1];
      const payload = verifyToken(token);
      if (!payload) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      try {
        const data = await getGitHubFile('data/portfolio.json');
        const portfolio = JSON.parse(data);
        const workId = parts[3];
        portfolio.works = portfolio.works.filter(w => w.id !== workId);
        await updateGitHubFile('data/portfolio.json', JSON.stringify(portfolio, null, 2), 'Delete portfolio work');
        res.status(200).json({ message: 'Work deleted' });
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: GET PROFILE ──────────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'admin' && parts[2] === 'profile') {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const data = await getGitHubFile('data/profile.json');
        res.status(200).json(JSON.parse(data));
      } catch {
        res.status(200).json({ name: '', title: '', bio: '', photo: '', skills: [], socialLinks: {} });
      }
      return;
    }

    // ─── ADMIN: UPDATE PROFILE ───────────────────────────────────────────
    if (method === 'PUT' && parts[1] === 'admin' && parts[2] === 'profile') {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const updated = { ...body, updatedAt: new Date().toISOString() };
        await updateGitHubFile('data/profile.json', JSON.stringify(updated, null, 2), 'Update profile');
        res.status(200).json(updated);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: GET GALLERY ──────────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'admin' && parts[2] === 'gallery') {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const data = await getGitHubFile('data/gallery.json');
        res.status(200).json(JSON.parse(data));
      } catch {
        res.status(200).json({ photos: [] });
      }
      return;
    }

    // ─── ADMIN: ADD GALLERY PHOTO ────────────────────────────────────────
    if (method === 'POST' && parts[1] === 'admin' && parts[2] === 'gallery') {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        let gallery = { photos: [] };
        try {
          const data = await getGitHubFile('data/gallery.json');
          gallery = JSON.parse(data);
        } catch {}
        const newPhoto = { id: Date.now().toString(), ...body, createdAt: new Date().toISOString() };
        gallery.photos.unshift(newPhoto);
        await updateGitHubFile('data/gallery.json', JSON.stringify(gallery, null, 2), 'Add gallery photo');
        res.status(201).json(newPhoto);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: DELETE GALLERY PHOTO ─────────────────────────────────────
    if (method === 'DELETE' && parts[1] === 'admin' && parts[2] === 'gallery' && parts[3]) {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const data = await getGitHubFile('data/gallery.json');
        const gallery = JSON.parse(data);
        gallery.photos = gallery.photos.filter(p => p.id !== parts[3]);
        await updateGitHubFile('data/gallery.json', JSON.stringify(gallery, null, 2), 'Delete gallery photo');
        res.status(200).json({ message: 'Photo deleted' });
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: GET NEWS (ALL) ───────────────────────────────────────────
    if (method === 'GET' && parts[1] === 'admin' && parts[2] === 'news') {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const data = await getGitHubFile('data/news.json');
        res.status(200).json(JSON.parse(data));
      } catch {
        res.status(200).json({ items: [] });
      }
      return;
    }

    // ─── ADMIN: ADD NEWS ─────────────────────────────────────────────────
    if (method === 'POST' && parts[1] === 'admin' && parts[2] === 'news') {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        let news = { items: [] };
        try {
          const data = await getGitHubFile('data/news.json');
          news = JSON.parse(data);
        } catch {}
        const newItem = { id: Date.now().toString(), ...body, createdAt: new Date().toISOString() };
        news.items.unshift(newItem);
        await updateGitHubFile('data/news.json', JSON.stringify(news, null, 2), 'Add news item');
        res.status(201).json(newItem);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: UPDATE NEWS ──────────────────────────────────────────────
    if (method === 'PUT' && parts[1] === 'admin' && parts[2] === 'news' && parts[3]) {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const data = await getGitHubFile('data/news.json');
        const news = JSON.parse(data);
        const idx = news.items.findIndex(n => n.id === parts[3]);
        if (idx === -1) return res.status(404).json({ message: 'News not found' });
        news.items[idx] = { ...news.items[idx], ...body };
        await updateGitHubFile('data/news.json', JSON.stringify(news, null, 2), 'Update news item');
        res.status(200).json(news.items[idx]);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    // ─── ADMIN: DELETE NEWS ──────────────────────────────────────────────
    if (method === 'DELETE' && parts[1] === 'admin' && parts[2] === 'news' && parts[3]) {
      const payload = verifyToken(headers.authorization?.split(' ')[1]);
      if (!payload) return res.status(401).json({ message: 'Unauthorized' });
      try {
        const data = await getGitHubFile('data/news.json');
        const news = JSON.parse(data);
        news.items = news.items.filter(n => n.id !== parts[3]);
        await updateGitHubFile('data/news.json', JSON.stringify(news, null, 2), 'Delete news item');
        res.status(200).json({ message: 'News deleted' });
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
      return;
    }

    res.status(404).json({ message: 'Endpoint not found' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
}
