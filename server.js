import express from 'express';
import multer from 'multer';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
import fs from 'fs';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS (Socket.IO)'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ dest: '/tmp' });

const allowedOrigins = [
  process.env.FRONTEND_URL,       // Deployed frontend
  'http://localhost:5173',        // Local frontend
  'http://127.0.0.1:3000'         // Alternate local frontend
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., Postman or mobile apps)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());

const userSockets = new Map();

io.on('connection', (socket) => {
  socket.on('register', (userId) => {
    userSockets.set(userId, socket.id);
  });

  socket.on('disconnect', () => {
    for (const [userId, socketId] of userSockets.entries()) {
      if (socketId === socket.id) {
        userSockets.delete(userId);
        break;
      }
    }
  });
});

const emitNotification = async (receiverId, message) => {
  const socketId = userSockets.get(receiverId);
  if (socketId) {
    io.to(socketId).emit('notification', message);
  }
};

const generateToken = (user) =>
  jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing or invalid auth token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalid or expired' });
    req.user = user;
    next();
  });
};

const uploadImage = async (file) => {
  if (!file) return null;
  const result = await cloudinary.uploader.upload(file.path);
  fs.unlinkSync(file.path);
  return result.secure_url;
};

app.get('/', (req, res) => {
  res.send('Welcome to SAYSO');
});

// Register
app.post('/register', upload.single('image'), async (req, res) => {
  try {
    const { username, email, password, bio } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const profile_image_url = await uploadImage(req.file);

    const { data, error } = await supabase
      .from('users')
      .insert([{ username, email, password: hashedPassword, profile_image_url, bio }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    const token = generateToken(data);
    res.json({ token, user: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error || !user) return res.status(400).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

    const token = generateToken(user);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update user profile
app.put('/users/me', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { username, email, bio } = req.body;
    const profile_image_url = await uploadImage(req.file);
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (bio) updateData.bio = bio;
    if (profile_image_url) updateData.profile_image_url = profile_image_url;

    const { data, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', req.user.id)
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public user profile
app.get('/users/:id/profile', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('id, username, email, profile_image_url, bio')
      .eq('id', id)
      .single();

    if (userError || !user) return res.status(404).json({ error: 'User not found' });

    const { data: posts, error: postsError } = await supabase
      .from('posts')
      .select('id, title, content, category, tags, image_url, created_at')
      .eq('user_id', id)
      .order('created_at', { ascending: false });

    if (postsError) return res.status(500).json({ error: postsError.message });

    res.json({ user, posts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create post
app.post('/posts', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { title, content, category, tags } = req.body;
    const image_url = await uploadImage(req.file);

    const { data, error } = await supabase
      .from('posts')
      .insert([{ title, content, category, tags, image_url, user_id: req.user.id }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all posts
app.get('/posts', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('posts')
      .select('*, users(username, profile_image_url)')
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single post
app.get('/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: post, error } = await supabase
      .from('posts')
      .select('*, users(username, profile_image_url)')
      .eq('id', id)
      .single();

    if (error) return res.status(404).json({ error: 'Post not found' });
    res.json(post);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update post
app.put('/posts/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, category, tags } = req.body;
    const image_url = await uploadImage(req.file);
    const updateData = {};
    if (title) updateData.title = title;
    if (content) updateData.content = content;
    if (category) updateData.category = category;
    if (tags) updateData.tags = tags;
    if (image_url) updateData.image_url = image_url;

    const { data, error } = await supabase
      .from('posts')
      .update(updateData)
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete post
app.delete('/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('posts').delete().eq('id', id).eq('user_id', req.user.id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Post deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Comment on post
app.post('/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    const { data: comment, error } = await supabase
      .from('comments')
      .insert([{ content, post_id: id, user_id: req.user.id }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    await supabase.rpc('update_comment_count', { post_id_input: id });

    const { data: post } = await supabase.from('posts').select('user_id').eq('id', id).single();
    const { data: user } = await supabase.from('users').select('username').eq('id', req.user.id).single();

    if (post?.user_id !== req.user.id) {
      emitNotification(post.user_id, `${user.username} commented on your post`);
    }

    res.json(comment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Like or dislike a post
app.post('/posts/:id/react', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { reaction } = req.body;

    const existing = await supabase
      .from('likes')
      .select('*')
      .eq('post_id', id)
      .eq('user_id', req.user.id)
      .single();

    if (existing.data) {
      await supabase.from('likes').delete().eq('id', existing.data.id);
    }

    if (reaction === 'like' || reaction === 'dislike') {
      await supabase
        .from('likes')
        .insert([{ post_id: id, user_id: req.user.id, reaction }]);
    }

    await supabase.rpc('update_like_count', { post_id_input: id });

    const { data: post } = await supabase.from('posts').select('user_id').eq('id', id).single();
    const { data: user } = await supabase.from('users').select('username').eq('id', req.user.id).single();

    if (reaction === 'like' && post?.user_id !== req.user.id) {
      emitNotification(post.user_id, `${user.username} liked your post`);
    }

    res.json({ message: 'Reaction updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get comments
app.get('/posts/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from('comments')
      .select('*, users(username, profile_image_url)')
      .eq('post_id', id)
      .order('created_at', { ascending: true });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
