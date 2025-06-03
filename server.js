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

const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:5173',
  'http://127.0.0.1:3000',
];

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

app.use(cors({
  origin: (origin, callback) => {
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

const calculateReadTime = (content) => {
  if (!content) return "1 min";
  const words = content.trim().split(/\s+/).length;
  return `${Math.ceil(words / 300)} min`;
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

// Update user
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
      .select('id, title, content, category, tags, image_url, created_at, read_time, like_count, comment_count')
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
    const read_time = calculateReadTime(content);

    const { data, error } = await supabase
      .from('posts')
      .insert([{ title, content, category, tags, image_url, user_id: req.user.id, read_time }])
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
    const { data: posts, error } = await supabase
      .from('posts')
      .select('*, users(id, username, profile_image_url)')
      .order('created_at', { ascending: false });

    if (error) return res.status(400).json({ error: error.message });

    // Fetch likes for all post IDs in one query for efficiency
    const postIds = posts.map(post => post.id);
    const { data: likes, error: likesError } = await supabase
      .from('likes')
      .select('post_id, user_id')
      .in('post_id', postIds);

    if (likesError) return res.status(400).json({ error: likesError.message });

    // Map post_id to list of user_ids who liked
    const likesByPost = {};
    likes.forEach(like => {
      if (!likesByPost[like.post_id]) likesByPost[like.post_id] = [];
      likesByPost[like.post_id].push(like.user_id);
    });

    // Attach the user IDs who liked each post
    const postsWithLikes = posts.map(post => ({
      ...post,
      liked_user_ids: likesByPost[post.id] || []
    }));

    res.json(postsWithLikes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get post by ID
app.get('/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: post, error } = await supabase
      .from('posts')
      .select('*, users(id, username, profile_image_url)')
      .eq('id', id)
      .single();

    if (error || !post) return res.status(404).json({ error: 'Post not found' });

    // Get all user_ids who liked this post
    const { data: likes, error: likesError } = await supabase
      .from('likes')
      .select('user_id')
      .eq('post_id', id);

    if (likesError) return res.status(400).json({ error: likesError.message });

    res.json({ 
      ...post, 
      liked_user_ids: likes.map(like => like.user_id) 
    });
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
    const read_time = calculateReadTime(content);

    const { data: post } = await supabase.from('posts').select('*').eq('id', id).single();
    if (!post || post.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized to update this post' });
    }

    const updateData = { title, content, category, tags, read_time };
    if (image_url) updateData.image_url = image_url;

    const { data, error } = await supabase
      .from('posts')
      .update(updateData)
      .eq('id', id)
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

    const { data: post } = await supabase.from('posts').select('*').eq('id', id).single();
    if (!post || post.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }

    const { error } = await supabase.from('posts').delete().eq('id', id);
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: 'Post deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Comment on post
app.post('/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { id: post_id } = req.params;
    const { content } = req.body;

    const { data: post } = await supabase.from('posts').select('*').eq('id', post_id).single();
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const { data: comment, error } = await supabase
      .from('comments')
      .insert([{ post_id, user_id: req.user.id, content }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    if (post.user_id !== req.user.id) {
      emitNotification(post.user_id, `Your post was commented on: "${content}"`);
    }

    res.json(comment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Get comments for post
app.get('/posts/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from('comments')
      .select('*, users(id, username, profile_image_url)')
      .eq('post_id', id)
      .order('created_at', { ascending: false });

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Edit comment
app.put('/comments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    const { data: comment, error: fetchError } = await supabase
      .from('comments')
      .select('*')
      .eq('id', id)
      .single();

    if (fetchError || !comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.user_id !== req.user.id) return res.status(403).json({ error: 'Not authorized to edit this comment' });

    const { data, error } = await supabase
      .from('comments')
      .update({ content })
      .eq('id', id)
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete comment
app.delete('/comments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: comment, error: fetchError } = await supabase
      .from('comments')
      .select('*')
      .eq('id', id)
      .single();

    if (fetchError || !comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.user_id !== req.user.id) return res.status(403).json({ error: 'Not authorized to delete this comment' });

    const { error } = await supabase
      .from('comments')
      .delete()
      .eq('id', id);

    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Comment deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const { id: post_id } = req.params;

    // Check if the user already liked the post
    const { data: existingLike, error: likeError } = await supabase
      .from('likes')
      .select('*')
      .eq('post_id', post_id)
      .eq('user_id', req.user.id)
      .single();

    if (!existingLike) {
      // Like the post
      const { data, error } = await supabase
        .from('likes')
        .insert([{ post_id, user_id: req.user.id, action: 'like' }]);

      if (error) return res.status(400).json({ error: error.message });

    } else {
      // Unlike the post
      const { error } = await supabase
        .from('likes')
        .delete()
        .eq('id', existingLike.id);

      if (error) return res.status(400).json({ error: error.message });
    }

    // Get updated like count
    const { count, error: countError } = await supabase
      .from('likes')
      .select('id', { count: 'exact', head: true })
      .eq('post_id', post_id);

    if (countError) return res.status(400).json({ error: countError.message });

    res.json({ message: existingLike ? 'Post unliked' : 'Post liked', likeCount: count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
